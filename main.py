import sys
import yaml
import click
from os.path import join, dirname, exists
import logging
import math
import subprocess
from datetime import datetime
import os

sys.path.append(join(dirname(__file__), "src/python"))

from src.python import main
from src.python import report as report_server
from inc.config import Config
from inc.logging import CustomFormatter

logger = logging.getLogger("hardeninganalyzer")


@click.group()
# Normal flags
@click.option(
    "--config", "-c", type=click.Path(), required=True, help="YAML config file to use"
)
@click.option(
    "--multithread",
    "-m",
    type=int,
    default=1,
    help="Number of threads to use for analysis",
)
@click.option(
    "--force",
    "-f",
    is_flag=True,
    help="Force analysis of apps, even if a step has already been completed",
)
# Internal flags for multithreading
@click.option(
    "--thread",
    "-t",
    type=str,
    default=None,
    help="Thread number and total threads e.g. (1/4), takes a certain subset of the apps to analyze",
)
@click.option(
    "--r2-server",
    "-r2",
    type=str,
    default="local",
    help='Address of the radare2 server to use (use "local" or a ssh host)',
)
@click.option("--android", "-a", is_flag=True, help="Only analyze Android apps")
@click.option("--ios", "-i", is_flag=True, help="Only analyze iOS apps")
@click.option("--dev", "-d", default=None, type=str, help="Device serial for ADB or UDID for iOS")
@click.pass_context
def cli(
    ctx: click.core.Context,
    config: str,
    thread: str | None,
    multithread: int,
    r2_server: str,
    force: bool,
    android: bool,
    ios: bool,
    dev: str,
):
    # Load config file
    if not exists(config):
        logging.error("Provided config file could not be found")
        exit(1)
    print(f"Loading config from {config}")
    with open(config, "r") as config_file:
        c = yaml.load(config_file, Loader=yaml.Loader)
        Config().from_dict(c, dev)

    if thread is None:
        thread = "1/1"
    try:
        thread_id = int(thread.split("/")[0])
        total_threads = int(thread.split("/")[1])
    except:
        logger.error(
            "Invalid thread format, should be '{thread_id}/{total_threads}', e.g. '1/4'"
        )
        exit(1)
    apps = Config().apps
    Config().apps = []
    for i in range(0, len(apps), total_threads):
        idx = i + thread_id - 1
        if (
            idx < len(apps)
            and (not android or apps[idx].os == "android")
            and (not ios or apps[idx].os == "ios")
        ):
            Config().apps.append(apps[idx])

    Config().radare_server = r2_server

    Config().force = force
    
    # Configure logging
    level = logging.getLevelName(Config().logging.upper())

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(CustomFormatter())
    stdout_handler.setLevel(level)
    
    os.makedirs(join(Config().work_dir, "logs"), exist_ok=True)
    file_handler = logging.FileHandler(
        join(
            Config().work_dir,
            "logs",
            f'log-{datetime.now().strftime("%Y%m%d%H%M%S")}.txt',
        )
    )
    file_handler.setFormatter(CustomFormatter(False))
    file_handler.setLevel(level)

    logging.basicConfig(level=logging.WARN)

    logger.setLevel(level)
    logger.propagate = False
    logger.addHandler(stdout_handler)
    logger.addHandler(file_handler)

    # Multiple devices, split the devices into subprocesses 
    if dev is None and len(Config().devices) > 1:
        if ctx.invoked_subcommand == "dynamic":
            run_multidevice("dynamic", config, Config().devices)
            exit(0)

    # Configure multithreading
    if multithread > 1:
        # Multithreading is only supported for static analysis
        if ctx.invoked_subcommand not in ["prepare", "static", "dynamic", "run"]:
            logger.error("Multithreading can only be used with static analysis")
            exit(1)

        if ctx.invoked_subcommand == "run":
            main.download_apps()

        if ctx.invoked_subcommand == "prepare" or ctx.invoked_subcommand == "run":
            run_multithreaded("prepare", config, multithread)

        if ctx.invoked_subcommand == "static" or ctx.invoked_subcommand == "run":
            run_multithreaded("static", config, multithread)

        if ctx.invoked_subcommand == "dynamic" or ctx.invoked_subcommand == "run":
            run_multithreaded("dynamic", config, 2)

        if ctx.invoked_subcommand == "run":
            report_server.run()

        exit(0)


@click.command(help="Download apps")
def download():
    main.download_apps()


@click.command(
    help="Prepare apps for analysis by decompiling them and indexing the decompiled files"
)
@click.option("--decompile", "-d", is_flag=True, help="Only decompile apps")
@click.option("--index", "-i", is_flag=True, help="Only index decompiled apps")
def prepare(decompile, index):
    if decompile or (not decompile and not index):
        main.decompile_apps()
    if index or (not decompile and not index):
        main.index_apps()


@click.command(help="Run static analysis")
def static():
    main.analyze_static()


@click.command(help="Run dynamic analysis")
def dynamic():
    main.analyze_dynamic()


@click.command(help="Show HTML report")
def report():
    report_server.run()


@click.command(
    help="Run full pipeline by downloading apps, and running static and dynamic analysis"
)
def run():
    main.download_apps()
    main.decompile_apps()
    main.index_apps()
    main.analyze_static()
    main.analyze_dynamic()
    report_server.run()


cli.add_command(download)
cli.add_command(static)
cli.add_command(dynamic)
cli.add_command(prepare)
cli.add_command(run)
cli.add_command(report)

def run_multidevice(cmd: list[str] | str, config: str, devices: list[str]):
    if isinstance(cmd, str):
        cmd = [cmd]

    apps = Config().apps
    ios_apps = [app for app in apps if app.os == "ios"]
    android_apps = [app for app in apps if app.os == "android"]
    
    flags = ["-c", config]
    if Config().force:
        flags.append("-f")
    
    processes = []
    for dev in devices:
        dev_name = dev["name"]
        # iOS has not been tested with multiple devices
        if cmd[0] == "prepare" or cmd[0] == "dynamic":
            # Start process for iOS apps
            if len(ios_apps) > 0:
                logger.debug("Starting subprocess for iOS apps")
                command = [sys.executable, __file__, "--ios"] + flags + cmd
                p = subprocess.Popen(command)
                processes.append((p, "for iOS apps"))
                thread_amount -= 1
        if cmd[0] == "dynamic":
            # Start process for Android apps on device
            if len(android_apps) > 0:
                logger.debug(f"Starting subprocess for Android apps on device {dev_name}")
                command = (
                    [sys.executable, __file__, "--android", "-d", dev_name] + flags + cmd
                )
                p = subprocess.Popen(command)
                processes.append((p, f"for Android apps on device {dev_name}"))

    # Wait for all subprocesses to finish
    for process in processes:
        process[0].wait()
        logger.debug("Subprocess %s has finished" % process[1])


def run_multithreaded(cmd: list[str] | str, config: str, thread_amount: int):
    """
    Divide apps into chunks and run subprocesses for each chunk
    """
    if isinstance(cmd, str):
        cmd = [cmd]

    apps = Config().apps
    ios_apps = [app for app in apps if app.os == "ios"]
    android_apps = [app for app in apps if app.os == "android"]

    processes = []

    flags = ["-c", config]
    if Config().force:
        flags.append("-f")

    radare_servers = None
    if cmd[0] == "prepare" or cmd[0] == "static":
        radare_servers = Config().radare_servers
        if sum(radare_servers.values()) < thread_amount:
            logger.warn(
                "Number of threads is larger than number of radare2 servers, reducing number of threads"
            )
            thread_amount = sum(radare_servers.values())
        radare_servers = [
            server for server, amount in radare_servers.items() for _ in range(amount)
        ]
    # TODO change this comment when done testing for multi device
    # iOS prepare and iOS/Android dynamic need to be run on a single device
    if cmd[0] == "prepare" or cmd[0] == "dynamic":
        # Start process for iOS apps
        if len(ios_apps) > 0:
            logger.debug("Starting subprocess for iOS apps")
            command = [sys.executable, __file__, "--ios"] + flags + cmd
            p = subprocess.Popen(command)
            processes.append((p, "for iOS apps"))
            thread_amount -= 1
    if cmd[0] == "dynamic":
        # Start process for Android apps
        if len(android_apps) > 0:
            logger.debug("Starting subprocess for Android apps")
            command = (
                [sys.executable, __file__, "--android"] + flags + cmd
            )
            p = subprocess.Popen(command)
            processes.append((p, "for Android apps"))
    else:
        if cmd[0] == "prepare" and len(android_apps) > 0:
            flags += ["--android"]
        for i in range(thread_amount):
            r2_server = []
            if radare_servers is not None and (
                cmd[0] == "prepare" or cmd[0] == "static"
            ):
                r2_server = ["-r2", radare_servers.pop(0)]
            logger.debug(f"Starting subprocess {i}")
            command = (
                [sys.executable, __file__, "-t", f"{i+1}/{thread_amount}"]
                + flags
                + r2_server
                + cmd
            )
            p = subprocess.Popen(command)
            processes.append((p, i))

    # Wait for all subprocesses to finish
    for process in processes:
        process[0].wait()
        logger.debug("Subprocess %s has finished" % process[1])


if __name__ == "__main__":
    cli()
