from models.app import App
from detectors import Detectors
from inc.context import Context
from inc.util import serializer
from inc.config import Config
from os.path import dirname
import os
import time
import json
from inc.tools.frida import FridaApplication
from inc.tools.appmanager import install_app, uninstall_app, grant_permissions
import frida.core
from models.message import DynamicMessage
import logging
import subprocess
from inc.tools.adb import is_device_connected, kill_server, force_stop

logger = logging.getLogger("hardeninganalyzer")


def analyze(app: App) -> None:
    """
    Analyze an app using static analysis
    """
    logger.info(f"Performing dynamic analysis on {app.package_id}")

    # Start with a clean context for each app
    Context.cache_clear()
    Detectors.cache_clear()

    Context().app = app
    Context().stage = "dynamic"

    if app.get_stage() < 6:
        logger.error(f"App must be statically analyzed before running dynamic analysis")
        return

    if app.get_stage() >= 7 and not Config().force:
        logger.info(
            f"Skipping dynamic analysis of {app.package_id}, results already exist in the working directory"
        )
        return
    
    def start_emulator(avd: str, snapshot: str = None, network_adapter: str = None)->subprocess.Popen:
        # Start the emulator as a subprocess with the provided AVD and snapshot and use the network adapter, check if this is a tap device
        
        # Check if the emulator is already running
        emulator_running = False
        try:
            emulator_running = (
                subprocess.run(["adb", "devices"], capture_output=True)
                .stdout.decode()
                .find("emulator") != -1
            )
        except:
            pass
        
        if emulator_running:
            logger.info("Emulator already running")
            return
        
        is_tap = False
        if network_adapter is not None:
            is_tap = network_adapter.startswith("tap")
        
        # Create commands for starting the emulator using the tap interface and if there is a snapshot or not
        cmd = ["emulator", "-avd", avd]
        if snapshot is not None:
            cmd += ["-snapshot", snapshot]
        if is_tap:
            cmd += ["-net-tap", network_adapter]
        if network_adapter is not None and not is_tap:
            cmd += ["-net", network_adapter]
        print(f"Starting emulator with command: {cmd}")
        # Start the emulator
        return subprocess.Popen(cmd, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,)
    
    emu_proc = None

    if Config().device is not None and Config().device["type"] == "emulator" and Config().device["avd"] is not None:
        print("Starting emulator")
        #kill_server()
	#time.sleep(2)
        emu_proc = start_emulator(Config().device["avd"], Config().device["snapshot"], Config().device["network_adapter"])
    time.sleep(10)
    # Check if device is online
    if is_device_connected(Config().device["serial"]):
        logger.info("Device is online! Can continue...")
    else:
        logger.error("Device is not online! Exiting...")
        emu_proc.terminate()
        return
    
    # Install app if not installed
    install_app(app)

    if Context().is_android():
        info = Detectors().get_static_results()["info"]
        if "permissions" in info:
            grant_permissions(app, info["permissions"])

    # Perform analysis
    def on_message(message, data):
        """
        Handle a Frida message
        Print errors and send messages to the detectors
        """
        if message["type"] == "send":
            message = message["payload"]

            if message["type"] == "modules":
                Context().modules = message["modules"]
                return
            if message["type"] == "log":
                logger.log(
                    logging.getLevelName(message["level"].upper()), message["message"]
                )
                return

            Detectors().dynamic_handle_message(DynamicMessage.from_dict(message))
        elif message["type"] == "error":
            if "stack" in message:
                error = message["stack"]
            else:
                error = json.dumps(message)
            if "unable to intercept function" in error:
                # We ignore svc instructions that we are unable to hook since they may not be actual instructions
                return
            logger.error(f"Error from frida: {error}")

    def on_instrument(script: frida.core.Script, is_main_process: bool):
        """
        On instrumentation of a binary, set context
        """
        Detectors().dynamic_instrument(script, is_main_process)

    Detectors().dynamic_before_analysis()

    # Get context and add data from detectors
    context = Context().to_dict()
    context.update(Detectors().dynamic_get_data())

    attempt = 0
    while attempt < 3:
        if attempt == 2:
            # On the last attempt, try without hooking some functions that might crash the app
            logger.warning(
                "Trying to run app without hooking some function that might crash it..."
            )
            safe_mode = True
        else:
            safe_mode = False

        start = time.time()
        FridaApplication(
            app,
            {"context": context, "safeMode": "yes" if safe_mode else "no"},
            on_message,
            on_instrument,
            Config().dynamic_analysis_timeout,
        ).run()
        if time.time() - start > Config().dynamic_analysis_timeout - 1:
            break
        time.sleep(1)
        logger.warning(
            "App finished before timeout and has probably crashed, retrying..."
        )
        force_stop(app.package_id, Config().device["serial"])
        attempt += 1

    Detectors().dynamic_after_analysis()

    if Config().uninstall_apps:
        # Uninstall the app from the device
        uninstall_app(app)
        
    if emu_proc is not None:
        emu_proc.terminate()
    	#kill_server()

    if attempt == 3:
        logger.error("App crashed too many times, aborting...")
        return

    # Save results
    path = app.get_dynamic_result_path()
    os.makedirs(dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(Detectors().get_dynamic_results(), f, indent=4, default=serializer)

    app.set_stage(7)
