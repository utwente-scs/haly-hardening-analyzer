import threading
import time
import frida
from frida_tools.application import Reactor
from inc.util import *
from typing import Callable, Mapping, Any
from inc.config import Config
from inc.context import Context
from models.app import App
import logging
from time import sleep
import json
from inc.tools.telnet import TelnetReverseShell
from inc.tools.adb import adb, get_root

logger = logging.getLogger("hardeninganalyzer")

def start_frida_server(device: dict) -> None:
    """
    Start the Frida server on the device
    """
    logger.info("Starting Frida server")
    if device["type"] == "physical" and "stealthy" in device["name"]:
        if "telnet" not in device or not device["telnet"].is_connected():
            Config().connect_telnet()
        logger.debug("Starting Frida server on stealthy device")
        device["telnet"].send_command("/data/local/tmp/bins/frida/frida-server -D &")
    elif device["type"] == "root":
        logger.debug("Starting Frida server on rooted device")
        logger.debug("Starting Frida server on rooted device")
        adb("shell \"echo '/data/local/tmp/bins/frida/hlserver -D &'| /system/bin/kp\"", device["serial"])
    else:
        adb("shell /data/local/tmp/bins/frida/frida-server -D &", device["serial"])
# def check frida_running() -> bool:
#     """
#     Check if the Frida server is running on the device with subprocess and frida-ps -U on host
#     """
#     logger.debug("Checking if Frida server is running")
#     try:
#         output = subprocess.check_output(["frida-ps", "-U"], stderr=subprocess.STDOUT)
#         if "frida-server" in output.decode():
#             return True


class FridaApplication:
    def __init__(
        self,
        app: App,
        data: dict = None,
        onmessage: Callable[[Mapping[Any, Any], Any], Any] = None,
        oninstrument: Callable[[frida.core.Script, bool], None] = None,
        timeout: int = 60,
        resume: bool = True,
    ):
        """
        Initialize a new Frida application
        :param app: application to run
        :param data: data to add to the script
        :param oninstrument: callback to instrument Frida sessions
        :param onmessage: callback to handle Frida messages
        :param resume: whether the app should be resumed after spawning
        """
        self._stop_requested = threading.Event()
        self._reactor = Reactor(
            run_until_return=lambda reactor: self._stop_requested.wait(timeout)
        )

        self._sessions = set()

        self._device = None
        while self._device is None:
            devices = frida.enumerate_devices()
            if len(devices) == 0:
                logger.error("No connected devices found. Is a device connected?")
                sleep(1)
                continue
            
            for device in devices:
                if device.type != "usb":
                    continue
                if device.id != Config().device["serial"]:
                    print(device.id, Config().device["serial"])
                    continue
                if device.query_system_parameters()["os"]["id"] == Context().get_os():
                    self._device = device
                    break

            if self._device is None:
                os_name = (
                    "iOS"
                    if Context().get_os() == "ios"
                    else Context().get_os().capitalize()
                )
                logger.error(
                    f"Could not find a connected {Config().device['serial']}({os_name}) device. Is it connected?"
                )
                sleep(1)

        Context().set_device_info(self._device.query_system_parameters())

        self._appid = app.package_id
        self._data = data
        self._onmessage = onmessage
        self._oninstrument = oninstrument
        self._resume = resume

        self._device.on(
            "child-added",
            lambda child: self._reactor.schedule(lambda: self._on_child_added(child)),
        )

    def run(self) -> None:
        """
        Start running the application
        """
        self._reactor.schedule(lambda: self._start())
        self._reactor.run()

    def stop(self) -> None:
        """
        Stop running the application
        """
        self._stop_requested.set()

    def _start(self) -> None:
        """
        Start the application with the given app id
        """
        while True:
            try:
                pid = self._device.spawn([self._appid])
                break
            except frida.NotSupportedError as e:
                if (
                    "this feature requires an iOS Developer Disk Image to be mounted"
                    in str(e)
                ):
                    logger.error(
                        "Could not connect to iPhone. Is it connected and is Frida running?"
                    )
                    sleep(1)
                elif ("need Gadget to attach on jailed Android" in str(e)):
                    logger.debug("starting frida")
                    start_frida_server(Config().device)
                    time.sleep(3)
                else:
                    raise e
            except Exception as e:
                raise e
        self._main_pid = pid
        self._instrument(pid)

    def _stop_if_idle(self) -> None:
        """
        Stop the application if there are no more sessions
        """
        if len(self._sessions) == 0:
            self._stop_requested.set()

    def _instrument(self, pid: int):
        """
        Instrument the given process id with our detectors
        """
        session = self._device.attach(pid)
        session.on(
            "detached",
            lambda reason: self._reactor.schedule(
                lambda: self._on_detached(pid, session, reason)
            ),
        )
        session.enable_child_gating()
        script_path = frida_path("_main.js")
        with open(script_path, "r") as script_file:
            script_content = script_file.read()
        for key, value in self._data.items():
            script_content = script_content.replace("'{{%s}}'" % key, json.dumps(value))
        script = session.create_script(script_content)
        script.on("message", self._onmessage)
        script.load()
        self._sessions.add(session)
        if self._oninstrument:
            self._oninstrument(script, pid == self._main_pid)
        if self._resume:
            self._device.resume(pid)

    def _on_child_added(self, child):
        """
        Instrument a new child process
        """
        try:
            self._instrument(child.pid)
        except Exception:
            pass

    def _on_detached(self, pid, session, reason):
        """
        Handle a detached session
        """
        try:
            self._sessions.remove(session)
            self._reactor.schedule(self._stop_if_idle, delay=0.5)
            pass
        except Exception:
            pass
