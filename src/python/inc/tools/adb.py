from inc.util import run_system_command
import logging
from time import sleep

logger = logging.getLogger("hardeninganalyzer")

def is_device_connected(dev_serial: str) -> bool:
    print("Waiting for emulator to start...")
    started = adb("wait-for-device", dev_serial)
    if started is False:
        logger.error(f"Could not connect to Android device {dev_serial}. Is it connected?")
        exit(1)
    return started is not False

def kill_server() -> bool:
    """
    Kill the adb server
    :return: whether the server was killed
    """
    logger.debug("Killing adb server")
    return adb("kill-server")
def force_stop(package: str, dev_serial: str) -> bool:
	return adb(f"shell am force-stop {package}", dev_serial)
def adb(cmd: str, dev_serial: str = None, ignore_errors: bool = False) -> str | bool:
    """
    Run an adb command
    :param cmd: The command to run
    :return: The output of the command or False if an error occurred
    """
    while True:
        if dev_serial is None:
            (success, output, _) = run_system_command(f"adb {cmd}")
        else:
            (success, output, _) = run_system_command(f"adb -s {dev_serial} {cmd}")
        if success:
            return output
        else:
            if "no devices/emulators found" in output:
                logger.error("Could not connect to Android device. Is it connected?")
                sleep(2)
            else:
                if not ignore_errors:
                    logger.error(f"adb {cmd} failed with output {output}")
                return False
