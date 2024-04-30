import subprocess
import time
from inc.util import run_system_command
import logging
from time import sleep
from inc.tools.telnet import TelnetReverseShell

logger = logging.getLogger("hardeninganalyzer")

def is_device_connected(dev_serial: str) -> bool:
    print(f"Waiting for {dev_serial} to start...")
    started = adb("wait-for-device", dev_serial)
    if started is False:
        logger.error(f"Could not connect to Android device {dev_serial}. Is it connected?")
        exit(1)
    return started is not False

def get_ip_address(dev_serial: str) -> str:
    """
    Get the IP address of the device
    :return: The IP address of the device
    """
    if is_device_connected(dev_serial):
        return adb("shell ip -o -4 addr list wlan0 | awk '{print $4}' | cut -d/ -f1", dev_serial)
    else:
        logger.error("Device is not connected")
        return None

def kill_server() -> bool:
    """
    Kill the adb server
    :return: whether the server was killed
    """
    logger.debug("Killing adb server")
    return adb("kill-server")

def force_stop(package: str, dev_serial: str) -> bool:
	return adb(f"shell am force-stop {package}", dev_serial)
def has_root(device: dict) -> bool:
    """
    Check if the device has root access
    :return: True if the device has root access, False otherwise
    """
    if device["type"] == "physical":
        return "telnet" in device and device["telnet"].is_connected()
    elif device["type"] == "emulator":
        return adb("root", device["serial"])
    else:
        return False

def stealth_root(device: dict) -> bool:
    tries = 0
    while tries < 15:
        # wait for device
        if not is_device_connected(device["serial"]):
            time.sleep(5)
            continue
        time.sleep(2)
        print("Trying to get root access")
        output = adb("shell 'echo /data/local/tmp/bins/busybox telnetd -l /bin/sh -p 10847 | /data/local/tmp/mali/mali_jit'", device["serial"])
        if type(output) == bool and not output:
            print("Could not run command")
            continue
        print(output)
        # if the last line is not "result 50" then redo
        if "result 50" in output:
            device["telnet"] = TelnetReverseShell(device["ip"], 10847)
            if device["telnet"].is_connected():
                time.sleep(5)
                return True
        tries += 1
    return False

def get_root(device: dict) -> bool:
    if device["type"] == "physical" and "stealthy" in device["name"]:
        return stealth_root(device)
    elif device["type"] == "emulator":
        return True
    else:
        return adb("root", device["serial"])

def start_emulator(device: dict)->subprocess.Popen:
    # Start the emulator as a subprocess with the provided AVD and snapshot and use the network adapter, check if this is a tap device
    assert device["type"] == "emulator"
    
    avd = device["avd"]
    snapshot = device["snapshot"]
    network_adapter = device["network_adapter"]
    
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

def reboot_device(device: dict) -> bool:
    if is_device_connected(device["serial"]):
        rebooted = False
        if device["type"] == "physical":
            if not adb("reboot", device["serial"]):
                return False
        elif device["type"] == "emulator":
            device["emulator_proc"].terminate()
            emu_proc = start_emulator(device)
            if emu_proc is None:
                return False
            device["emulator_proc"] = emu_proc
        rebooted = is_device_connected(device["serial"])
        if not rebooted:
            logger.error("Device did not reboot")
            return False
        if not get_root(device):
            logger.error("Could not get root access")
            return False
        device["telnet"] = TelnetReverseShell(device["ip"], 10847)
    else:
        logger.error("Device is not connected")
        return False
    

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
