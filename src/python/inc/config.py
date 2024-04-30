from os.path import join, dirname
from functools import cache
from os.path import exists, abspath
from models.app import App
import logging
from inc.tools.telnet import TelnetReverseShell

logger = logging.getLogger("hardeninganalyzer")


@cache  # Singleton
class Config(object):
    logging = "info"
    work_dir = join(dirname(__file__), "../../../", "workdir")
    dump_timeout = 30
    radare_timeout = 30
    radare_memory_limit = None
    radare_server = "local"
    radare_servers = {"local": 1}
    dynamic_analysis_timeout = 30
    dynamic_analysis_ios_start_timeout = 120
    uninstall_apps = True
    force = False

    devices = [{"name": None, "serial": None, "type": None, "os": None, "ip": None, "network_adapter": None, "snapshot": None, "avd": None}]
    device = None
    dev = None
    dev_name = None

    network_adapter = None
    ips = {"android": None, "ios": None}

    play_store_email = None
    play_store_aastoken = None
    app_store_email = None
    app_store_password = None

    android_abi = "arm64-v8a"
    apps = []

    def from_dict(self, data: dict, dev_arg: str = None):
        """
        Configure the config from a dictionary of settings
        :param data: The dictionary of settings
        """

        if not exists(data["work_dir"]):
            logger.error("Provided working directory could not be found")
            exit(1)

        for key in [
            "logging",
            "dump_timeout",
            "radare_timeout",
            "radare_memory_limit",
            "radare_servers",
            "dynamic_analysis_timeout",
            "dynamic_analysis_ios_start_timeout",
            "uninstall_apps",
            "devices",
            "network_adapter",
            "ips",
            "play_store_email",
            "play_store_aastoken",
            "app_store_email",
            "app_store_password",
            "android_abi",
        ]:
            if key in data:
                self.__setattr__(key, data[key])
        self.work_dir = abspath(data["work_dir"])
        
        # Single device, set Config values
        if dev_arg is not None:
            for dev_i in self.devices:
                if dev_i["name"] == dev_arg:
                    self.device = dev_i
                    self.dev = dev_i["serial"]
                    self.dev_name = dev_i["name"]
                    self.ips = {dev_i["os"]: dev_i["ip"]}
                    self.network_adapter = dev_i["network_adapter"]
                    break
            else:
                logger.error(f"Device {dev_arg} not found in config file")
        else:
            # Take first device in list
            self.device = self.devices[0]
            self.dev = self.devices[0]["serial"]
            self.dev_name = self.devices[0]["name"]
            self.ips = {self.devices[0]["os"]: self.devices[0]["ip"]}
            self.network_adapter = self.devices[0]["network_adapter"]
        print(f"Device: {self.device}")
        
        for mobile_os in ["ios", "android"]:
            if mobile_os not in data["apps"] or data["apps"][mobile_os] is None:
                continue
            self.apps.extend([App(app, mobile_os, self.dev_name) for app in data["apps"][mobile_os]])

    def connect_telnet(self):
        """
        Connect to the telnet reverse shell
        """
        logger.info("Connecting to telnet reverse shell")
        if self.device is not None and "telnet" not in self.device:
            self.device["telnet"] = TelnetReverseShell(self.device["ip"], 10847)
        elif self.device is not None and "telnet" in self.device and not self.device["telnet"].is_connected():
            self.device["telnet"].connect()
        else:
            return False
        return "telnet" in self.device and self.device["telnet"].is_connected()