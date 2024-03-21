from os.path import join, dirname
from functools import cache
from os.path import exists, abspath
from models.app import App
import logging

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

    devs = []
    dev = None

    network_adapter = None
    ips = {"android": None, "ios": None}

    play_store_email = None
    play_store_aastoken = None
    app_store_email = None
    app_store_password = None

    android_abi = "arm64-v8a"
    apps = []

    def from_dict(self, data: dict):
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
            "devs",
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

        for mobile_os in ["ios", "android"]:
            if mobile_os not in data["apps"] or data["apps"][mobile_os] is None:
                continue
            self.apps.extend([App(app, mobile_os) for app in data["apps"][mobile_os]])
