from inc.util import data_path
from models.app import App
import json
from functools import cache
from inc.config import Config


@cache  # Singleton
class Context:
    stage: str = None
    """Stage of the analysis (e.g. 'static', 'dynamic')"""

    app: App | None = None
    """App being analyzed"""

    modules: list[dict] = []

    _device_info = None

    # Device info
    def set_device_info(self, device_info: dict) -> None:
        """
        Set the device info of the connected device returned by the frida query_system_parameters() function
        :param device_info: device info
        """
        self._device_info = device_info

    def get_device_info(self) -> dict:
        """
        Get the device info of the connected device returned by the frida query_system_parameters() function
        """
        return self._device_info

    def get_device_ip(self) -> str | None:
        """
        Get the IP address of the connected device
        """
        device_os = self.get_os()
        if device_os in Config().ips:
            return Config().ips[device_os]
        else:
            return None

    def get_architecture(self) -> str:
        """
        Get the CPU architecture of the connected device
        """
        return self._device_info["arch"] if self._device_info is not None else None

    def get_os(self) -> str:
        """
        Get the OS of the app being analyzed
        """
        return self.app.os

    def is_ios(self) -> bool:
        """
        Check if the app being analyzed is an iOS app
        """
        return self.get_os() == "ios"

    def is_android(self) -> bool:
        """
        Check if the app being analyzed is an Android app
        """
        return self.get_os() == "android"

    def get_os_version(self):
        """
        Get the OS version of the connected device (e.g. 12)
        """
        return (
            self._device_info["os"]["version"]
            if self._device_info is not None
            else None
        )

    def get_package_id(self) -> str:
        """
        Get the package id of the app to be analyzed
        """
        return self.app.package_id

    # SVC syscalls
    def get_svc_code(self) -> str:
        """
        Get platform specific id used for syscalls using the svc asm instruction
        """
        if self.is_ios():
            return "0x80"
        elif self.is_android():
            return "0"
        else:
            raise Exception("Unsupported OS")

    def get_svc_instruction_registry(self) -> str:
        """
        Get the address where the id of the syscall to be executed is stored
        """
        if self.is_ios():
            return "x16"
        elif self.is_android():
            # Android
            return "x8"
        else:
            raise Exception("Unsupported OS")

    def get_syscall_name(self, id: int) -> str:
        """
        Get the name of the syscall with the given id
        """
        names = self.get_syscall_names()
        return names[id] if id in names else None

    @cache
    def get_syscall_names(self) -> dict[int, str]:
        """
        Get the names of all syscalls
        """
        with open(data_path(f"syscalls/syscalls-{self.get_os()}.json")) as f:
            return {int(id): name for id, name in json.load(f).items()}

    def to_dict(self) -> dict:
        """
        Get the context as a dict to be sent to the frida script
        """
        return {
            "device_info": self._device_info,
            "package_id": self.get_package_id(),
            "os": self.get_os(),
        }
