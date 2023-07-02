from __future__ import annotations
from typing import TYPE_CHECKING
from abc import ABC
from androguard.core.bytecodes import apk
import frida.core
from models.message import DynamicMessage

if TYPE_CHECKING:
    from models.nativebinary import NativeBinary

class Detector(ABC):
    def __init__(self):
        self.static_results = []
        """Static results of the detector"""
        
        self.dynamic_results = []
        """Dynamic results of the detector"""

    def get_id(self) -> str:
        """
        Get the id of the detector
        :return: Id of the detector
        """
        raise NotImplementedError

    def static_analyze_manifest(self, app_apk: apk.APK) -> None:
        """
        During static analysis, analyze the manifest of an Android app
        :param app_apk: APK object of the app
        """
        pass

    def static_analyze_network_security_config(self, config_file: str, config_xml: str, config_dict: dict) -> None:
        """
        During static analysis, analyze the network security config of an Android app
        :param config_file: Path to the network security config file
        :param config_xml: XML content of the network security config
        :param config_dict: XML content of the network security config parsed as a dictionary
        """
        pass

    def static_analyze_info_plist(self, plist: dict):
        """
        During static analysis, analyze the Info.plist of an iOS app
        :param plist: Content of Info.plist of the app
        """
        pass

    def static_analyze_plaintext(self) -> None:
        """
        During static analysis, analyze plaintext files
        """
        pass

    def static_analyze_r2(self, binary: NativeBinary) -> None:
        """
        During static analysis, analyze a binary with radare2
        :param binary: Binary to analyze
        """
        pass

    def dynamic_before_analysis(self):
        """
        Runs just before starting the application for dynamic analysis
        """
        pass

    def dynamic_after_analysis(self):
        """
        Runs just after the application has run for dynamic analysis
        """
        pass

    def dynamic_get_data(self) -> dict:
        """
        During dynamic analysis, get data to send to the app
        :return: Data to send to the app
        """
        return {}

    def dynamic_instrument(self, script: frida.core.Script, is_main_process: bool) -> None:
        """
        Instrument app during dynamic analysis when a process is started
        :param script: Frida script to use for RPC calls
        :param is_main_process: True if the process is the main process of the app, False otherwise
        """
        pass

    def dynamic_handle_message(self, message: DynamicMessage) -> bool:
        """
        During dynamic analysis, handle an incoming Frida message
        :param message: Received message
        :return: True if the message was handled, False otherwise
        """
        if message.detector == self.get_id():
            self.dynamic_results.append(message)

            return True
        return False