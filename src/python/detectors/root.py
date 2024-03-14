from detectors.detector import Detector
from inc.util import data_path, pattern_to_regex
from inc.context import Context
from models.message import (
    StringStaticMessage,
    NativeFunctionStaticMessage,
    DynamicMessage,
)
from functools import cache
import pyjson5
from inc.tools.codesearch import search_plaintext
from models.nativebinary import NativeBinary


class RootDetector(Detector):
    def get_id(self) -> str:
        return "root"

    @cache
    def _get_data(self) -> dict:
        with open(
            data_path(f"detectors/root/root-{Context().get_os()}.json5"), "r"
        ) as f:
            return pyjson5.decode_io(f)

    def static_analyze_plaintext(self) -> None:
        data = self._get_data()
        patterns = data["files"]["static"]

        if Context().is_android():
            patterns = [
                pattern_to_regex(pattern)
                for pattern in set(patterns + data["apps"]["blacklist"])
            ]
        elif Context().is_ios():
            # On iOS, apps are checked by URI
            patterns = [pattern_to_regex(pattern) for pattern in patterns]
            patterns += [
                "(^|[\"'])" + pattern.replace("*", ".*") + "://.*"
                for pattern in data["apps"]["blacklist"]
            ]

        su_pattern = pattern_to_regex("su")
        for pattern in patterns:
            for result in search_plaintext(pattern):
                # su causes some false-positives
                confident = pattern != su_pattern or "/su" in result["line"]
                self.static_results.append(
                    StringStaticMessage(result["source"], pattern, result, confident)
                )

    def static_analyze_r2(self, binary: NativeBinary) -> None:
        confident = True
        if "Frameworks/libswift" in binary.path:
            # Likely a util function
            confident = False

        for syscall in self._get_data()["syscalls"]:
            for result in binary.find_syscalls(syscall):
                self.static_results.append(
                    NativeFunctionStaticMessage(binary.path, syscall, result, confident)
                )

    def dynamic_handle_message(self, message: DynamicMessage) -> bool:
        if message.detector == self.get_id():
            if message.type == "file" and not self._confident(message.file):
                message.confident = False
            self.dynamic_results.append(message)

            return True
        return False

    def _confident(self, path: str) -> bool:
        data = self._get_data()
        for pattern in data["files"]["ro"]:
            if pattern.startswith("/etc/"):
                continue

            if path.strip("/").startswith(pattern.strip("/")):
                return False

        return True

    def dynamic_get_data(self) -> dict:
        return {"root": self._get_data()}
