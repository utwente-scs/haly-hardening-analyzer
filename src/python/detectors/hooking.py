from detectors.detector import Detector
from functools import cache
from inc.context import Context
from inc.util import data_path, pattern_to_regex
from models.message import StringStaticMessage, NativeFunctionStaticMessage
import pyjson5
from inc.tools.codesearch import search_plaintext
from models.nativebinary import NativeBinary


class HookingDetector(Detector):
    def get_id(self) -> str:
        return "hooking"

    @cache
    def _get_data(self) -> dict:
        with open(
            data_path(f"detectors/hooking/hooking-{Context().get_os()}.json5"), "r"
        ) as f:
            return pyjson5.decode_io(f)

    def _static_get_patterns(self) -> list:
        data = self._get_data()
        return data["files"] + data["apps"]

    def static_analyze_plaintext(self) -> None:
        patterns = self._static_get_patterns()

        for pattern in patterns:
            for result in search_plaintext(pattern_to_regex(pattern)):
                self.static_results.append(
                    StringStaticMessage(result["source"], pattern, result)
                )

    def static_analyze_r2(self, binary: NativeBinary) -> None:
        if Context().app.os != "ios":
            return

        for call in ["_dyld_image_count", "_dyld_get_image_name"]:
            for result in binary.find_syscalls(call):
                self.static_results.append(
                    NativeFunctionStaticMessage(binary.path, call, result, False)
                )

    def dynamic_get_data(self) -> dict:
        return {"hooking": self._get_data()}
