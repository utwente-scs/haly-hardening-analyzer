from detectors.detector import Detector
from models.smali import Smali
from models.nativebinary import NativeBinary
from models.message import NativeFunctionStaticMessage, SmaliStaticMessage
from inc.tools.codesearch import search_smali
from inc.context import Context


class DebugDetector(Detector):
    def get_id(self) -> str:
        return "debug"

    def static_analyze_r2(self, binary: NativeBinary) -> None:
        functions = ["ptrace"]
        if Context().is_ios():
            functions += ["sysctl", "getppid"]
        for call in functions:
            for result in binary.find_syscalls(call):
                self.static_results.append(
                    NativeFunctionStaticMessage(
                        binary.path, call, result, "sysctl" not in call
                    )
                )

    def static_analyze_plaintext(self) -> None:
        # Check for android.os.Debug.isDebuggerConnected(), android.os.Debug.waitingForDebugger()
        for function in ["isDebuggerConnected", "waitingForDebugger"]:
            signature = f"Landroid/os/Debug;->{function}()Z"
            for smali_file in search_smali(signature):
                for result in smali_file.find_call(signature):
                    self.static_results.append(
                        SmaliStaticMessage(
                            smali_file.file, f"android.os.Debug::{function}", result
                        )
                    )

        # Check for android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE
        signature = "->getApplicationInfo()Landroid/content/pm/ApplicationInfo;"
        for smali_file in search_smali(signature):
            for result in smali_file.find_call(signature):
                # TODO: Check if compared to FLAG_DEBUGGABLE
                self.static_results.append(
                    SmaliStaticMessage(
                        smali_file.file,
                        "android.content.ContextWrapper::getApplicationInfo",
                        result,
                        False,
                    )
                )

        # Check for android.provider.Settings.Secure.getString()
        signatures = [
            "Landroid/provider/Settings$Secure;->get",
            "Landroid/provider/Settings$Global;->get",
        ]
        for signature in signatures:
            for smali_file in search_smali(signature):
                for result in smali_file.find_call(signature):
                    if "->getUriFor" in result["line"]:
                        # Only match getFloat, getInt, getLong, getString
                        continue

                    if len(result["args"]) > 1 and result["args"][1] is not None:
                        if result["args"][1] not in [
                            "adb_enabled",
                            "development_settings_enabled",
                            "mock_location",
                        ]:
                            continue

                    self.static_results.append(
                        SmaliStaticMessage(
                            smali_file.file,
                            "android.provider.Settings$Secure::getString",
                            result,
                            len(result["args"]) > 1 and result["args"][1] is not None,
                        )
                    )
