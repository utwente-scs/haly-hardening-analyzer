from detectors.detector import Detector
from models.message import (
    SmaliStaticMessage,
    StringStaticMessage,
    NativeFunctionStaticMessage,
)
from inc.tools.codesearch import search_smali, search_plaintext
from inc.context import Context
from inc.util import pattern_to_regex
from models.nativebinary import NativeBinary


class TamperDetector(Detector):
    def get_id(self) -> str:
        return "tamper"

    def static_analyze_r2(self, binary: NativeBinary) -> None:
        for result in binary.find_objc_call(
            "attestKey:clientDataHash:completionHandler:"
        ):
            self.static_results.append(
                NativeFunctionStaticMessage(
                    binary.path, "DCAppAttestService::attestKey", result
                )
            )

    def static_analyze_plaintext(self) -> None:
        if Context().is_android():
            # Check for packageInfo.signatures
            signature = "Landroid/content/pm/PackageInfo;->signatures:[Landroid/content/pm/Signature;"
            for smali_file in search_smali(signature):
                for result in smali_file.find_call(signature, "object"):
                    self.static_results.append(
                        SmaliStaticMessage(
                            smali_file.file,
                            "android.content.pm.PackageInfo::signatures",
                            result,
                            False,
                        )
                    )

            # Check for packageInfo.signingInfo
            signature = "Landroid/content/pm/PackageInfo;->signingInfo:Landroid/content/pm/SigningInfo;"
            for smali_file in search_smali(signature):
                for result in smali_file.find_call(signature, "object"):
                    self.static_results.append(
                        SmaliStaticMessage(
                            smali_file.file,
                            "android.content.pm.PackageInfo::signingInfo",
                            result,
                            False,
                        )
                    )

            # Check for PackageManager.hasSigningCertificate()
            signature = "Landroid/content/pm/PackageManager;->hasSigningCertificate"
            for smali_file in search_smali(signature):
                for result in smali_file.find_call(signature):
                    self.static_results.append(
                        SmaliStaticMessage(
                            smali_file.file,
                            "android.content.pm.PackageManager::hasSigningCertificate",
                            result,
                        )
                    )

            # Check for Google Play Integrity API
            signature = "Lcom/google/android/play/core/integrity/IntegrityManager;->requestIntegrityToken"
            for smali_file in search_smali(signature):
                for result in smali_file.find_call(signature):
                    self.static_results.append(
                        SmaliStaticMessage(
                            smali_file.file,
                            "com.google.android.play.core.integrity.IntegrityManager::requestIntegrityToken",
                            result,
                        )
                    )

            # Check for SafetyNet API
            signature = "Lcom/google/android/gms/safetynet/SafetyNetClient;->attest"
            for smali_file in search_smali(signature):
                for result in smali_file.find_call(signature):
                    self.static_results.append(
                        SmaliStaticMessage(
                            smali_file.file,
                            "com.google.android.gms.safetynet.SafetyNetClient::attest",
                            result,
                        )
                    )
