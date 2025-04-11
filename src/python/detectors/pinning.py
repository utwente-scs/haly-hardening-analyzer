from androguard.core import apk
from androguard.core.axml import AXMLPrinter
from detectors.detector import Detector
from inc.context import Context
from models.message import (
    StringStaticMessage,
    NetworkConfigStaticMessage,
    SmaliStaticMessage,
)
from inc.tools.codesearch import search_plaintext, search_smali
import os
import logging
import xmltodict

logger = logging.getLogger("hardeninganalyzer")


class PinningDetector(Detector):
    # TODO: Add detection of iOS pinning functions
    def get_id(self) -> str:
        return "pinning"

    def static_analyze_plaintext(self) -> None:
        # Find certificate hashes or text
        pin_pattern = "sha(1|256)/[a-zA-Z0-9+/=]{28,64}"
        cert_pattern = "\-\-\-\-\-(BEGIN CERTIFICATE|BEGIN PKCS7)\-\-\-\-\-(([A-Za-z0-9+=/\\\]|\n)(?!BEGIN))+\-\-\-\-\-(END CERTIFICATE|END PKCS7)\-\-\-\-\-"
        patterns = [pin_pattern, cert_pattern]

        for pattern in patterns:
            for result in search_plaintext(pattern):
                self.static_results.append(
                    StringStaticMessage(result["source"], pattern, result)
                )

        # Find certificate files
        cert_extensions = [".cert", ".crt", ".pem", ".der", ".cer"]
        app_dir = Context().app.get_decompiled_path()
        for root, dirs, files in os.walk(app_dir):
            for file in files:
                extension = os.path.splitext(file)[1].lower()
                if extension in cert_extensions:
                    with open(os.path.join(root, file), "rb") as f:
                        try:
                            line = f.read().decode("utf-8")
                        except UnicodeDecodeError:
                            line = None

                        # TODO: This could lead to duplicates, should we check for that?
                        self.static_results.append(
                            StringStaticMessage(
                                os.path.join(root, file),
                                extension,
                                {
                                    "line": line,
                                    "line_nr": 1,
                                },
                            )
                        )

    def static_analyze_network_security_config(
        self, config_file: str, config_xml: str, config_dict: dict
    ) -> None:
        try:
            domain_config = config_dict["network-security-config"]["domain-config"]
            if not isinstance(domain_config, list):
                domain_config = [domain_config]
            for domain in domain_config:
                if "pin-set" in domain:
                    self.static_results.append(
                        StringStaticMessage(
                            config_file,
                            "pin-set",
                            {
                                "line": xmltodict.unparse(
                                    {"pin-set": domain["pin-set"]}, full_document=False
                                ),
                                "line_nr": 1,
                            },
                        )
                    )
        except Exception:
            pass

    def static_analyze_info_plist(self, plist: dict):
        # Find App Transport Security settings
        if (
            "NSAppTransportSecurity" in plist
            and "NSPinnedDomains" in plist["NSAppTransportSecurity"]
            and len(plist["NSAppTransportSecurity"]["NSPinnedDomains"]) > 0
        ):
            self.static_results.append(
                NetworkConfigStaticMessage(
                    Context().app.get_decompiled_path(),
                    "NSPinnedDomains",
                    plist["NSAppTransportSecurity"]["NSPinnedDomains"],
                )
            )
