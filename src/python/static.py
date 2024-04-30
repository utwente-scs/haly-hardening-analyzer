from models.app import App
from detectors import Detectors
from inc.context import Context
from models.nativebinary import NativeBinary
from androguard.core import apk
from androguard.core.axml import ResParserError
from androguard.core.axml import AXMLPrinter
import json
from inc.util import serializer
from inc.config import Config
from os.path import dirname, join
import os
import logging
import glob
import plistlib
import xmltodict

logger = logging.getLogger("hardeninganalyzer")


def analyze(app: App) -> None:
    """
    Analyze an app using static analysis
    """
    logger.info(f"Performing static analysis on {app.package_id}")

    # Start with a clean context for each app
    Context.cache_clear()
    Detectors.cache_clear()

    Context().app = app
    Context().stage = "static"

    if app.get_stage() < 5:
        logger.error(
            f"App must be decompiled and indexed before running static analysis"
        )
        return

    if app.get_stage() >= 6 and not Config().force:
        logger.info(
            f"Skipping static analysis of {app.package_id}, results already exist in the working directory"
        )
        return

    # Perform analysis
    if Context().is_android():
        if not _analyze_manifest():
            return
    elif Context().is_ios():
        _analyze_plist()

    _analyze_native_files()

    _analyze_plaintext_files()

    # Save results
    path = app.get_static_result_path()
    os.makedirs(dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(Detectors().get_static_results(), f, indent=4, default=serializer)

    app.set_stage(6)


def _analyze_manifest() -> bool:
    """
    Analyze the manifest of an app
    """
    logger.info("Analyzing manifest file...")

    app = Context().app

    app_apk = apk.APK(app.get_main_binary_path())

    # Analyze manifest
    try:
        for detector in Detectors():
            detector.static_analyze_manifest(app_apk)
    except ResParserError:
        logger.error("Failed to parse manifest file")
        return False

    # Analyze Network Security Config
    config_key = "{http://schemas.android.com/apk/res/android}networkSecurityConfig"
    config_res = (
        app_apk.get_android_manifest_xml().find("./application").get(config_key)
    )
    if config_res is None:
        logger.debug("No network security config found in manifest")
        return True

    try:
        if config_res[0] == "@":
            config_res = int(config_res[1:], 16)

        config_file = None
        for _, file in app_apk.get_android_resources().get_resolved_res_configs(
            config_res
        ):
            config_file = file
            break

        if config_file is None:
            logger.error("Could not find network security config file")
            return True

        config = app_apk.get_file(config_file)

        if config is None:
            logger.error("Could not find network security config file")
            return True

        config_xml = AXMLPrinter(config).get_xml(pretty=False).decode("utf-8")

        config_dict = xmltodict.parse(config_xml)

        for detector in Detectors():
            detector.static_analyze_network_security_config(
                os.path.join(app_apk.filename.replace(".apk", ""), config_file),
                config_xml,
                config_dict,
            )
    except Exception:
        logger.error("Could not parse network security config")

    return True


def _analyze_plist() -> None:
    """
    Analyze plist files of an app
    """
    logger.info("Analyzing info plist file...")

    app = Context().app
    info_plist_file = glob.glob(
        join(app.get_decompiled_path(), "*", "Payload", "*.app", "Info.plist")
    )[0]
    with open(info_plist_file, "rb") as f:
        info_plist = plistlib.load(f)

    for detector in Detectors():
        detector.static_analyze_info_plist(info_plist)


def _analyze_native_files() -> None:
    """
    Analyze the native files of an app
    """
    logger.info("Analyzing native files...")

    app = Context().app
    native_files = app.get_native_files()
    for native_file in native_files:
        logger.debug(f"Analyzing native file {native_file}...")

        # Analyze native file with radare2
        binary = NativeBinary(native_file)
        binary.analyze_r2()


def _analyze_plaintext_files() -> None:
    """
    Analyze plaintext files of an app for strings
    """
    logger.info("Analyzing plaintext files...")

    # Run analysis
    for detector in Detectors():
        detector.static_analyze_plaintext()
