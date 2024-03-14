from models.app import App
import glob
from os.path import join, isdir
import os
import shutil
import logging
import zipfile
import json
import frida
from inc.tools.apktool import decompile as apktool_decompile
from inc.tools.frida import FridaApplication
from inc.tools.appmanager import install_app, uninstall_app
from inc.tools.codesearch import index as codesearch_index
from inc.util import glob_by_magic
from inc.config import Config
from inc.context import Context
import plistlib
from models.nativebinary import NativeBinary
from detectors import Detectors

logger = logging.getLogger("hardeninganalyzer")


def decompile(app: App):
    """
    Decompile an app for static analysis and decrypt it if necessary
    """
    logger.info(f"Decompiling app {app.package_id}...")

    Context().app = app
    Context().stage = "decompile"

    if app.get_stage() < 1:
        logger.error(f"App must be downloaded before running decompile")
        return

    if app.get_stage() == 1 or Config().force:
        if _decompile(app):
            app.set_stage(2)
    else:
        logger.info(f"Skipping decompilation of {app.package_id}, already decompiled")

    if app.get_stage() == 2 or Config().force:
        _clean_files(app)
        app.set_stage(3)


def index(app: App) -> None:
    """
    Prepare an app for analysis by extracting strings and indexing it
    """
    logger.info(f"Preparing {app.package_id} for analysis")

    Context().app = app
    Context().stage = "index"

    if app.get_stage() < 3:
        logger.error(f"App must be decompiled before running index")
        return
    elif app.get_stage() >= 5 and not Config().force:
        logger.info(f"Skipping index of {app.package_id}, already indexed")
        return

    if app.get_stage() == 3 or Config().force:
        _extract_strings(app)
        app.set_stage(4)

    if app.get_stage() == 4 or Config().force:
        _index(app)
        app.set_stage(5)


def _decompile(app: App):
    """
    Decompile an app and decrypt it if necessary
    """
    decompiled_path = app.get_decompiled_path()
    binaries = glob.glob(join(decompiled_path, f"*.{app.get_binary_extension()}"))

    for binary in binaries:
        decompiled = False
        if Context().is_android():
            decompiled = apktool_decompile(binary)

        if not decompiled:
            # Unzip file
            if not _unzip(binary):
                return False
        if Context().is_ios():
            # Decrypt
            return _decrypt(app)

    obbs = glob.glob(join(decompiled_path, f"*.{app.get_binary_extension()}"))
    for obb in obbs:
        if not _unzip(obb):
            return False

    return True


def _unzip(path: str) -> bool:
    """
    Unzip a file
    :param path: The path to the zip file
    :return: Whether the file was unzipped successfully
    """
    try:
        with zipfile.ZipFile(path, "r") as f:
            f.extractall(path[:-4])
        return True
    except zipfile.BadZipFile:
        logger.error(f"Failed to unzip {path}")
        return False


def _decrypt(app: App) -> bool:
    """
    Decrypt an app
    :param app: The app to decrypt
    :return: Whether the app was decrypted successfully
    """
    logger.debug(f"Decrypting app {app.package_id}...")

    # Install app if not installed
    success = install_app(app)
    if not success:
        logger.error(f"Failed to install app {app.package_id}")
        return False

    # Use an array so we can keep a reference to the frida app
    frida_app = None

    global decrypted, crashed
    decrypted = False
    crashed = False

    def on_message(message, data):
        """
        Handle a Frida message
        Print errors and send messages to the detectors
        """
        if message["type"] == "send":
            message = message["payload"]

            if message["type"] == "log":
                logger.log(
                    logging.getLevelName(message["level"].upper()), message["message"]
                )
                return

            if message["type"] == "dump":
                if message["complete"]:
                    logger.debug(f"App dump completed")
                    global decrypted
                    decrypted = True
                    frida_app.stop()
                else:
                    logger.debug(
                        f"Module {message['module']} dumped with size {len(data)} at offset {message['offset']}"
                    )
                    # We split path at slash before the .app directory
                    # E.g. /private/var/containers/Bundle/Application/Example.app/Frameworks/Example.dylib
                    # Should become Example.app/Frameworks/Example.dylib
                    path = message["path"].split("/")
                    index_of_app = [
                        i for i, x in enumerate(path) if x.endswith(".app")
                    ][0]
                    path = join(
                        app.get_main_binary_path()[:-4],
                        "Payload",
                        "/".join(path[index_of_app:]),
                    )

                    open(path, "a").close()  # Create file if it doesn't exist
                    with open(path, "r+b") as f:
                        f.seek(message["offset"])
                        f.write(data)

        elif message["type"] == "error":
            if "stack" in message:
                error = message["stack"]
            else:
                error = json.dumps(message)
            if "unable to intercept function" in error:
                # We ignore svc instructions that we are unable to hook since they may not be actual instructions
                return
            logger.error(f"Error from frida: {error}")

    def on_instrument(script: frida.core.Script, is_main_process: bool):
        """
        On instrumentation of a binary, export decryted modules
        """
        try:
            script.exports.dump_modules()
        except frida.InvalidOperationError as e:
            if "script has been destroyed" in str(e):
                global crashed
                crashed = True
                frida_app.stop()
            else:
                raise e

    # Get context and add data from detectors
    context = Context().to_dict()
    context.update(Detectors().dynamic_get_data())

    attempt = 0
    while attempt < 3:
        frida_app = FridaApplication(
            app,
            {"context": context},
            on_message,
            on_instrument,
            Config().dump_timeout,
            False,
        )
        frida_app.run()
        if crashed or not decrypted and attempt + 1 < 3:
            logger.warning(f"App may have crashed during dump, retrying...")
            attempt += 1
        else:
            break

    if attempt == 3 or not decrypted:
        logger.error(f"Failed to dump app {app.package_id}")

    if Config().uninstall_apps:
        # Uninstall the app from the device
        uninstall_app(app)

    return decrypted


def _clean_files(app: App):
    """
    Remove files not used during analysis to save disk space
    :param app: The app to clean
    """
    logger.debug(f"Cleaning files for app {app.package_id}...")

    # Remove unnecessary lib files
    if app.os == "android":
        for lib in glob.glob(join(app.get_binaries_path(), "*", "lib", "*/")):
            if not lib.strip("/").endswith(Config().android_abi):
                # Lib files are not for current architecture
                shutil.rmtree(lib)

    # Remove photos, videos, fonts etc.
    for root, dirs, files in os.walk(app.get_binaries_path()):
        for file in files:
            imgs = (
                ".jpg",
                ".jpeg",
                ".png",
                ".gif",
                ".bmp",
                ".tiff",
                ".tif",
                ".webp",
                ".ico",
            )
            videos = (
                ".mp4",
                ".mov",
                ".avi",
                ".mpg",
                ".mpeg",
                ".mkv",
                ".flv",
                ".wmv",
                ".webm",
            )
            audio = (
                ".mp3",
                ".wav",
                ".aac",
                ".ogg",
                ".flac",
                ".m4a",
                ".wma",
                ".aiff",
                ".aif",
                ".m4r",
            )
            fonts = (".ttf", ".otf", ".woff", ".woff2", ".eot", ".ttc")
            games = (
                ".unity3d",
                ".atlas",
                ".spine",
                ".skel",
                ".ccreator",
                ".glsl",
                ".resource",
                ".bundle",
            )
            if file.endswith(imgs + videos + audio + fonts + games):
                os.remove(join(root, file))


def _extract_strings(app: App):
    """
    Extract strings from binary files so they can be indexed by codesearch
    :param app: The app to extract strings from
    """
    logger.debug(f"Extracting strings from app {app.package_id}...")

    # Monkey patch some plistlib functions to support proper binary to XML plists transcoding
    def _patched_escape(text):
        # Remove control characters
        text = plistlib._controlCharPat.sub("", text)

        text = text.replace("\r\n", "\n")  # convert DOS line endings
        text = text.replace("\r", "\n")  # convert Mac line endings
        text = text.replace("&", "&amp;")  # escape '&'
        text = text.replace("<", "&lt;")  # escape '<'
        text = text.replace(">", "&gt;")  # escape '>'
        text = text.replace("'", "&apos;")  # escape '''
        text = text.replace('"', "&quot;")  # escape '"'

        return text

    plistlib._escape = _patched_escape

    class PlistWriter(plistlib._PlistWriter):
        def write_value(self, value):
            if isinstance(value, plistlib.UID):
                self.simple_element("integer", "%d" % value)
            else:
                super().write_value(value)

    plistlib._FORMATS[plistlib.FMT_XML]["writer"] = PlistWriter

    # Convert binary plist files to xml
    for plist_file in glob_by_magic(app.get_decompiled_path(), b"bplist"):
        try:
            with open(plist_file, "rb") as f:
                plist = plistlib.load(f)

            with open(plist_file, "wb") as f:
                plistlib.dump(plist, f, fmt=plistlib.FMT_XML)
        except Exception as e:
            logger.warning(
                f"Failed to convert binary plist file {plist_file} to xml: {e}"
            )

    # Extract strings from binary files
    native_files = app.get_native_files()
    for native_file in native_files:
        logger.debug(f"Extracting strings from native file {native_file}...")

        # Analyze native file with radare2
        binary = NativeBinary(native_file)
        binary.extract_strings()


def _index(app: App):
    """
    Index the app using codesearch
    :param app: The app to index
    """
    logger.debug(f"Indexing app {app.package_id}...")

    app = Context().app
    codesearch_index(app.get_binaries_path(), False)
