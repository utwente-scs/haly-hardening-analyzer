from inc.util import tools_path, run_system_command
from inc.config import Config
from models.app import App
from os.path import join
import os
import logging
import platform
import json
from getpass import getpass

logger = logging.getLogger("hardeninganalyzer")

keychain_passphrase = None

os_name = platform.system().lower()
if os_name == "darwin":
    os_name = "macos"
arch = platform.machine().lower()
if arch == "x86_64":
    arch = "amd64"
ipatool_path = f"ipatool-{os_name}-{arch}"
ipatool = tools_path(f"{ipatool_path} --non-interactive --format json")


def _execute_ipatool_command(command: str, error_ok: bool = False) -> str:
    """
    Execute an ipatool command
    :param command: The command to execute
    :param error_ok: Whether to ignore errors
    :return: The result of the command
    """
    global keychain_passphrase

    if keychain_passphrase is not None:
        command += f" --keychain-passphrase {keychain_passphrase}"

    (success, result, _) = run_system_command(f"{ipatool} {command}", timeout=None)
    if "--auth-code" in result:
        auth_code = input("Please enter the 2FA code for your Apple account: ")
        command += f" --auth-code {auth_code}"
        return _execute_ipatool_command(command)
    elif "--keychain-passphrase" in result and keychain_passphrase is None:
        keychain_passphrase = getpass(
            "Please enter your keychain passphrase to save or access the credentials: "
        )
        return _execute_ipatool_command(command)

    if not success or not '"success":true' in result:
        if not error_ok:
            if keychain_passphrase is not None:
                command = command.replace(
                    keychain_passphrase, "*" * len(keychain_passphrase)
                )
            logger.error(f"Failed to execute ipatool command '{command}': {result}")
        return None
    else:
        return result


def download_ipa(app: App) -> bool:
    """
    Download an app from the App Store using ipatool
    :param app: The app to download
    """
    # Authentication
    result = _execute_ipatool_command(f"auth info", True)
    if result is None:
        # (Re-)authenticate user
        result = _execute_ipatool_command(
            f"auth login -e {Config().app_store_email} -p {Config().app_store_password}"
        )
        if result is None:
            logger.error(f"Failed to authenticate")
            return False

    # Download the app
    os.makedirs(app.get_binaries_path(), exist_ok=True)
    result = _execute_ipatool_command(
        f"download --purchase -b {app.package_id} -o {app.get_binaries_path()}"
    )
    if result is None:
        logger.error(f"Failed to download {app.package_id}")

        return False
    else:
        # Rename {package_id}.ipa to base.ipa
        os.rename(
            json.loads(result)["output"], join(app.get_binaries_path(), "base.ipa")
        )

        return True
