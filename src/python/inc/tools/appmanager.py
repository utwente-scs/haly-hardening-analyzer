from inc.tools.adb import adb
from models.app import App
import glob
from os.path import join, exists
import logging
import shlex
from inc.util import run_system_command
from inc.context import Context
from time import sleep
from tidevice.exceptions import SocketError

logger = logging.getLogger('hardeninganalyzer')

def is_app_installed(app: App) -> bool:
    """
    Check if an app is installed on the device
    :param app: app to check
    :return: whether the app is installed
    """
    if Context().is_ios():
        while True:
            (success, output, _) = run_system_command(f'tidevice appinfo {app.package_id}')
            if not success and "ConnectionRefusedError" in output:
                logger.error('Could not connect to iPhone. Is it connected?')
                sleep(2)
            else:
                return success

    elif Context().is_android():
        package_installed = adb(f'shell pm list packages {app.package_id}')
        if package_installed is False:
            exit(1)
        else:
            return package_installed.strip() != ''

def install_app(app: App, wait_to_finish: bool=True) -> bool:
    """
    Install an app on the device
    :param app_id: app to install
    :param wait_to_finish: whether to wait for the app to be installed
    :return: whether the app was installed
    """
    logger.debug(f"Installing app {app.package_id}")

    # Check if the app is not already installed
    if is_app_installed(app):
        logger.debug(f"Skipping, app is already installed")
        return True

    if Context().is_ios():
        # Check if the app is already downloaded
        ipa = app.get_main_binary_path()
        if exists(ipa):
            # Install app via ipa
            while True:
                (success, result, _) = run_system_command(f'tidevice install {ipa}')
                if not success and ("ConnectionRefusedError" in result or "unable to connect" in result):
                    logger.error('Could not connect to iPhone. Is it connected?')
                    sleep(2)
                elif success:
                    return True
                else:
                    logger.error(f"Failed to install app {app.package_id}: {result}")
                    break
        else:
            logger.error(f"Could not find ipa for app {app.package_id}")

    elif Context().is_android():
        # Check if the app is already downloaded
        apks = glob.glob(join(app.get_binaries_path(), '*.apk'))
        if len(apks) > 0:
            # Install app via apks
            apks = ' '.join([shlex.quote(apk) for apk in apks])
            if adb(f'install-multiple {apks}') is not False:
                return True

    return False

def uninstall_app(app: App) -> bool:
    """
    Uninstall an app from the device
    :param app: app to uninstall
    :return: whether the app was uninstalled
    """
    if Context().is_ios():
        while True:
            (success, result, _) = run_system_command(f'tidevice uninstall {app.package_id}')
            if not success and "ConnectionRefusedError" in result:
                logger.error('Could not connect to iPhone. Is it connected?')
                sleep(2)
            elif success:
                return True
            else:
                logger.error(f"Failed to uninstall app {app.package_id}: {result}")
                break
    elif Context().is_android():
        success = adb(f'uninstall {app.package_id}')
        if not success:
            logger.error(f"Failed to uninstall app {app.package_id}")
        return success
    
    return False

def grant_permissions(app: App, permissions: list[str]):
    """
    Grant permissions to the app
    :param permissions: permissions to grant
    """
    for permission in permissions:
        adb(f'shell pm grant {app.package_id} {permission}', True)
