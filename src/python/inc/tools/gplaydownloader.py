from inc.util import temp_path, tools_path, workdir_path, run_system_command
from inc.config import Config
from models.app import App
from os.path import join, exists
import os
import logging
import glob

logger = logging.getLogger("hardeninganalyzer")


def download_apk(app: App) -> bool:
    """
    Download an app from the Google Play Store using gplay-downloader
    """
    # Save app id in a file
    app_ids = temp_path("appids.txt")
    with open(app_ids, "w") as f:
        f.write(app.package_id)

    # Save auth config in a file
    auth_config = temp_path("authconfig.txt")
    with open(auth_config, "w") as f:
        f.write(f"{Config().play_store_email} {Config().play_store_aastoken}")

    os.makedirs(app.get_binaries_path(), exist_ok=True)

    # Delete any previous (failed) downloads
    for file in glob.glob(join(app.get_binaries_path(), "*.apk")):
        os.remove(file)

    # Download the app
    (success, result, _) = run_system_command(
        f"java -jar {tools_path('gplay-downloader.jar')} -a {app_ids} -c {auth_config} -o {workdir_path(join('binary', app.os))}", timeout=None
    )
    if success:
        if not f"Downloaded AppId {app.package_id}" in result:
            logger.error(f"Failed to download {app.package_id}: {result}")
            success = False
        else:
            # Rename {package_id}.apk to base.apk
            os.rename(
                join(app.get_binaries_path(), f"{app.package_id}.apk"),
                join(app.get_binaries_path(), "base.apk"),
            )
    else:
        logger.error(f"Failed to download {app.package_id}: {result}")

    # Remove created files
    os.remove(app_ids)
    os.remove(auth_config)

    if exists("log.txt"):
        os.remove("log.txt")

    return success
