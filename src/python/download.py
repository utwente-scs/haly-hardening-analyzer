from models.app import App
from inc.context import Context
from inc.config import Config
from os import listdir
from os.path import exists
import logging
from inc.tools.gplaydownloader import download_apk
from inc.tools.ipatool import download_ipa

logger = logging.getLogger('hardeninganalyzer')

def download(app: App):
    logger.info(f"Downloading {app.package_id} ({app.os})")

    # Start with a clean context for each app
    Context.cache_clear()

    Context().app = app
    Context().stage = 'download'

    # Check if app already downloaded
    if app.get_stage() >= 1 and exists(app.get_main_binary_path()) and not Config().force:
        logger.info(f"Skipping download of {app.package_id}, binary already exists in the working directory")
        return

    if Context().is_android():
        # Download using gplay-downloader
        success = download_apk(app)
    elif Context().is_ios():
        # Download using ipatool
        success = download_ipa(app)

    if success:
        app.set_stage(1)
    else:
        logger.error(f"Download failed for {app.package_id}")