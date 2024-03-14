from inc.util import *
import static
import dynamic
import download
import prepare


def download_apps():
    for app in Config().apps:
        download.download(app)


def decompile_apps():
    for app in Config().apps:
        prepare.decompile(app)


def index_apps():
    for app in Config().apps:
        prepare.index(app)


def analyze_static():
    for app in Config().apps:
        static.analyze(app)


def analyze_dynamic():
    for app in Config().apps:
        dynamic.analyze(app)
