from typing import Tuple
from flask import Flask, redirect, render_template
from inc.config import Config
from os.path import join, basename, exists, dirname
from inc.util import data_path, result_path
from models.message import StaticMessage, DynamicMessage
import json
import glob
import pandas as pd
from tqdm import tqdm
from pandasql import sqldf as psql
from flask_caching import Cache

flask_app = Flask(__name__)
flask_app.config.from_object(__name__)
flask_app.config["CACHE_TYPE"] = "SimpleCache" # better not use this type w. gunicorn
flask_app.config["apps_cache"] = None
flask_app.config["stats_cache"] = None
cache = Cache(flask_app)



@flask_app.route("/")
def index():
    return redirect("/apps")


def _get_apps_data():
    with open(data_path("apps/apps.json")) as f:
        apps_data = json.load(f)["apps"]
    return apps_data


@cache.cached()
def _get_apps() -> list:
    """
    Get a list of apps and filter out apps that are not available on both iOS and Android
    """
    apps_data = _get_apps_data()

    # Filter apps that are available on both OSes
    apps = []
    for app in apps_data:
        if app["ios_bundle_id"] is None or app["android_id"] is None:
            continue

        apps.append(app)

    return apps


# @cache.cached()
def _get_libraries() -> Tuple[list, list]:
    """
    Get a list of known libraries
    """
    with open(data_path("libraries/java.txt")) as f:
        known_java_libraries = [
            lib.strip()
            for lib in f.read().splitlines()
            if not lib.startswith("#") and lib.strip() != ""
        ]

    with open(data_path("libraries/native.txt")) as f:
        known_native_libraries = [
            lib.strip()
            for lib in f.read().splitlines()
            if not lib.startswith("#") and lib.strip() != ""
        ]

    return known_java_libraries, known_native_libraries


def get_library(result: dict) -> str:
    """
    Get the library the result originated from
    :param result: The result to get the library for
    :return: The library the result originated from or None if the library could not be determined
    """
    java_libs, native_libs = _get_libraries()

    # Remove libraries that are the same as the app id, should be considered internal code
    java_libs = [
        lib
        for lib in java_libs
        if not lib.startswith(result["app_id"]) and not result["app_id"].startswith(lib)
    ]

    if result["analysis_type"] == "static":
        if result["source"] is None:
            return None

        if result["type"] == "native" or result["source"].endswith(".nativestrings"):
            for lib in native_libs:
                if result["source"].endswith("/" + lib):
                    return lib
        elif "smali" in result["source"]:
            for lib in java_libs:
                if "/" + lib.replace(".", "/") + "/" in result["source"]:
                    return lib

    elif result["analysis_type"] == "dynamic":
        java_backtrace = (
            result["java_backtrace"] if "java_backtrace" in result else None
        )
        if java_backtrace is None and result["context"] == "java":
            java_backtrace = result["backtrace"]
        if java_backtrace is not None:
            java_backtrace = json.loads(java_backtrace)
            for lib in java_libs:
                if any(lib in item for item in java_backtrace):
                    return lib

        if result["context"] != "java":
            backtrace = json.loads(result["backtrace"])
            for lib in native_libs:
                if any(
                    lib in item["module"]
                    for item in backtrace
                    if item["module"] is not None
                ):
                    return lib

    return None


def _get_apps_results() -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, dict]:
    """
    Get the results of the analysis of all apps
    :return: A tuple containing the apps, app infos, app results and statistics
    """

    apps = []
    app_infos = []
    app_results = []
    app_counts = {
        "totalApps": 0,  # Number of apps in config to be analyzed
        "totalIosStatic": 0,  # Number of apps statically analyzed on iOS
        "totalIosDynamic": 0,  # Number of apps dynamically analyzed on iOS
        "totalAndroidStatic": 0,  # Number of apps statically analyzed on Android
        "totalAndroidDynamic": 0,  # Number of apps dynamically analyzed on Android
        "totalAnalyzed": 0,  # Number of apps that are statically analyzed on iOS and Android (might have failed dynamic analysis)
    }

    if not Config().force:
        print(
            "Checking for cached results, use --force to force re-calculating all results"
        )
        cached_data = {}
        for file in ["apps", "app_infos", "app_results", "app_counts"]:
            if exists(result_path(f"{file}_{Config().device['name']}.csv")):
                data = pd.read_csv(
                    join(result_path(""), f"{file}_{Config().device['name']}.csv"),
                    low_memory=False,
                    escapechar="\\",
                )
                if file == "app_counts":
                    data = dict(zip(data["key"], data["value"]))

                cached_data[file] = data

        if len(cached_data) == 4:
            print("Using cached results")
            return (
                cached_data["apps"],
                cached_data["app_infos"],
                cached_data["app_results"],
                cached_data["app_counts"],
            )

    android_to_app = {app["android_id"]: app for app in _get_apps()}
    print("Parsing app results...")
    for app in tqdm([app for app in Config().apps if app.os == "android"]):
        app_counts["totalApps"] += 1

        # Check if analysis of app is completed
        analysis_completed = True
        try:
            for app_os in ["ios", "android"]:
                for analysis_type in ["static", "dynamic"]:
                    package_id = (
                            android_to_app[app.package_id]["ios_bundle_id"]
                        if app_os == "ios"
                        else app.package_id
                    )
                    
                    if analysis_type == "dynamic":
                        json_file = join(
                            result_path(app_os), package_id, f"{analysis_type}_{Config().device['name']}.json"
                        )
                    else:
                        json_file = join(
                            result_path(app_os), package_id, f"{analysis_type}.json"
                        )

                    if exists(json_file):
                        app_counts[
                            f"total{app_os.capitalize()}{analysis_type.capitalize()}"
                        ] += 1
        except KeyError:
            print(f"KeyError {app.package_id}")
            analysis_completed = False
            continue
        if not analysis_completed:
            continue

        app_counts["totalAnalyzed"] += 1
        apps.append(android_to_app[app.package_id])

        # Process app results
        for app_os in ["ios", "android"]:
            for analysis_type in ["static", "dynamic"]:
                app_id = (
                    android_to_app[app.package_id]["ios_bundle_id"]
                    if app_os == "ios"
                    else app.package_id
                )
                other_app_id = (
                    app.package_id
                    if app_os == "ios"
                    else android_to_app[app.package_id]["ios_bundle_id"]
                )
                
                if analysis_type == "dynamic":
                    json_file = join(
                        result_path(app_os), app_id, f"{analysis_type}_{Config().device['name']}.json"
                    )
                else:
                    json_file = join(
                        result_path(app_os), app_id, f"{analysis_type}.json"
                    )
                    
                if not exists(json_file):
                    continue

                with open(json_file, "r") as f:
                    result = json.load(f)

                for detector in result.keys():
                    if detector == "info":
                        if not isinstance(result[detector], dict):
                            continue

                        app_info = _normalize(result[detector])
                        app_info["os"] = app_os
                        app_info["app_id"] = app_id
                        app_info["other_app_id"] = other_app_id
                        app_info["analysis_type"] = analysis_type
                        app_infos.append(app_info)
                    else:
                        if not isinstance(result[detector], list):
                            continue

                        for detection_result in result[detector]:
                            detection_result = _normalize(detection_result)

                            detection_result["os"] = app_os
                            detection_result["app_id"] = app_id
                            detection_result["other_app_id"] = other_app_id
                            detection_result["analysis_type"] = analysis_type
                            detection_result["detector"] = detector
                            detection_result["library"] = get_library(detection_result)

                            if _should_ignore_detection(detection_result):
                                continue
                            
                            if not ("pattern" in detection_result):
                                detection_result["pattern"] = ""
                            if not ("source" in detection_result):
                                detection_result["source"] = ""

                            app_results.append(detection_result)

                            if detection_result["detector"] == "tamper" and any(
                                attest in detection_result["function"]
                                for attest in ["IntegrityManager", "SafetyNetClient"]
                            ):
                                # SafetyNet and Play Integrity also provide root, hooking and emulator detection
                                for detector in ["root", "hooking", "emulation"]:
                                    detection_result = detection_result.copy()
                                    detection_result["detector"] = detector
                                    app_results.append(detection_result)

    # Sort by Android app name
    apps = sorted(apps, key=lambda app: app["android_id"])

    # Parse with pandas so we can use SQL
    print("Converting data to pandas...")
    apps = pd.DataFrame(apps)
    app_infos = pd.DataFrame(app_infos)
    app_results = pd.DataFrame(app_results)

    for file in ["apps", "app_infos", "app_results", "app_counts"]:
        data = locals()[file]
        if file == "app_counts":
            data = pd.DataFrame(data.items(), columns=["key", "value"])
        data.to_csv(result_path(f"{file}_{Config().device['name']}.csv"), index=False, escapechar="\\")

    return apps, app_infos, app_results, app_counts


def _should_ignore_detection(detection_result: dict) -> bool:
    """
    Filter out false positive results
    This code is unnecessary for new analyses but added for backwards compatibility with results that did not filter out these false positives
    :param detection_result: The detection result to check
    :return: True if the detection result should be ignored, False otherwise
    """
    if detection_result["analysis_type"] == "dynamic":
        return False

    pattern = detection_result["pattern"] if "pattern" in detection_result else ""
    source = detection_result["source"] if "source" in detection_result else ""

    if detection_result["detector"] == "hooking":
        lower_line_text = (
            detection_result["line"].lower() if "line" in detection_result else ""
        )
        fp = {
            "cydia": ["dial"],
            "frida": [
                "frida khalo",
                "sufrida",
                "sofrida",
                "profile_name",
                "alfrida",
                "ivett",
                "fritiof",
                "female",
                "feminine",
                "first_name",
                "giuffrida",
                "boy.",
                "girl.",
                "wilfrid",
            ],
            "xposed": ["axposed"],
        }

        if any(
            pattern in pattern and any(fp in lower_line_text for fp in fp[pattern])
            for pattern in fp.keys()
        ):
            return True

        if "frida" in pattern and (
            source.endswith(".json")
            or any(
                name in source.lower()
                for name in [
                    "firstname",
                    "lastname",
                    "first_name",
                    "last_name",
                    "/sv/",
                    "_sv",
                    "sv.lproj",
                ]
            )
        ):
            return True

        if "cydia" in pattern and source.endswith("taxonomy.csv"):
            return True

        if "taig.*://" in pattern and not "taig://" in source:
            return True

    elif detection_result["detector"] == "root":
        lower_line_text = (
            detection_result["line"].lower() if "line" in detection_result else ""
        )

        fp = {
            "kinguser": [
                "networkinguser",
                "bookinguser",
                "trackinguser",
                "cookinguser",
                "blockinguser",
                "rankinguser",
                "parkinguser",
                "linkinguser",
                "seekinguser",
                "talkinguser",
                "checkinguser",
                "markinguser",
                "likinguser",
                "speakinguser",
                "pickinguser",
                "lockinguser",
                "talkinguser",
                "takinguser",
                "bankinguser",
                "\\u2026kinguser",
            ],
            "bash": ["#!/bin/bash", "for example"],
            ".su": ["/wiki/.su"],
            "supersu": [
                "supersub",
                "supersuc",
                "supersud",
                "supersuf",
                "supersug",
                "supersuk",
                "supersul",
                "supersum",
                "supersun",
                "supersup",
                "supersur",
                "supersus",
                "supersut",
                "supersuv",
            ],
        }

        if any(
            pattern in pattern and any(fp in lower_line_text for fp in fp[pattern])
            for pattern in fp.keys()
        ):
            return True

        if "icy.*://" in pattern and "icy://" not in lower_line_text:
            return True

        if "bash" in pattern and not "bin/bash" in lower_line_text:
            return True

        if "\/sys\/kernel\/debug" in pattern:
            return True

        if (
            (")su(" in pattern or ")sudo(" in pattern)
            and not "bin/" in lower_line_text
            and "data/local/" not in lower_line_text
        ):
            return True

        if "magisk" in pattern and [
            danish in source
            for danish in ["/da/", "_da", "da.lproj", "ideas_info_config.json"]
        ]:
            return True

        if pattern == "superuser":
            return True

    elif detection_result["detector"] == "emulation":
        lower_line_text = (
            detection_result["line"].lower() if "line" in detection_result else ""
        )

        if "droid4x" in pattern and "android4x" in lower_line_text:
            return True

        if "robolectric" in pattern:
            return True

        if (
            "genymotion" in pattern
            and "running on emulator (or genymotion)" in lower_line_text
        ):
            return True

    elif (
        detection_result["detector"] == "pinning"
        and detection_result["type"] == "network_config"
        and detection_result["config_type"] == "nsc"
    ):
        return True

    return False


def _normalize(data: dict) -> dict:
    """
    Normalize a dictionary to be able to store it in a database by converting lists and dictionaries to JSON strings
    :param data: The dictionary to normalize
    :return: The normalized dictionary
    """
    # For each item, if it is a list or dict, json encode it
    for key in data.keys():
        if isinstance(data[key], dict) or isinstance(data[key], list):
            data[key] = json.dumps(data[key])
    return data


def _get_statistics() -> Tuple[pd.DataFrame, dict]:
    """
    Calculate statistics on the analyzed apps
    :return: List of analyzed apps and a dictionary containing the statistics
    """
    statistics_to_show = [
        "hardeningTechniques",
        "hardeningTechniquesApps",
        "hardeningTechniquesConsistency",
        "hardeningTechniquesDelta",
        "hardeningTechniquesPerCategory",
        "hardeningTechniquesPerPermission",
        "hardeningTechniquesPerPermissionCount",
        "permissionsDiff",
        "jailbreaks",
        "hookingFrameworks",
        "plaintextTraffic",
        "plaintextTrafficType",
        "tlsCipher",
        "hardeningTechniquesLibraries",
        "hardeningTechniquesLibrariesNoCommon",
        "libraries",
    ]

    hardening_techniques = {
        "debug": "Anti-debug",
        "tamper": "Anti-tampering",
        "hooking": "Hooking detection",
        "emulation": "Emulation detection",
        "root": "Root and jailbreak detection",
        "keylogger": "Keylogger protection",
        "screenreader": "Screenreader protection",
        "pinning": "Certificate pinning",
    }
    i_techs = list(hardening_techniques.keys())
    l_techs = list(hardening_techniques.values())
    n_techs = len(hardening_techniques)

    # Get app analysis results
    (apps, app_infos, app_results, statistics) = _get_apps_results()

    print("Calculating statistics...")
    progress = tqdm(range(len(statistics_to_show)))

    ###################################
    # Hardening techniques prevalence #
    ###################################
    if "hardeningTechniques" in statistics_to_show:
        statistics["hardeningTechniques"] = {
            "title": "Hardening techniques prevalence",
            "labels": l_techs,
            "values": {
                "androidStatic": [0] * n_techs,
                "androidStatic?": [0] * n_techs,
                "androidDynamic": [0] * n_techs,
                "androidDynamic?": [0] * n_techs,
                "iosStatic": [0] * n_techs,
                "iosStatic?": [0] * n_techs,
                "iosDynamic": [0] * n_techs,
                "iosDynamic?": [0] * n_techs,
            },
        }

        apps_inner_query = """
            (SELECT detector, analysis_type, os, app_id, CASE WHEN SUM(confident) > 0 THEN 1 ELSE 0 END AS confident
            FROM app_results
            GROUP BY detector, analysis_type, os, app_id) app_unique_results
        """
        query_results = psql(
            """
            SELECT detector, analysis_type, os, confident, COUNT(DISTINCT app_id) AS count
            FROM """
            + apps_inner_query
            + """
            GROUP BY detector, analysis_type, os, confident
            """,
            locals(),
        )
        for _, result in query_results.iterrows():
            if result["detector"] in hardening_techniques:
                key = f'{result["os"]}{result["analysis_type"].capitalize()}'
                if result["confident"] == 0:
                    key += "?"
                statistics["hardeningTechniques"]["values"][key][
                    i_techs.index(result["detector"])
                ] = result["count"]

        progress.n += 1
        progress.refresh()

    ###################################
    # Hardening techniques apps #
    ###################################
    if "hardeningTechniquesApps" in statistics_to_show:
        statistics["hardeningTechniquesApps"] = {
            "title": "CDF of hardening techniques in apps",
            "values": {"android": [], "ios": []},
        }

        query_results = psql(
            """
            SELECT app_infos.os, 
            CASE WHEN app_hardening_count IS NULL THEN 0 ELSE app_hardening_count END AS hardening_count, 
            COUNT(DISTINCT app_infos.app_id) app_count 
            FROM app_infos 
            LEFT JOIN (
                SELECT app_id, os, COUNT(DISTINCT detector) AS app_hardening_count 
                FROM app_results 
                WHERE detector != 'svc' AND detector != 'connection' AND detector != 'screenreader' 
                AND confident = 1 
                GROUP BY app_id, OS
            ) hardening 
            ON hardening.os = app_infos.os AND hardening.app_id = app_infos.app_id 
            WHERE analysis_type = 'static' 
            GROUP BY app_infos.os, app_hardening_count
            ORDER BY app_infos.os, hardening_count ASC; 
            """,
            locals(),
        )
        cum_sum = {"android": 0, "ios": 0}
        for _, result in query_results.iterrows():
            cum_sum[result["os"]] += result["app_count"]
            pct = round(cum_sum[result["os"]] / statistics["totalAnalyzed"] * 100, 1)
            for x in [
                result["hardening_count"],
                min(result["hardening_count"] + 1, n_techs - 1),
            ]:
                statistics["hardeningTechniquesApps"]["values"][result["os"]].append(
                    {"x": x, "y": pct}
                )

        progress.n += 1
        progress.refresh()

    ####################################
    # Hardening techniques consistency #
    ####################################
    if "hardeningTechniquesConsistency" in statistics_to_show:
        statistics["hardeningTechniquesConsistency"] = {
            "title": "Hardening techniques consistency",
            "labels": l_techs,
            "values": {
                "neither": [0] * n_techs,
                "androidOnly": [0] * n_techs,
                "iosOnly": [0] * n_techs,
                "both": [0] * n_techs,
            },
        }

        ios_inner_query = """
            (SELECT detector, app_id, 1 AS detected_ios
            FROM app_results
            WHERE confident = 1
            AND os = 'ios'
            GROUP BY detector, app_id) ios_results
        """
        android_inner_query = """
            (SELECT detector, app_id, 1 AS detected_android
            FROM app_results
            WHERE confident = 1
            AND os = 'android'
            GROUP BY detector, app_id) android_results
        """
        techniques_inner_query = """
            (SELECT DISTINCT detector FROM app_results WHERE detector != 'svc' AND detector != 'connection') techniques
        """
        query_results = psql(
            """
            SELECT techniques.detector, ios_results.detected_ios, android_results.detected_android, COUNT(*) AS app_count FROM apps
            CROSS JOIN """
            + techniques_inner_query
            + """
            LEFT JOIN """
            + ios_inner_query
            + """ ON apps.ios_bundle_id = ios_results.app_id AND ios_results.detector = techniques.detector
            LEFT JOIN """
            + android_inner_query
            + """ ON apps.android_id = android_results.app_id AND android_results.detector = techniques.detector
            GROUP BY techniques.detector, ios_results.detected_ios, android_results.detected_android
        """,
            locals(),
        ).fillna(0)

        for _, result in query_results.iterrows():
            if result["detector"] not in hardening_techniques:
                continue

            key = "neither"
            if result["detected_ios"] == 1 and result["detected_android"] == 1:
                key = "both"
            elif result["detected_ios"] == 1:
                key = "iosOnly"
            elif result["detected_android"] == 1:
                key = "androidOnly"

            statistics["hardeningTechniquesConsistency"]["values"][key][
                i_techs.index(result["detector"])
            ] = result["app_count"]

        progress.n += 1
        progress.refresh()

    ##############################
    # Hardening techniques delta #
    ##############################
    if "hardeningTechniquesDelta" in statistics_to_show:
        ios_inner_query = """
            (SELECT detector, app_id, 1 AS detected_ios
            FROM app_results
            WHERE confident = 1
            AND os = 'ios'
            GROUP BY detector, app_id) ios_results
        """
        android_inner_query = """
            (SELECT detector, app_id, 1 AS detected_android
            FROM app_results
            WHERE confident = 1
            AND os = 'android'
            GROUP BY detector, app_id) android_results
        """
        techniques_inner_query = """
            (SELECT DISTINCT detector FROM app_results WHERE detector != 'screenreader' AND detector != 'svc' AND detector != 'connection') techniques
        """
        different_inner_query = (
            """
            (SELECT apps.android_id,
            SUM(CASE WHEN (ios_results.detected_ios = 1 AND android_results.detected_android IS NULL) OR (ios_results.detected_ios IS NULL AND android_results.detected_android = 1) THEN 1 ELSE 0 END) AS different
            FROM apps
            CROSS JOIN """
            + techniques_inner_query
            + """
            LEFT JOIN """
            + ios_inner_query
            + """ ON apps.ios_bundle_id = ios_results.app_id AND ios_results.detector = techniques.detector
            LEFT JOIN """
            + android_inner_query
            + """ ON apps.android_id = android_results.app_id AND android_results.detector = techniques.detector
            GROUP BY apps.android_id) diff_results
        """
        )

        query_results = psql(
            """
            SELECT different, COUNT(*) AS app_count
            FROM """
            + different_inner_query
            + """
            GROUP BY different
        """,
            locals(),
        ).fillna(0)

        statistics["hardeningTechniquesDelta"] = {
            "title": "Difference in implemented hardening techniques",
            "labels": [str(i) for i in range(n_techs + 1)],
            "values": [0] * (n_techs + 1),
        }

        for _, result in query_results.iterrows():
            statistics["hardeningTechniquesDelta"]["values"][
                int(result["different"])
            ] = int(result["app_count"])

        progress.n += 1
        progress.refresh()

    ###########################
    # Statistics per category #
    ###########################
    if "hardeningTechniquesPerCategory" in statistics_to_show:
        categories = psql(
            """SELECT DISTINCT android_category FROM apps ORDER BY android_category""", locals()
        )["android_category"].tolist()
        
        statistics["hardeningTechniquesPerCategory"] = {
            "title": "Average number of hardening techniques per category",
            "labels": categories,
            "values": {
                "android": [0] * len(categories),
                "ios": [0] * len(categories),
            },
        }

        ios_inner_query = """
            (SELECT app_id, COUNT(DISTINCT detector) AS detected_ios
            FROM app_results
            WHERE confident = 1
            AND os = 'ios'
            GROUP BY app_id) ios_results
        """
        android_inner_query = """
            (SELECT app_id, COUNT(DISTINCT detector) AS detected_android
            FROM app_results
            WHERE confident = 1
            AND os = 'android'
            GROUP BY app_id) android_results
        """
        query_results = psql(
            """
            SELECT apps.android_category, AVG(ios_results.detected_ios) AS detected_ios, AVG(android_results.detected_android) AS detected_android FROM apps
            LEFT JOIN """
            + ios_inner_query
            + """ ON apps.ios_bundle_id = ios_results.app_id
            LEFT JOIN """
            + android_inner_query
            + """ ON apps.android_id = android_results.app_id
            GROUP BY apps.android_category
        """,
            locals(),
        ).fillna(0)

        for _, result in query_results.iterrows():
            for os in ["android", "ios"]:
                statistics["hardeningTechniquesPerCategory"]["values"][os][
                    categories.index(result["android_category"])
                ] = result[f"detected_{os}"]

        # Sort labels, android values and ios values by descending order of the android values
        (
            statistics["hardeningTechniquesPerCategory"]["labels"],
            statistics["hardeningTechniquesPerCategory"]["values"]["android"],
            statistics["hardeningTechniquesPerCategory"]["values"]["ios"],
        ) = zip(
            *sorted(
                zip(
                    statistics["hardeningTechniquesPerCategory"]["labels"],
                    statistics["hardeningTechniquesPerCategory"]["values"]["android"],
                    statistics["hardeningTechniquesPerCategory"]["values"]["ios"],
                ),
                key=lambda x: x[1],
                reverse=True,
            )
        )

        progress.n += 1
        progress.refresh()

    ##############################
    # Statistics per permissions #
    ##############################
    if "hardeningTechniquesPerPermission" in statistics_to_show:
        permissions = {
            "Calendar": [
                "android.permission.READ_CALENDAR",
                "android.permission.WRITE_CALENDAR",
                "NSCalendarsUsageDescription",
                "NSRemindersUsageDescription",
            ],
            "Camera": ["android.permission.CAMERA", "NSCameraUsageDescription"],
            "Contacts": [
                "android.permission.READ_CONTACTS",
                "android.permission.WRITE_CONTACTS",
                "NSContactsUsageDescription",
            ],
            "Location": [
                "android.permission.ACCESS_COARSE_LOCATION",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_BACKGROUND_LOCATION",
                "android.permission.ACCESS_MEDIA_LOCATION",
                "NSLocationAlwaysAndWhenInUseUsageDescription",
                "NSLocationUsageDescription",
                "NSLocationWhenInUseUsageDescription",
                "NSLocationTemporaryUsageDescriptionDictionary",
                "NSLocationAlwaysUsageDescription",
                "NSWidgetWantsLocation",
                "NSLocationDefaultAccuracyReduced",
            ],
            "Microphone": [
                "android.permission.RECORD_AUDIO",
                "NSMicrophoneUsageDescription",
            ],
            "Health sensors": [
                "android.permission.BODY_SENSORS",
                "android.permission.ACTIVITY_RECOGNITION",
                "NSHealthUpdateUsageDescription",
                "NSHealthShareUsageDescription",
                "NSHealthClinicalHealthRecordsShareUsageDescription",
                "NSHealthRequiredReadAuthorizationTypeIdentifiers",
            ],
            "Storage": [
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.MANAGE_EXTERNAL_STORAGE",
                "NSPhotoLibraryAddUsageDescription",
                "NSPhotoLibraryUsageDescription",
                "NSAppleMusicUsageDescription",
            ],
            "HomeKit": ["NSHomeKitUsageDescription"],
            "None": [],
        }

        statistics["hardeningTechniquesPerPermission"] = {
            "title": "Average number of hardening techniques depending on permissions",
            "labels": list(permissions.keys()),
            "values": {
                "android": [0] * len(permissions),
                "ios": [0] * len(permissions),
            },
        }

        results_inner_query = """
            (SELECT app_id, os, COUNT(DISTINCT detector) AS techniques_detected
            FROM app_results
            WHERE confident = 1
            GROUP BY os, app_id) results
        """

        permission_names = pd.DataFrame(permissions.keys(), columns=["permission_name"])
        all_permissions = [item for sublist in permissions.values() for item in sublist]
        permissions_select = "CASE "
        for permission, permission_keys in permissions.items():
            if len(permission_keys) > 0:
                permissions_select += (
                    'WHEN permission_names.permission_name = "'
                    + permission
                    + '" AND ('
                    + " OR ".join(
                        f"app_infos.permissions LIKE '%{key}%'"
                        for key in permission_keys
                    )
                    + f") THEN 1 \n"
                )
            else:
                # When none of the permissions above is set
                permissions_select += (
                    'WHEN permission_names.permission_name = "'
                    + permission
                    + '" AND ('
                    + " AND ".join(
                        f"app_infos.permissions NOT LIKE '%{key}%'"
                        for key in all_permissions
                    )
                    + f") THEN 1 \n"
                )
        permissions_select += " ELSE 0 END AS " + "permission_set"

        query_results = psql(
            """
            SELECT 
            app_infos.os,
            AVG(results.techniques_detected) AS techniques_detected,
            permission_names.permission_name,
            """
            + permissions_select
            + """
            FROM app_infos
            CROSS JOIN permission_names
            LEFT JOIN """
            + results_inner_query
            + """ ON app_infos.app_id = results.app_id AND results.os = app_infos.os
            WHERE app_infos.analysis_type = 'static'
            AND permission_set = 1
            GROUP BY app_infos.os, permission_names.permission_name, permission_set
        """,
            locals(),
        ).fillna(0)
        for _, result in query_results.iterrows():
            print(list(permissions.keys()).index(result["permission_name"]))
            print(result)
            print(result["techniques_detected"])
            print(statistics["hardeningTechniquesPerPermission"]["values"])
            statistics["hardeningTechniquesPerPermission"]["values"][result["os"]][
                list(permissions.keys()).index(result["permission_name"])
            ] = result["techniques_detected"]

        # Sort labels, android values and ios values by descending order of the android values
        (
            statistics["hardeningTechniquesPerPermission"]["labels"],
            statistics["hardeningTechniquesPerPermission"]["values"]["android"],
        ) = [
            list(item)
            for item in zip(
                *sorted(
                    zip(
                        statistics["hardeningTechniquesPerPermission"]["labels"],
                        statistics["hardeningTechniquesPerPermission"]["values"][
                            "android"
                        ],
                    ),
                    key=lambda x: x[1],
                    reverse=True,
                )
            )
        ]

        # Move the 'None' category to the end
        index = statistics["hardeningTechniquesPerPermission"]["labels"].index("None")
        statistics["hardeningTechniquesPerPermission"]["labels"].append(
            statistics["hardeningTechniquesPerPermission"]["labels"].pop(index)
        )
        statistics["hardeningTechniquesPerPermission"]["values"]["android"].append(
            statistics["hardeningTechniquesPerPermission"]["values"]["android"].pop(
                index
            )
        )
        statistics["hardeningTechniquesPerPermission"]["values"]["ios"].append(
            statistics["hardeningTechniquesPerPermission"]["values"]["ios"].pop(index)
        )

        progress.n += 1
        progress.refresh()

    ########################################
    # Statistics per number of permissions #
    ########################################
    if "hardeningTechniquesPerPermissionCount" in statistics_to_show:
        permissions = {
            "Calendar": [
                "android.permission.READ_CALENDAR",
                "android.permission.WRITE_CALENDAR",
                "NSCalendarsUsageDescription",
                "NSRemindersUsageDescription",
            ],
            "Camera": ["android.permission.CAMERA", "NSCameraUsageDescription"],
            "Contacts": [
                "android.permission.READ_CONTACTS",
                "android.permission.WRITE_CONTACTS",
                "NSContactsUsageDescription",
            ],
            "Location": [
                "android.permission.ACCESS_COARSE_LOCATION",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_BACKGROUND_LOCATION",
                "android.permission.ACCESS_MEDIA_LOCATION",
                "NSLocationAlwaysAndWhenInUseUsageDescription",
                "NSLocationUsageDescription",
                "NSLocationWhenInUseUsageDescription",
                "NSLocationTemporaryUsageDescriptionDictionary",
                "NSLocationAlwaysUsageDescription",
                "NSWidgetWantsLocation",
                "NSLocationDefaultAccuracyReduced",
            ],
            "Microphone": [
                "android.permission.RECORD_AUDIO",
                "NSMicrophoneUsageDescription",
            ],
            "Health sensors": [
                "android.permission.BODY_SENSORS",
                "android.permission.ACTIVITY_RECOGNITION",
                "NSHealthUpdateUsageDescription",
                "NSHealthShareUsageDescription",
                "NSHealthClinicalHealthRecordsShareUsageDescription",
                "NSHealthRequiredReadAuthorizationTypeIdentifiers",
            ],
            "Storage": [
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.MANAGE_EXTERNAL_STORAGE",
                "NSPhotoLibraryAddUsageDescription",
                "NSPhotoLibraryUsageDescription",
                "NSAppleMusicUsageDescription",
            ],
            "HomeKit": ["NSHomeKitUsageDescription"],
        }

        statistics["hardeningTechniquesPerPermissionCount"] = {
            "title": "Average number of hardening techniques depending on number of privacy-sensitive permissions",
            "labels": list(range(len(permissions.keys()) + 1)),
            "values": {
                "android": [0] * (len(permissions.keys()) + 1),
                "ios": [0] * (len(permissions.keys()) + 1),
            },
        }

        results_inner_query = """
            (SELECT app_id, os, COUNT(DISTINCT detector) AS techniques_detected
            FROM app_results
            WHERE confident = 1
            GROUP BY os, app_id) results
        """

        permission_names = pd.DataFrame(permissions.keys(), columns=["permission_name"])
        all_permissions = [item for sublist in permissions.values() for item in sublist]
        permissions_select = "SUM(CASE "
        for permission, permission_keys in permissions.items():
            if len(permission_keys) > 0:
                permissions_select += (
                    'WHEN permission_names.permission_name = "'
                    + permission
                    + '" AND ('
                    + " OR ".join(
                        f"app_infos.permissions LIKE '%{key}%'"
                        for key in permission_keys
                    )
                    + f") THEN 1 \n"
                )
            else:
                # When none of the permissions above is set
                permissions_select += (
                    'WHEN permission_names.permission_name = "'
                    + permission
                    + '" AND ('
                    + " AND ".join(
                        f"app_infos.permissions NOT LIKE '%{key}%'"
                        for key in all_permissions
                    )
                    + f") THEN 1 \n"
                )
        permissions_select += " ELSE 0 END) AS " + "permission_count"

        inner_query = (
            """
            (SELECT 
            app_infos.os,
            app_infos.app_id,
            results.techniques_detected,
            """
            + permissions_select
            + """
            FROM app_infos
            CROSS JOIN permission_names
            LEFT JOIN """
            + results_inner_query
            + """ ON app_infos.app_id = results.app_id AND results.os = app_infos.os
            WHERE app_infos.analysis_type = 'static'
            GROUP BY app_infos.os, app_infos.app_id, results.techniques_detected
            ) AS permission_counts
        """
        )

        query_results = psql(
            """
            SELECT 
            permission_counts.os,
            AVG(permission_counts.techniques_detected) AS techniques_detected,
            permission_counts.permission_count
            FROM """
            + inner_query
            + """
            GROUP BY permission_counts.os, permission_counts.permission_count
        """,
            locals(),
        ).fillna(0)

        for _, result in query_results.iterrows():
            statistics["hardeningTechniquesPerPermissionCount"]["values"][result["os"]][
                result["permission_count"]
            ] = result["techniques_detected"]

        if all(
            statistics["hardeningTechniquesPerPermissionCount"]["values"][os][-1] == 0
            for os in ["android", "ios"]
        ):
            statistics["hardeningTechniquesPerPermissionCount"]["labels"].pop()
            for os in ["android", "ios"]:
                statistics["hardeningTechniquesPerPermissionCount"]["values"][os].pop()

    #########################################
    # Difference in permissions across OSes #
    #########################################
    if "permissionsDiff" in statistics_to_show:
        permissions = {
            "Calendar": [
                "android.permission.READ_CALENDAR",
                "android.permission.WRITE_CALENDAR",
                "NSCalendarsUsageDescription",
                "NSRemindersUsageDescription",
            ],
            "Camera": ["android.permission.CAMERA", "NSCameraUsageDescription"],
            "Contacts": [
                "android.permission.READ_CONTACTS",
                "android.permission.WRITE_CONTACTS",
                "NSContactsUsageDescription",
            ],
            "Location": [
                "android.permission.ACCESS_COARSE_LOCATION",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_BACKGROUND_LOCATION",
                "android.permission.ACCESS_MEDIA_LOCATION",
                "NSLocationAlwaysAndWhenInUseUsageDescription",
                "NSLocationUsageDescription",
                "NSLocationWhenInUseUsageDescription",
                "NSLocationTemporaryUsageDescriptionDictionary",
                "NSLocationAlwaysUsageDescription",
                "NSWidgetWantsLocation",
                "NSLocationDefaultAccuracyReduced",
            ],
            "Microphone": [
                "android.permission.RECORD_AUDIO",
                "NSMicrophoneUsageDescription",
            ],
            "Health sensors": [
                "android.permission.BODY_SENSORS",
                "android.permission.ACTIVITY_RECOGNITION",
                "NSHealthUpdateUsageDescription",
                "NSHealthShareUsageDescription",
                "NSHealthClinicalHealthRecordsShareUsageDescription",
                "NSHealthRequiredReadAuthorizationTypeIdentifiers",
            ],
            "Storage": [
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.MANAGE_EXTERNAL_STORAGE",
                "NSPhotoLibraryAddUsageDescription",
                "NSPhotoLibraryUsageDescription",
                "NSAppleMusicUsageDescription",
            ],
            "HomeKit": ["NSHomeKitUsageDescription"],
            "None": [],
        }

        permission_names = pd.DataFrame(permissions.keys(), columns=["permission_name"])
        all_permissions = [item for sublist in permissions.values() for item in sublist]
        permissions_select = "CASE "
        for permission, permission_keys in permissions.items():
            if len(permission_keys) > 0:
                permissions_select += (
                    'WHEN permission_names.permission_name = "'
                    + permission
                    + '" AND ('
                    + " OR ".join(
                        f"app_infos.permissions LIKE '%{key}%'"
                        for key in permission_keys
                    )
                    + f") THEN 1 \n"
                )
            else:
                # When none of the permissions above is set
                permissions_select += (
                    'WHEN permission_names.permission_name = "'
                    + permission
                    + '" AND ('
                    + " AND ".join(
                        f"app_infos.permissions NOT LIKE '%{key}%'"
                        for key in all_permissions
                    )
                    + f") THEN 1 \n"
                )
        permissions_select += " ELSE 0 END AS " + "permission_set"
        app_permissions_query = (
            """
            (SELECT
            app_infos.os,
            apps.android_id AS app_id,
            permission_names.permission_name,
            """
            + permissions_select
            + """
            FROM app_infos
            LEFT JOIN apps ON (app_infos.os = 'android' AND apps.android_id = app_infos.app_id) OR (app_infos.os = 'ios' AND apps.ios_bundle_id = app_infos.app_id)
            CROSS JOIN permission_names
            WHERE app_infos.analysis_type = 'static'
            AND permission_set = 1
            AND permission_name != 'HomeKit'
            AND permission_name != 'None') app_permissions
        """
        )

        app_permissions_diff_query = (
            """
            (SELECT app_id,
            permission_name,
            CASE WHEN SUM(permission_set) = 1 THEN 1 ELSE 0 END AS perm_different
            FROM """
            + app_permissions_query
            + """
            GROUP BY app_id, permission_name, permission_set) app_permissions_diff
        """
        )

        permissions_diff_query = (
            """
            (SELECT app_id, SUM(perm_different) AS different
            FROM """
            + app_permissions_diff_query
            + """
            GROUP BY app_id) permissions_diff
        """
        )

        query_results = psql(
            """
            SELECT different, COUNT(*) AS app_count
            FROM """
            + permissions_diff_query
            + """
            GROUP BY different
        """,
            locals(),
        ).fillna(0)

        statistics["permissionsDiff"] = {
            "title": "Difference in used privacy-sensitive permissions",
            "labels": [str(i) for i in range(len(permissions) - 1)],
            "values": [0] * (len(permissions) - 1),
        }

        for _, result in query_results.iterrows():
            statistics["permissionsDiff"]["values"][int(result["different"])] = int(
                result["app_count"]
            )

        progress.n += 1
        progress.refresh()

    #####################################
    # Detection of different jailbreaks #
    #####################################
    if "jailbreaks" in statistics_to_show:
        jailbreaks = {
            "palera1n (iOS 15-16)": ["palera1n", "palecursus"],
            "Cheyote (iOS 15)": ["cheyote"],
            "XinaA15 (iOS 15)": ["xina15"],
            "Fugu (iOS 14-15)": ["fugu14", "fugu15"],
            "Taurine (iOS 14)": ["taurine"],
            "Odyssey (iOS 13)": ["odyssey"],
            "Chimera (iOS 12)": ["chimera"],
            "unc0ver (iOS 11-14)": ["unc0ver", "undecimus"],
            "Electra (iOS 11)": ["electra"],
            "LiberiOS (iOS 11)": ["liberios"],
            "checkra1n (iOS 10-14)": ["checkra1n"],
            "PPJailbreak (iOS 8, 10)": ["ppjailbreak"],
            "TaiG (iOS 8)": ["taig"],
            "Pangu (iOS 7-9)": ["pangu"],
            "evasi0n (iOS 6-7)": ["evasi0n"],
            "redsn0w (iOS 3-5)": ["redsn0w"],
            "limera1n (iOS 3-4)": ["limera1n"],
            "greenpois0n (iOS 3)": ["greenpois0n"],
            "blackra1n (iOS 3)": ["blackra1n", "blacksn0w"],
        }
        query_results = psql(
            """
            SELECT DISTINCT app_id, pattern FROM app_results
            WHERE pattern IS NOT NULL
            AND detector = 'root'
            AND analysis_type = 'static'
            AND os = 'ios'
            ORDER BY app_id
        """,
            locals(),
        )

        statistics["jailbreaks"] = {
            "title": "Detected jaibreaks",
            "labels": list(jailbreaks.keys()),
            "values": [],
        }

        for _, jailbreak_keywords in jailbreaks.items():
            number_of_apps = 0
            last_app_id = None
            for _, result in query_results.iterrows():
                if last_app_id == result["app_id"]:
                    continue

                if any(keyword in result["pattern"] for keyword in jailbreak_keywords):
                    number_of_apps += 1
                    last_app_id = result["app_id"]

            statistics["jailbreaks"]["values"].append(number_of_apps)

        progress.n += 1
        progress.refresh()

    #############################################
    # Detection of different hooking frameworks #
    #############################################
    if "hookingFrameworks" in statistics_to_show:
        hooking_frameworks = {
            "Frida": ["frida"],
            "Cydia Substrate": ["cydia", "substrate", "tweakinject"],
            "Xposed": ["xposed", "edxp"],
            "Riru": ["riru"],
            "Zygisk": ["zygisk"],
        }
        query_results = psql(
            """
            SELECT DISTINCT app_id, os, analysis_type, pattern, file FROM app_results
            WHERE (pattern IS NOT NULL OR file IS NOT NULL)
            AND detector = 'hooking'
            ORDER BY app_id, os, analysis_type
        """,
            locals(),
        ).fillna("")

        statistics["hookingFrameworks"] = {
            "title": "Detected hooking frameworks",
            "labels": list(hooking_frameworks.keys()),
            "values": {
                "androidStatic": [],
                "androidDynamic": [],
                "iosStatic": [],
                "iosDynamic": [],
            },
        }

        for _, framework_keywords in hooking_frameworks.items():
            number_of_apps = {
                "androidStatic": 0,
                "androidDynamic": 0,
                "iosStatic": 0,
                "iosDynamic": 0,
            }
            last_app_id = None
            last_app_os = None
            last_analysis_type = None
            for _, result in query_results.iterrows():
                if (
                    last_app_id == result["app_id"]
                    and last_app_os == result["os"]
                    and last_analysis_type == result["analysis_type"]
                ):
                    continue

                if any(
                    any(keyword in result[key].lower() for key in ["pattern", "file"])
                    for keyword in framework_keywords
                ):
                    number_of_apps[
                        f'{result["os"]}{result["analysis_type"].capitalize()}'
                    ] += 1
                    last_app_id = result["app_id"]
                    last_app_os = result["os"]
                    last_analysis_type = result["analysis_type"]

            for os in ["android", "ios"]:
                for analysis_type in ["static", "dynamic"]:
                    key = f"{os}{analysis_type.capitalize()}"
                    statistics["hookingFrameworks"]["values"][key].append(
                        number_of_apps[key]
                    )

        progress.n += 1
        progress.refresh()

    ##################################
    # Detection of plaintext traffic #
    ##################################
    if "plaintextTraffic" in statistics_to_show:
        query_results = psql(
            """
            SELECT DISTINCT app_id, os FROM app_results
            WHERE type = 'plain_http' 
            AND detector = 'connection'
            ORDER BY app_id, os
        """,
            locals(),
        ).fillna("")

        statistics["plaintextTraffic"] = {
            "title": "Detected plaintext traffic",
            "labels": ["Android", "iOS", "Android no OCSP", "iOS no OCSP"],
            "values": [0, 0, 0, 0],
        }

        for _, result in query_results.iterrows():
            statistics["plaintextTraffic"]["values"][
                0 if result["os"] == "android" else 1
            ] += 1

        query_results = psql(
            """
            SELECT DISTINCT app_id, os FROM app_results
            WHERE type = 'plain_http' 
            AND detector = 'connection'
            AND data IS NOT NULL
            AND data NOT LIKE '%ocsp%'
            AND data NOT LIKE '%o.lencr.org%'
            ORDER BY app_id, os
        """,
            locals(),
        ).fillna("")

        for _, result in query_results.iterrows():
            statistics["plaintextTraffic"]["values"][
                2 if result["os"] == "android" else 3
            ] += 1

        progress.n += 1
        progress.refresh()

    #############################
    # Type of plaintext traffic #
    #############################
    if "plaintextTrafficType" in statistics_to_show and "data" in app_results:
        query_results = psql(
            """
            SELECT DISTINCT app_id, os, data FROM app_results
            WHERE type = 'plain_http' 
            AND detector = 'connection'
            ORDER BY data, app_id, os
        """,
            locals(),
        ).fillna("")

        statistics["plaintextTrafficType"] = {
            "title": "Type of detected plaintext traffic",
            "labels": [
                "OCSP",
                "Images",
                "Archives",
                "Web resources",
                "Fonts",
                "API",
                "Local IP",
                "Other",
            ],
            "values": [0, 0, 0, 0, 0, 0, 0, 0],
        }

        for _, result in query_results.iterrows():
            request = ""
            if "data" in app_results:
                request = result["data"]
            if "ocsp" in request or "o.lencr.org" in request:
                statistics["plaintextTrafficType"]["values"][0] += 1
            elif any(
                image_ext + " HTTP" in request or image_ext + "?" in request
                for image_ext in [
                    ".png",
                    ".jpg",
                    ".jpeg",
                    ".gif",
                    ".webp",
                    ".bmp",
                    ".svg",
                ]
            ):
                statistics["plaintextTrafficType"]["values"][1] += 1
            elif any(
                archive_ext + " HTTP" in request or archive_ext + "?" in request
                for archive_ext in [
                    ".zip",
                    ".rar",
                    ".tar",
                    ".tar.gz",
                    ".tar.bz2",
                    ".tar.xz",
                    ".7z",
                    ".tz",
                ]
            ):
                statistics["plaintextTrafficType"]["values"][2] += 1
            elif any(
                web_ext + " HTTP" in request or web_ext + "?" in request
                for web_ext in [".js", ".css"]
            ):
                statistics["plaintextTrafficType"]["values"][3] += 1
            elif any(
                web_ext + " HTTP" in request or web_ext + "?" in request
                for web_ext in [".otf", ".ttf", ".woff", ".woff2"]
            ):
                statistics["plaintextTrafficType"]["values"][4] += 1
            elif any(
                api_query in request
                for api_query in [
                    ".json HTTP",
                    ".json?",
                    "/v1/",
                    "api",
                    ".xml HTTP",
                    ".xml?",
                    "itunes.apple.com",
                ]
            ):
                statistics["plaintextTrafficType"]["values"][5] += 1
            elif any(
                local in request
                for local in ["http://localhost/", "http://192.168.", "http://10."]
            ):
                statistics["plaintextTrafficType"]["values"][6] += 1
            else:
                statistics["plaintextTrafficType"]["values"][7] += 1

        progress.n += 1
        progress.refresh()

    ############################
    # Detection of TLS ciphers #
    ############################
    if "tlsCipher" in statistics_to_show and "data" in app_results:
        query_results = psql(
            """
            SELECT DISTINCT data, os, COUNT(*) AS count FROM app_results
            WHERE type = 'tls_conn'
            AND detector = 'connection'
            GROUP BY data, os
            ORDER BY data, os
        """,
            locals(),
        ).fillna("")

        ciphers = {}

        for _, result in query_results.iterrows():
            if "data" in result:
                info = json.loads(result["data"])
            else:
                continue
            cipher = info["cipher"]
            tls_version = info["version"]
            key = cipher + " (" + tls_version + ")"
            if key not in ciphers:
                ciphers[key] = {}
            ciphers[key][result["os"]] = result["count"]

        statistics["tlsCipher"] = {
            "title": "Detected TLS ciphers",
            "labels": list(ciphers.keys()),
            "values": {
                "android": [
                    count["android"] if "android" in count else 0
                    for count in ciphers.values()
                ],
                "ios": [
                    count["ios"] if "ios" in count else 0 for count in ciphers.values()
                ],
            },
        }

        progress.n += 1
        progress.refresh()

    ######################################################################
    # Hardening technique prevalence in first- and third-party libraries #
    ######################################################################
    if "hardeningTechniquesLibraries" in statistics_to_show:
        query_results = psql(
            """
            SELECT detector, os, library, COUNT(DISTINCT app_id) AS app_count FROM
            (SELECT DISTINCT app_id, detector, os, (CASE WHEN library IS NULL THEN 'FirstParty' ELSE 'ThirdParty' END) AS library FROM app_results WHERE confident = 1) first_third_party
            GROUP BY detector, os, library;
        """,
            locals(),
        )

        statistics["hardeningTechniquesLibraries"] = {
            "title": "Hardening technique prevalence in first- and third-party libraries",
            "labels": l_techs,
            "values": {
                "androidFirstParty": [0] * n_techs,
                "androidThirdParty": [0] * n_techs,
                "iosFirstParty": [0] * n_techs,
                "iosThirdParty": [0] * n_techs,
            },
        }

        for _, result in query_results.iterrows():
            if result["detector"] not in i_techs:
                continue

            statistics["hardeningTechniquesLibraries"]["values"][
                result["os"] + result["library"]
            ][i_techs.index(result["detector"])] = result["app_count"]

        progress.n += 1
        progress.refresh()

    ###############################################################################################
    # Hardening technique prevalence in first- and third-party libraries without common libraries #
    ###############################################################################################
    if "hardeningTechniquesLibrariesNoCommon" in statistics_to_show:
        query_results = psql(
            """
            SELECT detector, os, library, COUNT(DISTINCT app_id) AS app_count FROM
            (
                SELECT DISTINCT app_id, detector, os, (CASE WHEN library IS NULL THEN 'FirstParty' ELSE 'ThirdParty' END) AS library 
                FROM app_results 
                WHERE confident = 1
                AND (library IS NULL OR library NOT IN ('com.google.android.gms', 'com.google.firebase', 'com.appsflyer'))
            ) first_third_party
            GROUP BY detector, os, library;
        """,
            locals(),
        )

        statistics["hardeningTechniquesLibrariesNoCommon"] = {
            "title": "Hardening technique prevalence in first- and third-party libraries without GMS, Firebase, AppsFlyer",
            "labels": l_techs,
            "values": {
                "androidFirstParty": [0] * n_techs,
                "androidThirdParty": [0] * n_techs,
                "iosFirstParty": [0] * n_techs,
                "iosThirdParty": [0] * n_techs,
            },
        }

        for _, result in query_results.iterrows():
            if result["detector"] not in i_techs:
                continue

            statistics["hardeningTechniquesLibrariesNoCommon"]["values"][
                result["os"] + result["library"]
            ][i_techs.index(result["detector"])] = result["app_count"]

        progress.n += 1
        progress.refresh()

    #################################################
    # Detection of hardening techiques in libraries #
    #################################################
    if "libraries" in statistics_to_show:
        query_results = psql(
            """
            SELECT DISTINCT os, analysis_type, detector, library, COUNT(DISTINCT app_id) AS app_count
            FROM app_results
            WHERE confident = 1
            GROUP BY analysis_type, detector, os, library
            HAVING app_count > 1
            ORDER BY os, detector, analysis_type DESC, app_count DESC;
        """,
            locals(),
        ).fillna("App-specific")

        # Structure as {os: {detector: {analysis_type: [{rest of data}]}
        statistics["libraries"] = {}
        for _, result in query_results.iterrows():
            if result["os"] not in statistics["libraries"]:
                statistics["libraries"][result["os"]] = {}
            if result["detector"] not in statistics["libraries"][result["os"]]:
                statistics["libraries"][result["os"]][result["detector"]] = {}
            if (
                result["analysis_type"]
                not in statistics["libraries"][result["os"]][result["detector"]]
            ):
                statistics["libraries"][result["os"]][result["detector"]][
                    result["analysis_type"]
                ] = []
            statistics["libraries"][result["os"]][result["detector"]][
                result["analysis_type"]
            ].append(
                {"Library": result["library"], "Number of apps": result["app_count"]}
            )

    print("Done! Rendering webpage...")

    return apps, statistics


@flask_app.route("/apps")
@cache.cached()
def apps():
    if cache.get("apps_cache") is None or cache.get("stats_cache") is None:
        print(f'recalculating {cache.get("apps_cache")} and {cache.get("stats_cache")}')
        (apps, statistics) = _get_statistics()
        cache.set("apps_cache", apps)
        cache.set("stats_cache", statistics)
    else:
        apps = cache.get("apps_cache")
        statistics = cache.get("stats_cache")

    return render_template("apps.html", apps=apps, statistics=statistics)


@flask_app.route("/apps/<path_app_id>")
@cache.cached()
def app(path_app_id):
    apps_data = _get_apps_data()

    app_id = {"android": None, "ios": None}
    for os in ["android", "ios"]:
        if exists(result_path(join(os, path_app_id))):
            app_id[os] = path_app_id

    for app in apps_data:
        if app["android_id"] is not None and app["android_id"] == app_id["android"]:
            app_id["ios"] = app["ios_bundle_id"]
        elif app["ios_bundle_id"] is not None and app["ios_bundle_id"] == app_id["ios"]:
            app_id["android"] = app["android_id"]

    results = {"static": {}, "dynamic": {}}
    for atype in ["static", "dynamic"]:
        for os in ["android", "ios"]:
            results[atype][os] = None
            if app_id[os] is None:
                continue

            results_path = result_path(join(os, app_id[os], f"{atype}.json"))
            if exists(results_path):
                results[atype][os] = {}
                with open(results_path, "r") as f:
                    data = json.load(f)
                    for key in data:
                        if key == "info":
                            results[atype][os][key] = data[key]
                            continue

                        result = []
                        for item in data[key]:
                            if atype == "static":
                                result.append(StaticMessage.from_dict(item))
                            else:
                                result.append(DynamicMessage.from_dict(item))

                        # Group results based on message.should_group(other_message)
                        grouped_results = []
                        for message in result:
                            for group in grouped_results:
                                if type(message) is type(
                                    group[0]
                                ) and message.should_group(group[0]):
                                    group.append(message)
                                    break
                            else:
                                grouped_results.append([message])

                        results[atype][os][key] = sorted(
                            grouped_results, key=lambda group: group[0].summary()
                        )

    return render_template("app.html", app_id=app_id, results=results)

@flask_app.route("/categories")
def categories():
    app_data = _get_apps_data()
    
    # Make a set of categories and a list of apps for each category
    categories = {}
    for app in app_data:
        if app["android_category"] is not None:
            if app["android_category"] not in categories:
                categories[app["android_category"]] = []
            categories[app["android_category"]].append(app)
    # sort categories with most apps
    categories = dict(sorted(categories.items(), key=lambda item: len(item[1]), reverse=True))
    return render_template("categories.html", categories=categories)
    

def run():
    flask_app.run(debug=True, host="0.0.0.0", port=Config().flask_port)

