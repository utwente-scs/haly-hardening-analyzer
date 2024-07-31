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
import re

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

def _parse_result(json_file, app_infos, app_results, app_os, app_id, other_app_id, analysis_type, device=None):
    if not exists(json_file):
        return

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
                detection_result["device"] = device["name"] if device is not None else ""
                detection_result["analysis_type"] = analysis_type
                detection_result["detector"] = detector
                detection_result["library"] = get_library(detection_result)
                
                # # DONE Can remove?
                # if _should_ignore_detection(detection_result):
                #     continue
                
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

def _parse_apkid_results(json_file, app_apkid_results, app_id):
    if not exists(json_file):
        return
    results = {
        "app_id": app_id,
        "anti_vm": 0,
        "anti_debug": 0,
        "anti_disassembly": 0,
        "packer": {},
        "protector": {},
        "obfuscator": {},
        "compiler": {},
    }
    
    with open(json_file, "r") as f:
        result = json.load(f)
        for apk in result:
            for file_result in result[apk]["files"]:
                for key, match in file_result["matches"].items():
                    if key in results:
                        if type(results[key]) == int:
                            results[key] += len(match)
                        else:
                            for m in match:
                                if m not in results[key]:
                                    results[key][m] = 1
                                else:
                                    results[key][m] += 1
        app_apkid_results.append(results)    
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
        "totalAndroidDynamic": 0,  # Number of apps dynamically analyzed on Android
        "totalIosDynamic": 0,  # Number of apps dynamically analyzed on iOS TODO remove this too
        "totalAndroidStatic": 0,  # Number of apps statically analyzed on Android
        "totalAndroidAPKiD": 0,  # Number of apps analyzed with APKiD on Android
        "totalAnalyzed": 0,  # Number of apps that are statically analyzed on iOS and Android (might have failed dynamic analysis)
    }
    app_apkid_results = []

    if not Config().force:
        print(
            "Checking for cached results, use --force to force re-calculating all results"
        )
        cached_data = {}
        for file in ["apps", "app_infos", "app_results", "app_counts", "app_apkid_results"]:
            # DONE make this a generic result path. This one is the cached results
            if exists(result_path(f"{file}.csv")):
                data = pd.read_csv(
                    join(result_path(""), f"{file}.csv"),
                    low_memory=False,
                    escapechar="\\",
                )
                if file == "app_counts":
                    data = dict(zip(data["key"], data["value"]))
                if file == "app_results":
                    data["confident"] = data["confident"].astype(bool)
                if file == "app_apkid_results":
                    data["packer"] = data["packer"].apply(
                        lambda x: json.loads(x.replace("'", '"')) if x != {} else {}
                    )
                    data["protector"] = data["protector"].apply(
                        lambda x: json.loads(x.replace("'", '"')) if x != {} else {}
                    )
                    data["obfuscator"] = data["obfuscator"].apply(
                        lambda x: json.loads(x.replace("'", '"')) if x != {} else {}
                    )
                    data["compiler"] = data["compiler"].apply(
                        lambda x: json.loads(x.replace("'", '"')) if x != {} else {}
                    )

                cached_data[file] = data

        if len(cached_data) == 5:
            print("Using cached results")
            return (
                cached_data["apps"],
                cached_data["app_infos"],
                cached_data["app_results"],
                cached_data["app_counts"],
                cached_data["app_apkid_results"],
            )

    android_to_app = {app["android_id"]: app for app in _get_apps()}
    print("Parsing app results...")
    for app in tqdm([app for app in Config().apps if app.os == "android"]):
        app_counts["totalApps"] += 1

        # Check if analysis of app is completed
        analysis_completed = True
        try:
            for app_os in ["ios", "android"]:
                for analysis_type in ["static", "dynamic", "apkid"]:
                    package_id = (
                            android_to_app[app.package_id]["ios_bundle_id"]
                        if app_os == "ios"
                        else app.package_id
                    )
                    
                    # DONE make this a for loop of all devices
                    if analysis_type == "dynamic":
                        counted = False
                        for device in Config().devices:
                            json_file = join(
                                result_path(app_os), package_id, f"{analysis_type}_{device['name']}.json"
                            )
                            
                            if exists(json_file):
                                # DONE change to device total too totalAndroidDynamic<Device>
                                key = f"total{app_os.capitalize()}{analysis_type.capitalize()}{device['name'].capitalize()}"
                                if key not in app_counts:
                                    app_counts[key] = 0
                                app_counts[key] += 1
                                if not counted:
                                    app_counts[
                                        f"total{app_os.capitalize()}{analysis_type.capitalize()}"
                                    ] += 1
                                    counted = True
                    elif analysis_type == "static":
                        json_file = join(
                            result_path(app_os), package_id, f"{analysis_type}.json"
                        )

                        if exists(json_file):
                            app_counts[
                                f"total{app_os.capitalize()}{analysis_type.capitalize()}"
                            ] += 1
                    elif analysis_type == "apkid" and app_os == "android":
                        json_file = join(
                            result_path(app_os), package_id, f"{analysis_type}_results.json"
                        )

                        if exists(json_file):
                            app_counts[
                                f"total{app_os.capitalize()}APKiD"
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
            for analysis_type in ["static", "dynamic", "apkid"]:
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
                
                # DONE make this a for loop of all devices
                if analysis_type == "dynamic":
                    for device in Config().devices:
                        json_file = join(
                            result_path(app_os), app_id, f"{analysis_type}_{device['name']}.json"
                        )
                        _parse_result(json_file, app_infos, app_results, app_os, app_id, other_app_id, analysis_type, device)
                elif analysis_type == "static":
                    json_file = join(
                        result_path(app_os), app_id, f"{analysis_type}.json"
                    )
                    _parse_result(json_file, app_infos, app_results, app_os, app_id, other_app_id, analysis_type)
                elif analysis_type == "apkid":
                    json_file = join(
                        result_path(app_os), app_id, f"{analysis_type}_results.json"
                    )
                    _parse_apkid_results(json_file, app_apkid_results, app_id)

    # Sort by Android app name
    apps = sorted(apps, key=lambda app: app["android_id"])

    # Parse with pandas so we can use SQL
    print("Converting data to pandas...")
    apps = pd.DataFrame(apps)
    app_infos = pd.DataFrame(app_infos)
    app_results = pd.DataFrame(app_results)
    app_apkid_results = pd.DataFrame(app_apkid_results)

    for file in ["apps", "app_infos", "app_results", "app_counts", "app_apkid_results"]:
        data = locals()[file]
        if file == "app_counts":
            data = pd.DataFrame(data.items(), columns=["key", "value"])
        data.to_csv(result_path(f"{file}.csv"), index=False, escapechar="\\")

    return apps, app_infos, app_results, app_counts, app_apkid_results



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
        # "hardeningTechniques",
        # "hardeningTechniquesApps",
        # # "hardeningTechniquesConsistency",
        # # "hardeningTechniquesDelta",
        # "hardeningTechniquesPerCategory",
        # "hardeningTechniquesPerPermission",
        # "hardeningTechniquesPerPermissionCount",
        # # "permissionsDiff",
        # "jailbreaks",
        # "hookingFrameworks",
        # "plaintextTraffic",
        # "plaintextTrafficType",
        # "tlsCipher",
        # "hardeningTechniquesLibraries",
        # "hardeningTechniquesLibrariesNoCommon",
        # "libraries",
        # "packer",
        "packerPerCategory",
        # "obfuscator",
        # "obfuscatorPerCategory",
        # "protector",
        # "protectorPerCategory",
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
    (apps, app_infos, app_results, statistics, app_apkid_results) = _get_apps_results()
    
    # app_results_static = app_results[app_results["analysis_type"] == "static"]
    # app_results_static_confident = app_results_static[app_results_static["confident"] == True]
    # app_results_static_not_confident = app_results_static[app_results_static["confident"] == False]
        
    # devices = Config().devices
    # app_results_dynamic = {
    #     device["name"]: app_results[(app_results["analysis_type"] == "dynamic") & (app_results["device"] == device["name"])]
    #     for device in devices
    # }
    # app_results_dynamic_confident = {
    #     device["name"]: app_results_dynamic[device["name"]][app_results_dynamic[device["name"]]["confident"] == True]
    #     for device in devices
    # }
    # app_results_dynamic_not_confident = {
    #     device["name"]: app_results_dynamic[device["name"]][app_results_dynamic[device["name"]]["confident"] == False]
    #     for device in devices
    # }
    

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
            },
        }
        for device in Config().devices:
            statistics["hardeningTechniques"]["values"][f"androidDynamic_{device['name'].capitalize()}"] = [0] * n_techs
            statistics["hardeningTechniques"]["values"][f"androidDynamic_{device['name'].capitalize()}?"] = [0] * n_techs
        for ios_type in ["iosStatic", "iosStatic?", "iosDynamic", "iosDynamic?"]:
            statistics["hardeningTechniques"]["values"][ios_type] = [0] * n_techs

        apps_results_grouped = app_results.groupby(["detector", "analysis_type", "os", "app_id", "device"])
        apps_results_grouped_confidence = apps_results_grouped['confident'].sum().reset_index()
        apps_results_grouped_confidence['confident'] = apps_results_grouped_confidence['confident'].apply(lambda x: 1 if x > 0 else 0)
        
        technique_counts = apps_results_grouped_confidence.groupby(['detector', 'analysis_type', 'os', 'confident',"device"])['app_id'].nunique().reset_index()
        technique_counts.rename(columns={'app_id': 'count'}, inplace=True)
        
        for _, result in technique_counts.iterrows():
            if result["detector"] in hardening_techniques:
                key = f'{result["os"]}{result["analysis_type"].capitalize()}'
                if result["analysis_type"] == "dynamic":
                    key += f'_{result["device"].capitalize()}'
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

        # Perform the subquery
        hardening = (app_results[(app_results['detector'] != 'svc') &
                                (app_results['detector'] != 'connection') &
                                (app_results['detector'] != 'screenreader') &
                                (app_results['confident'] == 1)]
                    .groupby(['app_id', 'os'])['detector']
                    .nunique()
                    .reset_index()
                    .rename(columns={'detector': 'app_hardening_count'}))

        # Perform the left join
        merged = pd.merge(app_infos, hardening, how='left', left_on=['app_id', 'os'], right_on=['app_id', 'os'])

        # Replace null values in `app_hardening_count` with 0
        merged['app_hardening_count'] = merged['app_hardening_count'].fillna(0)

        # Filter where analysis_type is 'static'
        filtered = merged[merged['analysis_type'] == 'static']

        # Group by `os` and `app_hardening_count` and count distinct `app_id`
        query_results = (filtered.groupby(['os', 'app_hardening_count'])['app_id']
                .nunique()
                .reset_index()
                .rename(columns={'app_id': 'app_count'}))

        # Rename the column to match the desired output
        query_results = query_results.rename(columns={'app_hardening_count': 'hardening_count'})

        # Order the result
        query_results = query_results.sort_values(by=['os', 'hardening_count'])

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

        techniques = app_results[(app_results['detector'] != 'svc') & 
                         (app_results['detector'] != 'connection')]['detector'].drop_duplicates().reset_index(drop=True)

        # Perform the ios_results subquery
        ios_results = (app_results[(app_results['confident'] == 1) & 
                                (app_results['os'] == 'ios')]
                    .groupby(['detector', 'app_id'])
                    .size()
                    .reset_index(name='detected_ios')
                    .assign(detected_ios=1))

        # Perform the android_results subquery
        android_results = (app_results[(app_results['confident'] == 1) & 
                                    (app_results['os'] == 'android')]
                        .groupby(['detector', 'app_id'])
                        .size()
                        .reset_index(name='detected_android')
                        .assign(detected_android=1))

        # Create a DataFrame for cross join (Cartesian product)
        techniques_cross = pd.DataFrame({'key': 0, 'detector': techniques})
        apps['key'] = 0
        apps_techniques = pd.merge(apps, techniques_cross, on='key').drop('key', axis=1)

        # Perform the left join with ios_results
        merged_ios = pd.merge(apps_techniques, ios_results, how='left', left_on=['ios_bundle_id', 'detector'], right_on=['app_id', 'detector'])
        merged_ios['detected_ios'] = merged_ios['detected_ios'].fillna(0)

        # Perform the left join with android_results
        merged_android = pd.merge(merged_ios, android_results, how='left', left_on=['android_id', 'detector'], right_on=['app_id', 'detector'])
        merged_android['detected_android'] = merged_android['detected_android'].fillna(0)

        # Group by techniques.detector, ios_results.detected_ios, android_results.detected_android and count
        query_results = (merged_android.groupby(['detector', 'detected_ios', 'detected_android'])
                .size()
                .reset_index(name='app_count')).fillna(0)

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
        techniques = app_results[(app_results['detector'] != 'screenreader') & 
                         (app_results['detector'] != 'svc') & 
                         (app_results['detector'] != 'connection')]['detector'].drop_duplicates().reset_index(drop=True)

        # Perform the ios_results subquery
        ios_results = (app_results[(app_results['confident'] == 1) & 
                                (app_results['os'] == 'ios')]
                    .groupby(['detector', 'app_id'])
                    .size()
                    .reset_index(name='detected_ios')
                    .assign(detected_ios=1))

        # Perform the android_results subquery
        android_results = (app_results[(app_results['confident'] == 1) & 
                                    (app_results['os'] == 'android')]
                        .groupby(['detector', 'app_id'])
                        .size()
                        .reset_index(name='detected_android')
                        .assign(detected_android=1))

        # Create a DataFrame for cross join (Cartesian product)
        techniques_cross = pd.DataFrame({'key': 0, 'detector': techniques})
        apps['key'] = 0
        apps_techniques = pd.merge(apps, techniques_cross, on='key').drop('key', axis=1)

        # Perform the left join with ios_results
        merged_ios = pd.merge(apps_techniques, ios_results, how='left', left_on=['ios_bundle_id', 'detector'], right_on=['app_id', 'detector'])
        merged_ios['detected_ios'] = merged_ios['detected_ios'].fillna(0)

        # Perform the left join with android_results
        merged_android = pd.merge(merged_ios, android_results, how='left', left_on=['android_id', 'detector'], right_on=['app_id', 'detector'])
        merged_android['detected_android'] = merged_android['detected_android'].fillna(0)

        # Compute the 'different' column
        merged_android['different'] = merged_android.apply(lambda row: 1 if (row['detected_ios'] == 1 and row['detected_android'] == 0) or (row['detected_ios'] == 0 and row['detected_android'] == 1) else 0, axis=1)

        # Group by apps.android_id and sum the 'different' column
        diff_results = merged_android.groupby('android_id')['different'].sum().reset_index()

        # Group by 'different' and count the occurrences
        query_results = diff_results.groupby('different').size().reset_index(name='app_count').fillna(0)


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
        categories = apps["android_category"].drop_duplicates().sort_values().tolist()
        categories.append("Other")
        
        statistics["hardeningTechniquesPerCategory"] = {
            "title": "Average number of hardening techniques per category",
            "labels": categories,
            "values": {
                "android": [0] * len(categories),
                "ios": [0] * len(categories),
            },
        }
        
        # Perform the ios_results subquery
        ios_results = (app_results[(app_results['confident'] == 1) & 
                                (app_results['os'] == 'ios')]
                    .groupby('app_id')['detector']
                    .nunique()
                    .reset_index(name='detected_ios'))

        # Perform the android_results subquery
        android_results = (app_results[(app_results['confident'] == 1) & 
                                    (app_results['os'] == 'android')]
                        .groupby('app_id')['detector']
                        .nunique()
                        .reset_index(name='detected_android'))

        # Perform the left join with ios_results
        merged_ios = pd.merge(apps, ios_results, how='left', left_on='ios_bundle_id', right_on='app_id')
        merged_ios['detected_ios'] = merged_ios['detected_ios'].fillna(0)

        # Perform the left join with android_results
        merged_android = pd.merge(merged_ios, android_results, how='left', left_on='android_id', right_on='app_id')
        merged_android['detected_android'] = merged_android['detected_android'].fillna(0)
        
        

        # Group by android_category and compute the average values
        query_results = (merged_android.groupby('android_category')
                        .agg(detected_ios=('detected_ios', 'mean'), detected_android=('detected_android', 'mean'))
                        .reset_index()).fillna(0)

        # Check if the number of apps per category is less than 50
        small_categories = query_results[query_results['android_category'].map(merged_android['android_category'].value_counts()) < len(apps) * 0.015]

        # Group small categories as "other"
        query_results.loc[query_results['android_category'].isin(small_categories['android_category']), 'android_category'] = 'Other'
        
        for category in small_categories['android_category']:
            categories.remove(category)

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
        
        filtered_results = app_results[app_results['confident'] == 1]

        results_inner_query = (filtered_results.groupby(['os', 'app_id'])
                            ['detector'].nunique().reset_index(name='techniques_detected'))

        permission_names = pd.DataFrame(list(permissions.keys()), columns=["permission_name"])

        all_permissions = [item for sublist in permissions.values() for item in sublist]

        def calculate_permission_set(row):
            permission = row['permission_name']
            permission_keys = permissions.get(permission, [])

            if len(permission_keys) > 0:
                for key in permission_keys:
                    if key in row['permissions']:
                        return 1
                return 0
            else:
                for key in all_permissions:
                    if key not in row['permissions']:
                        return 1
                return 0

        merged = pd.merge(app_infos, permission_names, how='cross')

        merged['permission_set'] = merged.apply(calculate_permission_set, axis=1)

        merged = pd.merge(merged, results_inner_query, how='left', left_on=['app_id', 'os'], right_on=['app_id', 'os'])

        filtered = merged[merged['analysis_type'] == 'static']
        query_results = filtered.groupby(['os', 'permission_name', 'permission_set']).agg({
            'techniques_detected': 'mean'
        }).reset_index()

        query_results.fillna(0, inplace=True)
        
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
        
        results_inner_query = (app_results[app_results['confident'] == 1]).groupby(['os', 'app_id'])['detector'].nunique().reset_index(name='techniques_detected')

        permission_names = pd.DataFrame(permissions.keys(), columns=["permission_name"])
        all_permissions = [item for sublist in permissions.values() for item in sublist]
        
        def calculate_permission_count(row):
            permission = row['permission_name']
            permission_keys = permissions.get(permission, [])

            if len(permission_keys) > 0:
                for key in permission_keys:
                    if key in row['permissions']:
                        return 1
                return 0
            else:
                for key in all_permissions:
                    if key not in row['permissions']:
                        return 1
            return 0
        
        merged = pd.merge(app_infos, permission_names, how='cross')
        merged['permission_count'] = merged.apply(calculate_permission_count, axis=1)
        merged = merged.groupby(['os', 'app_id', 'analysis_type']).agg({
            'permission_count': 'sum'
        }).reset_index()
        
        merged = pd.merge(merged, results_inner_query, how='left', left_on=['app_id', 'os'], right_on=['app_id', 'os'])
        filtered = merged[merged['analysis_type'] == 'static']
        query_results = filtered.groupby(['os', 'permission_count']).agg({
            'techniques_detected': 'mean'
        }).reset_index().fillna(0)

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
        permission_names = pd.DataFrame(list(permissions.keys()), columns=["permission_name"])

        all_permissions = [item for sublist in permissions.values() for item in sublist]

        def calculate_permission_set(row):
            permission = row['permission_name']
            permission_keys = permissions.get(permission, [])

            if len(permission_keys) > 0:
                for key in permission_keys:
                    if key in row['permissions']:
                        return 1
                return 0
            else:
                for key in all_permissions:
                    if key not in row['permissions']:
                        return 1
                return 0

        merged = pd.merge(app_infos, apps, how='left',
                        left_on=['app_id'],
                        right_on=['android_id']).fillna(
                            pd.merge(app_infos, apps, how='left',
                                    left_on=['app_id'],
                                    right_on=['ios_bundle_id']))

        merged = pd.merge(merged.assign(key=1), permission_names.assign(key=1),
                        on='key').drop('key', axis=1)

        merged['permission_set'] = merged.apply(calculate_permission_set, axis=1)

        filtered = merged[(merged['analysis_type'] == 'static') & (
            merged['permission_set'] == 1) & (
                ~merged['permission_name'].isin(['HomeKit', 'None']))]

        grouped = filtered.groupby(['app_id', 'permission_name',
                                    'permission_set'])['permission_set'].sum().reset_index(
                                        name='perm_different')

        permissions_diff = grouped.groupby('app_id')['perm_different'].sum().reset_index(
            name='different')

        query_results = permissions_diff.groupby('different').size().reset_index(
            name='app_count')

        query_results.fillna(0, inplace=True)

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
    # TODO Dont have jailbreaks to test #
    # with                              #
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
        
        query_results = app_results[(app_results['pattern'].notnull() | app_results['file'].notnull()) & 
                                    (app_results['detector'] == 'hooking')].sort_values(by=['app_id', 'os', 'analysis_type', 'device']).fillna("")

        statistics["hookingFrameworks"] = {
            "title": "Detected hooking frameworks",
            "labels": list(hooking_frameworks.keys()),
            "values": {
                "androidStatic": [],
            },
        }
        for device in Config().devices:
            statistics["hookingFrameworks"]["values"][f"androidDynamic_{device['name'].capitalize()}"] = []
            # statistics["hookingFrameworks"]["values"][f"androidDynamic_{device['name'].capitalize()}?"] = []
        statistics["hookingFrameworks"]["values"]["iosStatic"] = []
        statistics["hookingFrameworks"]["values"]["iosDynamic"] = []

        for _, framework_keywords in hooking_frameworks.items():
            number_of_apps = {
                "androidStatic": 0,
            }
            for device in Config().devices:
                number_of_apps[f"androidDynamic_{device['name'].capitalize()}"] = 0
            number_of_apps["iosStatic"] = 0
            number_of_apps["iosDynamic"] = 0
            last_app_id = None
            last_app_os = None
            last_analysis_type = None
            last_device = None
            for _, result in query_results.iterrows():
                if (
                    last_app_id == result["app_id"]
                    and last_app_os == result["os"]
                    and last_analysis_type == result["analysis_type"]
                    and last_device == result["device"]
                ):
                    continue

                if any(
                    any(keyword in result[key].lower() for key in ["pattern", "file"])
                    for keyword in framework_keywords
                ):
                    key = f'{result["os"]}{result["analysis_type"].capitalize()}'
                    if result["analysis_type"] == "dynamic":
                        key += f'_{result["device"].capitalize()}'
                    number_of_apps[key] += 1
                    last_app_id = result["app_id"]
                    last_app_os = result["os"]
                    last_analysis_type = result["analysis_type"]
                    last_device = result["device"]

            for os in ["android", "ios"]:
                for analysis_type in ["static", "dynamic"]:
                    for device in Config().devices:
                        if device["os"] != os:
                            continue
                        key = f"{os}{analysis_type.capitalize()}"
                        if analysis_type == "dynamic":
                            key += f'_{device["name"].capitalize()}'
                        statistics["hookingFrameworks"]["values"][key].append(
                            number_of_apps[key]
                        )

        progress.n += 1
        progress.refresh()

    ##################################
    # Detection of plaintext traffic #
    ##################################
    if "plaintextTraffic" in statistics_to_show:        
        query_results = app_results[(app_results['type'] == 'plain_http') &
                                    (app_results['detector'] == 'connection')].sort_values(by=['app_id', 'os']).fillna("")

        statistics["plaintextTraffic"] = {
            "title": "Detected plaintext traffic",
            "labels": ["Android", "iOS", "Android no OCSP", "iOS no OCSP"],
            "values": [0, 0, 0, 0],
        }

        for _, result in query_results.iterrows():
            statistics["plaintextTraffic"]["values"][
                0 if result["os"] == "android" else 1
            ] += 1

        query_results = app_results[(app_results['type'] == 'plain_http') &
                                    (app_results['detector'] == 'connection') &
                                    (app_results['data'].notnull())]
        query_results = query_results[(query_results['data'].str.contains('ocsp') == False) &
                                    (query_results['data'].str.contains('o.lecncr.org') == False)].sort_values(by=['app_id', 'os']).fillna("")

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
        query_results = app_results[(app_results['type'] == 'plain_http') &
                                    (app_results['detector'] == 'connection')].sort_values(by=['data', 'app_id', 'os']).fillna("")

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
        query_results = app_results[(app_results['type'] == 'tls_conn') &
                                    (app_results['detector'] == 'connection')].groupby(['data', 'os']).size().reset_index(name='count').sort_values(by=['data', 'os']).fillna("")

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
        library = app_results['library'].apply(lambda x: 'FirstParty' if pd.isnull(x) else 'ThirdParty')
        query_results = app_results[app_results['confident'] == 1].groupby(['detector', 'os', library])['app_id'].nunique().reset_index(name='app_count')
        

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
        library = app_results['library'].apply(lambda x: 'FirstParty' if pd.isnull(x) else 'ThirdParty')
        query_results = app_results[(app_results['confident'] == 1) & 
                                    (app_results['library'].isnull() | ~app_results['library'].isin(['com.google.android.gms', 'com.google.firebase', 'com.appsflyer']))].groupby(['detector', 'os', library])['app_id'].nunique().reset_index(name='app_count')

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
        filtered_results = app_results[app_results['confident'] == 1].copy()     
        filtered_results['library'].fillna("App-specific", inplace=True)

        grouped_results = filtered_results.groupby(['analysis_type', 'detector', 'os', 'library'])
        app_counts = grouped_results['app_id'].nunique().reset_index(name='app_count')

        filtered_app_counts = app_counts[app_counts['app_count'] > 1]

        query_results = filtered_app_counts.sort_values(by=['os', 'detector', 'analysis_type', 'app_count'], 
                                                        ascending=[True, True, False, False])

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
     ###########################
    # Packer per category #
    ###########################
    if "packerPerCategory" in statistics_to_show:
        categories = apps["android_category"].drop_duplicates().sort_values().tolist()
        categories.append("Other")
        print(app_apkid_results)

        packers = app_apkid_results["packer"].drop_duplicates().tolist()
        packer_set = set()
        for packer in packers:
            for p in packer.keys():
                packer_set.add(p)
        android_merged = pd.merge(apps, app_apkid_results, how='left', left_on='android_id', right_on='app_id')
        
        # Check if the number of apps per category is less than 50
        small_categories = android_merged[android_merged['android_category'].map(android_merged['android_category'].value_counts()) < len(apps) * 0.015]

        # Group small categories as "other"
        android_merged.loc[android_merged['android_category'].isin(small_categories['android_category']), 'android_category'] = 'Other'
        
        for category in small_categories['android_category']:
            if category in categories:
                categories.remove(category)
            else:
                print(f"Category {category} not in categories")
            
        query_results = android_merged.groupby(['android_category']).size().reset_index(name='count')
            
        statistics["packerPerCategory"] = {
            "title": "Percentage of packers used per category",
            "labels": categories,
            "values": {
            },
        }
        
        packer_set = sorted(packer_set)
        
        for packer in packer_set:
            statistics["packerPerCategory"]["values"][packer] = [0] * len(categories)
        
        for _, row in android_merged.iterrows():
            category = row['android_category']
            packer = row['packer']
            if isinstance(packer, dict):
                packer_keys = packer.keys()
                for key in packer_keys:
                    statistics["packerPerCategory"]["values"][key][categories.index(category)] += 1
                    
        # percentages
        for packer in packer_set:
            if packer == "None":
                continue
            for i, category in enumerate(categories):
                statistics["packerPerCategory"]["values"][packer][i] = statistics["packerPerCategory"]["values"][packer][i] / query_results[query_results['android_category'] == category]['count'].values[0]*100

        progress.n += 1
        progress.refresh()

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

    return render_template("apps.html", apps=apps, statistics=statistics, re=re)


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
    
    categories["Other"] = []
    threshold = len(app_data) * 0.015
    to_remove = []
    # check if any category has less than 20 apps
    for category, apps in categories.items():

        if len(apps) < threshold:
            # create a new category called "other" and move the apps to it
            categories["other"] = categories.get("other", []) + apps
            to_remove.append(category)
    for category in to_remove:
        categories.pop(category)

    return render_template("categories.html", categories=categories)
def run():
    flask_app.run(debug=True, host="0.0.0.0", port=Config().flask_port)

