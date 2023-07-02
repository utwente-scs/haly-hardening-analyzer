from os.path import join, basename, exists, dirname
import json
import glob
import pandas as pd
from tqdm import tqdm

results = '/media/wilco375/FYP/result'
min_app_matches = 5

known_java_libraries = []
if exists(join(dirname(__file__), 'java.txt')):
    with open(join(dirname(__file__), 'java.txt'), 'r') as f:
        known_java_libraries = [lib.strip() for lib in f.read().splitlines() if not lib.startswith('#') and lib.strip() != '']

system_native_libraries = set()
if exists(join(dirname(__file__), 'system-native.txt')):
    with open(join(dirname(__file__), 'system-native.txt'), 'r') as f:
        system_native_libraries = set([lib.strip() for lib in f.read().splitlines() if not lib.startswith('#') and lib.strip() != ''])

def get_java_lib_name(libname: str):
    for known_lib in known_java_libraries:
        if libname.startswith(known_lib):
            return known_lib
        
    return libname

def _normalize(data: dict) -> dict:
    # For each item, if it is a list or dict, json encode it
    for key in data.keys():
        if isinstance(data[key], dict) or isinstance(data[key], list):
            data[key] = json.dumps(data[key])
    return data

app_results = []

print("Reading JSON files")

# Create list of all results
for os in ['android', 'ios']:
    for analysis_type in ['static', 'dynamic']:
        print("Parsing", os, analysis_type)
        for app_result in tqdm(glob.glob(join(results, os, '*', f'{analysis_type}.json'))):
            with open(app_result, 'r') as f:
                result = json.load(f)

            for detector in result.keys():
                if detector == 'info' or not isinstance(result[detector], list):
                    continue

                for detection_result in result[detector]:
                    detection_result = _normalize(detection_result)
                    detection_result['os'] = os
                    detection_result['app_id'] = basename(dirname(app_result))
                    detection_result['analysis_type'] = analysis_type
                    detection_result['detector'] = detector
                    app_results.append(detection_result)

print("Parsing to Pandas")
app_results = pd.DataFrame(app_results)

# Extract used libraries
print("Extracting libraries")
native_libraries = {}
java_libraries = {}
for app_id, app_result in tqdm(app_results.groupby('app_id')):
    app_native_libraries = set()
    app_java_libraries = set()

    for result in app_result.itertuples():
        if result.analysis_type == 'static':
            if result.source is None:
                continue

            if result.type == 'native' or result.source.endswith('.nativestrings'):
                # Native libraries
                module = basename(result.source).replace('.nativestrings', '')
                if module not in system_native_libraries:
                    app_native_libraries.add(module)
            elif 'smali' in result.source:
                # Java libraries
                path = result.source[result.source.index('/smali')+1:]
                path = path[path.index('/')+1:]
                if '/' in path:
                    path = path[:path.rindex('/')]
                    if all(len(part) <= 2 for part in path.split('/')) or len(path) <= 3:
                        # Assume obfuscated path
                        continue
                    app_java_libraries.add(get_java_lib_name(path.replace('/', '.')))

        elif result.analysis_type == 'dynamic':
            # Native libraries
            if result.context != 'java':
                backtrace = json.loads(result.backtrace)
                for item in backtrace:
                    if item['module'] is not None and item['module'] not in system_native_libraries:
                        if item['module'] == 'libsystem_c.dylib':
                            print(app_id)
                        app_native_libraries.add(item['module'])
                        break
            
            # Java libraries
            java_backtrace = result.java_backtrace
            if result.java_backtrace is None and result.context == 'java':
                java_backtrace = result.backtrace
            if java_backtrace is not None:
                java_backtrace = json.loads(java_backtrace)

                for item in java_backtrace:
                    internal_classes = ['android.', 'java.', 'javax.', 'com.android.internal.', 'androidx.', 'com.android.', 'dalvik.system.', 'kotlin.', 'kotlinx.', 'libcore.io.']
                    if any(item.startswith(internal_class) for internal_class in internal_classes):
                        # Internal class
                        continue

                    # Assume first non-internal class is library call was made
                    path = item[:item.index('(')]
                    try:
                        path = path[:path.rindex('.', 0, path.rindex('.'))]
                    except ValueError:
                        pass
                    if all(len(part) <= 2 for part in path.split('.')) or len(path) <= 3:
                        # Assume obfuscated path
                        continue
                    app_java_libraries.add(get_java_lib_name(path))
                    break

    for library in app_native_libraries:
        if library not in native_libraries:
            native_libraries[library] = 0
        native_libraries[library] += 1

    for library in app_java_libraries:
        if library not in java_libraries:
            java_libraries[library] = 0
        java_libraries[library] += 1

native_libraries = sorted(native_libraries.items(), key=lambda item: item[1])
java_libraries = sorted(java_libraries.items(), key=lambda item: item[1])

print('\nNative libraries:')
for library, count in native_libraries:
    if count >= min_app_matches:
        print(f'{library}: {count}')

print('\nJava libraries:')
for library, count in java_libraries:
    if count >= min_app_matches:
        print(f'{library}: {count}')



