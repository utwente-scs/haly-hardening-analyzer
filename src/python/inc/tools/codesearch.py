import logging
import os
import shlex
from os.path import exists
from inc.context import Context
from inc.util import run_system_command
from models.smali import Smali
import re2 as re

logger = logging.getLogger('hardeninganalyzer')

def index(directory: str, ignore_exists: bool = True) -> bool:
    """
    Index a directory for future searches
    :param directory: directory to index
    :param ignore_exists: do not index if index already exists
    """
    index = _set_index(directory)

    if exists(index):
        if ignore_exists:
            # Index already exists
            return True
        else:
            os.remove(index)

    logger.debug(f'Starting indexing of {directory}...')

    # Run cindex
    (success, result, code) = run_system_command(f'cindex {directory}')
    if not success:
        logger.warn(f'cindex {directory} failed with exit code {code}: {result}')
        return False

    logger.debug(f'Indexing of {directory} finished')

    return True

def search(directory: str, query: str, filefilter: str=None, ignore_case: bool=True) -> list[dict]:
    """
    Search for a regex query in a directory
    Directory will first be indexed if not already indexed
    :param directory: directory to search in
    :param query: regex query
    :param filefilter: regex to filter files (e.g. \.java$)
    :return: list of results with source, line_nr and line keys
    """
    if not exists(_set_index(directory)):
        # Index directory
        index(directory)

    # Run csearch
    flags = ''
    if filefilter is not None:
        flags = f'-f {shlex.quote(filefilter)} '
    if ignore_case:
        flags += '-i '
    logger.debug(f'csearch {flags} -n {shlex.quote(query)}')
    (success, output, code) = run_system_command(f'csearch {flags} -n {shlex.quote(query)}')
    if not success:
        if code == 1:
            # No results
            return []
        else:
            logger.error(output)
            return []

    # Parse result
    # Lines have format filename:line number:line
    result = []
    splitlines = output.splitlines()
    lines = []
    for line in splitlines:
        if not line.startswith('/') or not line.split(':')[1].isdigit():
            # Merge multiline results into one line
            if len(lines) == 0:
                continue
            lines[-1] += line
        else:
            lines.append(line)

    for line in lines:
        line = line.strip()
        if line.startswith('open ') and line.endswith(': no such file or directory'):
            # File does not exist
            continue
        line = line.split(':')
        source = line[0]
        if source.endswith('.nativestrings'):
            source = source[:-14]
        line_text = ':'.join(line[2:]).strip()
        lower_line_text = line_text.lower()

        # Ignore false positives
        fp = {
            'frida': ['friday', 'fridag', 'afrida', 'frida kahlo', 'frida khalo', 'frida kahalo', 'elfrida', 'glados_frida', 'sufrida', 'sofrida', 'profile_name', 'ivett', 'fritiof', 'female', 'feminine', 'first_name', 'giuffrida', 'boy.', 'girl.', 'wilfrid'], # Intercept things like weekdays and locations
            'xposed': ['exposed', 'axposed'],
            'cydia': ['acy', 'diag', 'emergency', 'dial'], # Intercept things like PrivacyDiagnostic, EmergencyDial
            'jailbreak': ['thanks to the jailbreak'], # Ignore license text of firebase
            '/bin/bash': ['#!/bin/bash', 'for example'], # Ignore shebangs
            'kinguser': ['networkinguser', 'bookinguser', 'trackinguser', 'cookinguser', 'blockinguser', 'rankinguser', 'parkinguser', 'linkinguser', 'seekinguser', 'talkinguser', 'checkinguser', 'markinguser', 'likinguser', 'speakinguser', 'pickinguser', 'lockinguser', 'talkinguser', 'takinguser', 'bankinguser', '\\u2026kinguser'], # Ignore blockingUser etc.
            'supersu': ['supersub', 'supersuc', 'supersud', 'supersuf', 'supersug', 'supersuk', 'supersul', 'supersum', 'supersun', 'supersup', 'supersur', 'supersus', 'supersut', 'supersuv'], # Ingore superSurface, superSubscribe etc.
            '.su': ['/wiki/.su'], # .su TLD wiki
            'droid4x': ['android4x'],
            'genymotion': ['running on emulator (or genymotion)']
        }

        if any(pattern in query and any(fp in lower_line_text for fp in fp[pattern]) for pattern in fp.keys()):
            continue

        if 'frida' in query and any(name in source.lower() for name in ['female', 'firstname', 'lastname', 'first_name', 'last_name', '/sv/', '_sv', 'sv.lproj']) or source.endswith('.json'):
            # Frida is in a female names dictionary, and also occurs in several json files
            continue

        if 'magisk' in query and re.match('[/_-+](da|no|sv|nb|)[/_-.+]', source) or source.endswith('ideas_info_config.json'):
            return True

        if 'cydia' in query and source.endswith('taxonomy.csv'):
            continue

        if (')su(' in query or ')sudo(' in query) and 'bin/' not in lower_line_text and 'data/local/' not in lower_line_text:
            continue

        result.append({
            'source': source,
            'line_nr': int(line[1]),
            'line': line_text
        })

    return result

def search_smali(query: str, ignore_case: bool=True) -> list[Smali]:
    """
    Search for a string query in smali files of app currently being analyzed
    :param query: string query
    :return: list of smali files containing the query
    """
    if not Context().is_android():
        return []

    result = search(Context().app.get_binaries_path(), re.escape(query), '\.smali$', ignore_case=ignore_case)

    # Load smali files
    files = {}
    for item in result:
        if item['source'] not in files:
            files[item['source']] = Smali(item['source'])

    return files.values()

def search_plaintext(query: str, ignore_case: bool=True) -> list[str]:
    """
    Search for a regex query in plaintext files of app currently being analyzed
    :param query: regex query
    :return: list of plaintext files containing the query
    """
    return search(Context().app.get_binaries_path(), query, ignore_case=ignore_case)

def _set_index(directory) -> str:
    """
    Set the $CSEARCHINDEX environment variable for the provided directory
    :param directory: directory to set the index for
    :return: path to the index file
    """
    index_file = f'{directory}.index'

    # Set $CSEARCHINDEX
    os.environ['CSEARCHINDEX'] = index_file

    return index_file
