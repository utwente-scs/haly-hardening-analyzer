from os.path import dirname, join, abspath
import os
import threading
import tempfile
from inc.config import Config
import re2 as re
import subprocess


def temp_path(path: str) -> str:
    """
    Get the full path to a file in the temp directory of the OS
    :param path: The path to the file
    :return: The full path to the file
    """
    return join(tempfile.gettempdir(), path)


def workdir_path(path: str) -> str:
    """
    Get the full path to a file in the current working directory
    :param path: The path to the file
    :return: The full path to the file
    """
    return join(os.getcwd(), path)


def project_path(path: str) -> str:
    """
    Get the full path to a file in the root directory of this project
    :param path: The path to the file
    :return: The full path to the file
    """
    return abspath(join(dirname(__file__), "../../..", path))


def src_path(path: str) -> str:
    """
    Get the full path to a file in the src directory
    :param path: The path to the file
    :return: The full path to the file
    """
    return project_path(join("src", path))


def data_path(path: str) -> str:
    """
    Get the full path to a file in the src/data directory
    :param path: The path to the file
    :return: The full path to the file
    """
    return src_path(join("data", path))


def python_path(path: str) -> str:
    """
    Get the full path to a file in the src/python directory
    :param path: The path to the file
    :return: The full path to the file
    """
    return src_path(join("python", path))


def frida_path(path: str) -> str:
    """
    Get the full path to a file in the src/python directory
    :param path: The path to the file
    :return: The full path to the file
    """
    return src_path(join("frida", path))


def tools_path(path: str) -> str:
    """
    Get the full path to a file in the tools directory
    :param path: The path to the file
    :return: The full path to the file
    """
    return project_path(join("tools", path))


def workdir_path(path: str) -> str:
    """
    Get the full path to a file in the tmp directory
    :param path: The path to the file
    :return: The full path to the file
    """
    workdir = Config().work_dir
    if not os.path.exists(workdir):
        os.makedirs(workdir)
    return abspath(join(workdir, path))


def result_path(path: str) -> str:
    """
    Get the full path to a file in the result directory
    :param path: The path to the file
    :return: The full path to the file
    """
    return workdir_path(join("result", path))


def serializer(obj: any) -> list | dict | str:
    """
    Convert objects to a lists/dicts for JSON serialization
    """
    # Convert sets to lists
    if isinstance(obj, set):
        return list(obj)

    # Convert objects to dicts
    if hasattr(obj, "to_dict"):
        return obj.to_dict()

    raise TypeError


def pattern_to_regex(pattern: str):
    """
    Convert a pattern to a regex
    Format:
    "*string" - match strings ending with the given string
    "string*" - match strings starting with the given string
    "*string*" - match strings containing the given string
    "string" - match files where the file name without the path or the entire string is exactly the given string
    "/dir/filename" - match files where the string is exactly the given string
    A string is considered to start and end with a ", ' or newline
    :param pattern: The pattern to convert
    :return: The regex
    """
    exact_start = not pattern.startswith("*")
    exact_end = not pattern.endswith("*")
    pattern = re.escape(pattern.strip("*"))
    path = exact_start and exact_end and "/" in pattern

    if exact_start and exact_end and not path:
        # Exactly match but allow for path before string
        return f"(^|[\"'/]){pattern}($|[\"'])"

    regex = ""
    if exact_start:
        if path:
            # Exactly match start of string
            regex += "(^|[\"'])"
        else:
            regex += "(^|[\"'/])"
    regex += pattern
    if exact_end:
        # Exactly match end of string
        regex += "($|[\"'])"
    return regex


def multithread(function: callable, items: list, num_threads: int = 6) -> None:
    """
    Chunk items into num_threads chunks and execute function on each item in a chunk in a separate thread
    """
    threads = []
    chunks = [items[i::num_threads] for i in range(num_threads)]

    def execute_chunk(chunk):
        for app in chunk:
            function(app)

    for thread, chunk in enumerate(chunks):
        if len(chunk) == 0:
            continue

        thread = threading.Thread(target=execute_chunk, args=(chunk,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()


def replace(string: str, chars: list[str], replace: str) -> str:
    """
    Replace all occurrences of chars in string with replace
    :param string: The string to replace in
    :param chars: The characters to replace
    :param replace: The character to replace with
    :return: The replaced string
    """
    new_string = ""
    for char in string:
        if char in chars:
            new_string += replace
        else:
            new_string += char
    return new_string


def glob_by_magic(path: str, magic_signature: bytes | list[bytes]):
    """
    Find all files in a specified directory that match the given signature
    :param path: Path in which to recursively search for files
    :param magic_signature: Signature(s) to seach for (first bytes of a file)
    If providing multiple signatures, all signatures must have the same length
    """
    if not isinstance(magic_signature, list):
        magic_signature = [magic_signature]

    for root, _, files in os.walk(path):
        for file in files:
            file_path = join(root, file)
            with open(file_path, "rb") as f:
                # TODO Support signatures of different lengths
                file_signature = f.read(len(magic_signature[0]))
                if file_signature in magic_signature:
                    yield file_path


def run_system_command(command: str | list[str]) -> tuple[bool, str, int]:
    """
    Run a system command
    :param command: The command to run
    :return: A tuple containing whether the command was successful, the output and the return code
    """
    shell = False
    if isinstance(command, str):
        shell = True

    try:
        output = subprocess.check_output(command, shell=shell, stderr=subprocess.STDOUT)
        return True, output.decode("utf-8", "ignore"), 0
    except subprocess.CalledProcessError as e:
        return False, e.output.decode("utf-8", "ignore"), e.returncode
