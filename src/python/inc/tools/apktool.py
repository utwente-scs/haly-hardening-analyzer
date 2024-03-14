from inc.util import tools_path, run_system_command
import logging

logger = logging.getLogger("hardeninganalyzer")


def decompile(binary: str) -> bool:
    """
    Decompile an app using apktool
    :param binary: Path to the binary of the app to decompile
    :return: True if the app was decompiled successfully, False otherwise
    """
    if not binary.endswith(".apk"):
        return False

    # Decompile using apktool
    apktool = tools_path("apktool.jar")
    cmd = f"java -jar {apktool} d {binary} -o {binary[:-4]} -f"
    if run_system_command(cmd)[0]:
        return True

    # Try to decompile without resources
    logger.warn(
        f"Failed to decompile {binary} with resources, trying without resources"
    )
    cmd = f"java -jar {apktool} d {binary} -o {binary[:-4]} --no-res -f"
    if run_system_command(cmd)[0]:
        return True

    # Try to decompile without resources and without sources
    logger.warn(
        f"Failed to decompile {binary} without resources, trying without resources and without sources"
    )
    cmd = f"java -jar {apktool} d {binary} -o {binary[:-4]} --no-res --no-src -f"
    if run_system_command(cmd)[0]:
        return True

    logger.warn(
        f"Failed to decompile {binary} without resources and without sources, trying to unzip"
    )

    return False
