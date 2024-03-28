import inc.util
from os.path import join, exists
import glob
import inc.config


class App:
    def __init__(self, package_id: str, os: str, device: str = None):
        """
        Object representing an app
        :param package_id: package id of the app
        :param os: OS of the app ('android' / 'ios')
        """
        self.package_id = package_id
        self.os = os
        self.device = device

    def get_binary_extension(self) -> str:
        """
        Get the extension of app binaries based on the app's os (apk for android, ipa for ios)
        """
        if self.os == "android":
            return "apk"
        elif self.os == "ios":
            return "ipa"
        else:
            raise ValueError(f"Unknown os {self.os}")

    def get_binaries_path(self) -> str:
        """
        Get the path to the binary directory of the app
        """
        return inc.util.workdir_path(join("binary", self.os, self.package_id))

    def get_main_binary_path(self) -> str:
        """
        Get the path to the binary of the app
        """
        return inc.util.workdir_path(
            join(
                "binary",
                self.os,
                self.package_id,
                f"base.{self.get_binary_extension()}",
            )
        )

    def get_native_files(self) -> list[str]:
        """
        Get the native files of the app
        """
        if self.os == "android":
            # Find so files
            files = glob.glob(
                join(
                    self.get_decompiled_path(),
                    "*/lib",
                    inc.config.Config().android_abi,
                    "*.so",
                )
            )
        elif self.os == "ios":
            # Find mach-o files
            files = inc.util.glob_by_magic(
                self.get_decompiled_path(),
                [
                    b"\xFE\xED\xFA\xCE",
                    b"\xFE\xED\xFA\xCF",
                    b"\xCE\xFA\xED\xFE",
                    b"\xCF\xFA\xED\xFE",
                ],
            )
        else:
            raise ValueError(f"Unknown os {self.os}")
        return list(files)

    def get_decompiled_path(self) -> str:
        """
        Get the path to the extracted app binary
        """
        return inc.util.workdir_path(join("binary", self.os, self.package_id))

    def get_result_path(self) -> str:
        """
        Get the path to the analysis result directory
        """
        return inc.util.result_path(join(self.os, self.package_id))

    def get_static_result_path(self) -> str:
        """
        Get the path to the static analysis result
        """
        return join(self.get_result_path(), "static.json")

    def get_dynamic_result_path(self) -> str:
        """
        Get the path to the dynamic analysis result
        """
        if self.device is None:
            path = join(self.get_result_path(), "dynamic.json")
        else:
            path = join(self.get_result_path(), f"dynamic_{self.device}.json")

    def get_stage(self) -> int:
        """
        Get the current decompilation / preparation stage of the app
        """
        stage_file = join(self.get_decompiled_path(), "stage")
        if not exists(stage_file):
            return 0

        with open(stage_file, "r") as f:
            num = f.read()
            if num == "":
                print("Empty stage file")
            return int(num)

    def set_stage(self, stage: int) -> None:
        """
        Set the current decompilation / preparation stage of the app
        """
        with open(join(self.get_decompiled_path(), "stage"), "w") as f:
            f.write(str(stage))
