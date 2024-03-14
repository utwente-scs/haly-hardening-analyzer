import re2 as re


class Smali:
    def __init__(self, smali_file: str):
        """
        Initialize the smali file
        :param smali_file: Path to the smali file
        """
        self.file = smali_file
        self.lines = []
        self.cls = None
        self._parse()

    def _parse(self):
        """
        Parse the smali file
        """
        with open(self.file, "r") as f:
            self.lines = f.readlines()

        for line in self.lines:
            if line.startswith(".class"):
                # Extract class name from line
                self.cls = line.strip().split(" ")[-1].split(";")[0][1:]
                break

    def get_smali(self) -> str:
        """
        Get the smali code
        :return: Smali code
        """
        return "".join(self.lines)

    def find_call(
        self, method_name: str, type: str = "method", include_comparisons: bool = False
    ) -> list[object]:
        """
        Find a call to a method in the smali file
        :param method_name: Method call to find
        :param type: Type of the method call ('method' or 'object')
        :param include_comparisons: Also return values to which the return value of the method call is compared in the code
        :return: List of method calls, with 'smali' code, 'smali_line' line number in smali, 'line' line number in java and 'args' arguments
        """
        # Simple check without registry tracking
        if method_name not in self.get_smali():
            return []

        # Process file with registry tracking
        method_calls = []
        return_registries = {}
        java_line = None
        registry = {}
        for number, line in enumerate(self.lines):
            line = line.strip()

            clear_registry = True

            # Method call tracking
            if line.startswith("invoke-"):
                clear_registry = False

                if include_comparisons:
                    comparison_funs = {
                        "endsWith": "Ljava/lang/String;->endsWith(Ljava/lang/String;)Z",
                        "startsWith": "Ljava/lang/String;->startsWith(Ljava/lang/String;)Z",
                        "contains": "Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z",
                        "equals": "Ljava/lang/String;->equals(Ljava/lang/Object;)Z",
                        "equalsIgnoreCase": "Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z",
                        "matches": "Ljava/lang/String;->matches(Ljava/lang/String;)Z",
                    }
                    for comparison_fun in comparison_funs:
                        if comparison_funs[comparison_fun] not in line:
                            continue

                        matches = re.match("invoke-(\S+) \{([^}]*)\}, (\S+)", line)
                        if not matches:
                            continue

                        smali_args = [
                            arg.strip() for arg in matches.group(2).split(",")
                        ]
                        if (
                            smali_args[0] in return_registries
                            and smali_args[1] in registry
                        ):
                            return_registries[smali_args[0]]["comparisons"].append(
                                {
                                    "comparison": comparison_fun,
                                    "value": registry[smali_args[1]],
                                }
                            )

                if type == "method" and method_name in line:
                    # Get arguments
                    matches = re.match("invoke-(\S+) \{([^}]*)\}, (\S+)", line)
                    args = []
                    if matches:
                        smali_args = [
                            arg.strip() for arg in matches.group(2).split(",")
                        ]
                        if matches.group(1) != "static":
                            # Remove first argument (object instance) if not static
                            smali_args = smali_args[1:]

                        for arg in smali_args:
                            if arg in registry:
                                args.append(registry[arg])
                            elif arg.strip() != "":
                                args.append(None)

                    method_call = {
                        "java_line_nr": java_line,
                        "line_nr": number + 1,
                        "line": line,
                        "args": args,
                    }
                    if include_comparisons:
                        method_call["comparisons"] = []
                        return_registries[None] = method_call
                    method_calls.append(method_call)

            elif "get-object" in line and method_name in line:
                matches = re.findall("get-object (\w+)", line)
                if not matches:
                    continue

                object_call = {
                    "java_line_nr": java_line,
                    "line_nr": number + 1,
                    "line": line,
                }
                if include_comparisons:
                    object_call["comparisons"] = []
                    return_registries[matches[0]] = object_call
                method_calls.append(object_call)
                clear_registry = False

            # Basic const values tracking
            elif line.startswith("const"):
                # Set registry
                matches = re.match("const(\S+) (\S+), (\S+)", line)
                if matches:
                    if "string" in matches.group(1):
                        registry[matches.group(2)] = matches.group(3).strip('"')
                    else:
                        try:
                            registry[matches.group(2)] = int(matches.group(3), 16)
                        except ValueError:
                            registry[matches.group(2)] = matches.group(3)
                    clear_registry = False

            elif line.startswith("move-result"):
                # Move result
                matches = re.match("move-result(?:-object)? (\S+)", line)
                if matches:
                    if None in return_registries:
                        registry[matches.group(1)] = return_registries[None]
                        return_registries.pop(None)
                    clear_registry = False

            elif line.startswith("move"):
                # Move registry
                matches = re.match("move(?:\S*) (\S+), (\S+)", line)
                if matches:
                    if matches.group(2) in registry:
                        registry[matches.group(1)] = registry[matches.group(2)]
                    clear_registry = False

            elif line.startswith(".line"):
                # Line number tracking
                java_line = int(line.strip().split(" ")[-1])

            if clear_registry:
                # Clear registry if used in line
                to_delete = set()
                line_text = line.split('"')[0]  # Ignore occurences in strings
                for key in registry:
                    if key in line_text:
                        to_delete.add(key)

                for key in return_registries:
                    if key in line_text:
                        to_delete.add(key)

                for key in to_delete:
                    if key in registry:
                        registry.pop(key)
                    if key in return_registries:
                        return_registries.pop(key)

        return method_calls
