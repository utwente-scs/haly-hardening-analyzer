from __future__ import annotations
from typing import TYPE_CHECKING
from detectors.detector import Detector
from inc.context import Context
from models.message import SvcStaticMessage
from androguard.core.bytecodes import apk
import frida.core

if TYPE_CHECKING:
    from models.nativebinary import NativeBinary


class SvcDetector(Detector):
    def get_id(self) -> str:
        return "svc"

    def static_analyze_r2(self, binary: NativeBinary):
        svcs = binary.exec_r2_cmd(
            f'"/aoj svc {Context().get_svc_code()}"'
        )  # Search for svc instructions

        if svcs is None or len(svcs) == 0:
            return

        # Get difference between vaddr and paddr to calculate offset
        sections = binary.exec_r2_cmd("iSj")
        if sections is None or len(sections) == 0:
            return
        vaddr = sections[0]["vaddr"]
        paddr = sections[0]["paddr"]
        offset = vaddr - paddr  # (vaddr is bigger than paddr)

        for svc in svcs:
            if not svc["code"].endswith(
                f"svc {Context().get_svc_code()}"
            ):  # "svc 0" also matches "svc 0x..." so we filter it out here
                continue

            # Get registry at this instruction so we can get the syscall number
            registry = binary.get_registry_at(svc["offset"])
            syscall_id = None
            syscall = None
            id_registry = Context().get_svc_instruction_registry()
            if id_registry in registry:
                syscall_id = registry[id_registry]
                syscall = Context().get_syscall_name(syscall_id)

            self.static_results.append(
                SvcStaticMessage(
                    binary.path, syscall_id, syscall, svc["offset"] - offset
                )
            )

    def dynamic_get_data(self) -> dict:
        return {"syscall_names": Context().get_syscall_names()}

    def dynamic_instrument(
        self, script: frida.core.Script, is_main_process: bool
    ) -> None:
        if is_main_process:
            svcs = self.static_results
            svcs_by_module = {}
            for svc in svcs:
                if svc["module"] not in svcs_by_module:
                    svcs_by_module[svc["module"]] = []
                if Context().is_ios():
                    path = svc["source"].split(".app/")[1]
                    if ".framework/" in path:
                        path = path.split(".framework/")[0] + ".framework"
                elif Context().is_android():
                    path = svc["module"][
                        3:-3
                    ]  # Remove the "lib" prefix and ".so" suffix
                svcs_by_module[svc["module"]].append(
                    {"path": path, "offset": svc["offset"]}
                )
            script.exports.hook_svcs(svcs_by_module)
