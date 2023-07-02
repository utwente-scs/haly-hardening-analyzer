from inc.util import *
from detectors import Detectors
import r2pipe
import inc.tools.radare2 as radare2
import traceback
from os.path import basename, exists
import os
import re2 as re
import logging
from typing import Callable
import time
from inc.context import Context

logger = logging.getLogger('hardeninganalyzer')

class NativeBinary:
    def __init__(self, path: str):
        """
        Create a binary object from a module by exporting it from the device
        :param module: source of the binary, either a dict with module info
        :param exports: frida rpc exports to use for getting the binary of a module
        """
        self.path = path
        """Path to the binary"""

        self._radare = None
        self._radare_cache = {}

    def get_name(self) -> str:
        """
        Get the name of the binary
        """
        return basename(self.path)
    
    def _r2_run(self, callback: Callable[[], None]):
        """ 
        Opens the file in radare2, calls the callback when radare2 is initialized and then closes radare2
        :param callback: callback to call when radare2 is initialized
        :return: True if radare2 was initialized successfully, False otherwise
        """
        if self.path is None:
            # No binary for this module
            return False

        try:
            attempt = 0
            while True:
                try:
                    if os.name == "nt":
                        self._radare = r2pipe.open(self.path, flags=['-2'])
                    else:
                        self._radare = radare2.open_with_timeout_and_memlimit(Config().radare_server, self.path, timeout=Config().radare_timeout, mem_limit_gb=Config().radare_memory_limit, flags=['-2'])
                    break
                except BrokenPipeError as e:
                    attempt += 1
                    if attempt > 3:
                        raise e
                    else:
                        time.sleep(1)
            
            callback()

            return True
        except TimeoutError:
            logger.error(f'Error analyzing binary {self.path}: Timeout reached')
        except Exception as e:
            if ('Cannot open' in str(e)) :
                logger.error(f'Error analyzing binary {self.path}: Binary might be corrupt or memory limit was reached')
            else:
                logger.error(f'Error analyzing binary {self.path}: {e}')
                traceback.print_exc()

            return False
        finally:
            if self._radare is not None:
                self._radare.quit()
                self._radare = None
    
    def extract_strings(self) -> bool:
        """
        Extract all strings from the binary to a separate file
        :return: True if the strings were extracted successfully, False otherwise
        """
        strings_file = f'{self.path}.nativestrings'
        if exists(strings_file):
            return True

        def _extract_strings():
            strings = self.exec_r2_cmd('izj')
            if strings is None:
                return False

            strings = [s['string'] for s in strings]
            # Filter out false positives
            # We only keep strings which are mostly ascii and do not contain too many non-alphanumeric characters
            strings = [s for s in strings if len([c for c in s if ord(c) < 128]) > 0.9 * len(s) and len(set(c for c in s if not c.isalnum())) <= 0.5 * len(s)]
            strings = '\n'.join(strings)

            # Save strings in plaintext file for string analysis
            with open(strings_file, 'w') as f:
                f.write(strings)

            return True

        return self._r2_run(_extract_strings)

    def analyze_r2(self) -> bool:
        """ 
        Analyze the binary using radare2 and run through the detectors
        :return: True if the analysis was successful, False otherwise
        """
        def _analyze_r2():
            for detector in Detectors():
                try:
                    detector.static_analyze_r2(self)
                except Exception as e:
                    logger.error(f'Error running static analysis for {detector.get_id()} on {self.path}: {e}')
                    traceback.print_exc()
        
        return self._r2_run(_analyze_r2)

    def exec_r2_cmd(self, cmd: str) -> any:
        """
        Execute a radare command and return the result
        :param cmd: radare command to execute
        :return: result of the command, either a string or a decoded json object, or None if the command failed
        """
        if cmd in self._radare_cache:
            return self._radare_cache[cmd]

        logger.debug(f'Executing r2 {cmd}')

        if self._radare is None:
            raise Exception('Radare is not initialized, this function can only be used during an analyze() call')
        
        json_command = 'j' in cmd.split(' ')[0].split('~')[0]
        result = None
        try:
            if json_command:
                # JSON output
                result = self._radare.cmdj(cmd)
            else:
                # Plain text output
                result = self._radare.cmd(cmd)

            self._radare_cache[cmd] = result
        except TimeoutError:
            logger.error("Failed to execute r2 command: Timeout reached")
        except Exception as e:
            logger.error(f"Failed to execute r2 command: {e}")
            traceback.print_exc()

        return result

    def find_syscalls(self, syscall: str) -> list[dict]:
        """
        Find all calls to a syscall in the binary
        :param syscall: syscall to search for
        :return: list of offsets where the syscall is called with its argument values (if available)
        """
        addr = self.exec_r2_cmd(f'is~{syscall}[2]')
        if addr is None:
            return []

        return self._find_reference(addr)

    def find_objc_call(self, fun: str) -> list[dict]:
        """
        Find all references to a objective-c call in the binary
        :param fun: name of the function to search for
        :return: list of offsets where the function is used
        """
        if not Context().is_ios():
            return []
        
        results = self.exec_r2_cmd(f'izj')
        if results is None:
            return []
        addresses = []
        for result in results:
            if result['string'] == fun:
                if result['section'].endswith('__objc_methname'):
                    addresses.append(result['vaddr'])
                else:
                    logger.debug(f"Found Obj-C function {fun} outside methname section: {result['section']}")

        return self._find_reference(addresses, False)

    def _find_reference(self, addr: str | list[str], track_args: bool = True) -> list[dict]:
        """
        Find the references to the given address
        :param addr: address to find the references to
        :return: offset and args of the call
        """
        if isinstance(addr, str):
            addr = [a.strip() for a in addr.split('\n') if a.strip() != '']
        if len(addr) == 0:
            return []

        self.exec_r2_cmd('/ra') # Find references

        syscalls = []
        for a in addr:
            references = self.exec_r2_cmd(f'axtj {a}')

            if references is None or len(references) == 0:
                logger.debug(f'Found no references for {a}, appending as-is')
                syscalls.append({
                    'offset': a,
                    'args': []
                })
                continue

            for result in references:
                if 'from' not in result:
                    continue

                args = []
                if track_args and 'type' in result and result['type'] == 'CALL':
                    registry = self.get_registry_at(result['from'])
                    for i in range(0, 8):
                        if f'x{i}' in registry:
                            args.append(registry[f'x{i}'])
                        else:
                            args.append(None)

                syscalls.append({
                    'offset': result['from'],
                    'args': args
                })

        return syscalls

    def get_registry_at(self, address: int, lookback: int = 5) -> dict:
        """
        Looks at the instructions before the given address and interprets these instructions 
        to get the content of the registry at the given address
        :param address: address to get the registry at
        :param lookback: number of instructions to look back
        :return: dict with the registry name and the value
        """
        offset = address - lookback * 4
        registry = {}
        instructions = self.exec_r2_cmd(f'pdj 5 @ {offset}')
        if instructions is None:
            return registry
        instructions = [result['disasm'] for result in instructions if 'disasm' in result]

        for instruction in instructions:
            mov = re.match('mov (\S+), (\S+)', instruction)
            if not mov:
                continue

            value = mov.group(2).replace('w', 'x')
            if value[0:1] == 'x':
                if value in registry:
                    # Value of register
                    value = registry[value]
                elif value == 'xzr':
                    # Zero register
                    value = 0
                else:
                    # Value of register is unknown
                    continue
            else:
                # Try to decode value
                if value[0:2] == '0x':
                    try:
                        value = int(value, 16)
                    except ValueError:
                        pass
                try:
                    value = int(value)
                except ValueError:
                    pass
            registry[mov.group(1).replace('w', 'x')] = value

        return registry


            