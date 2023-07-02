from os.path import dirname, basename, join, exists
import glob
import importlib.util
import inspect
from detectors.detector import Detector
from functools import cache
import frida.core
from inc.context import Context
from models.message import StaticMessage, DynamicMessage
import json
import logging
from intervaltree import IntervalTree

logger = logging.getLogger('hardeninganalyzer')

@cache # Singleton
class Detectors():
    def __init__(self):
        self._detectors = {}
        self._import()

    def _import(self) -> None:
        """
        Import all detectors from the detectors folder.
        """
        for file in glob.glob(join(dirname(__file__), '../detectors/*.py')):
            if file.endswith(('__init__.py', 'detector.py')):
                # Skip detector base class and this file
                continue

            module_name = basename(file)[:-3]
            spec = importlib.util.spec_from_file_location(module_name, file)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            static_results = None
            if Context().stage == 'dynamic':
                static_results_path = Context().app.get_static_result_path()
                if not exists(static_results_path):
                    raise FileNotFoundError(f'Static results not found at {static_results_path}. Static results are required for dynamic analysis.')

                with open(static_results_path, 'r') as f:
                    static_results = json.load(f)

            for member in inspect.getmembers(module, inspect.isclass):
                if member[1].__module__ == module_name and issubclass(member[1], Detector):
                    # Found a detector, construct it
                    detector = member[1]()

                    if static_results is not None and detector.get_id() in static_results:
                        # Import static results
                        detector.static_results = static_results[detector.get_id()]

                    self._detectors[detector.get_id()] = detector

    def __getitem__(self, item) -> Detector:
        """
        Get a detector by its ID
        :param item: The ID of the detector
        """
        return self._detectors[item]

    def __iter__(self) -> iter:
        """
        Iterate over all detectors
        """
        return iter(self._detectors.values())

    def __len__(self) -> int:
        """
        Get the number of detectors
        """
        return len(self._detectors)

    def dynamic_get_data(self) -> dict:
        """
        During dynamic analysis, get data to send to the app
        :return: Data to send to the app
        """
        data = {}
        for detector in self:
            data.update(detector.dynamic_get_data())
        return data

    def dynamic_handle_message(self, message: DynamicMessage) -> None:
        """
        Handle a Frida message
        :param message: The message to handle
        """
        message_handled = False
        for detector in self:
            if message.detector is None or message.detector == detector.get_id():
                # Only send message to relevant detectors, or to all if no detector is specified
                message_handled = message_handled or detector.dynamic_handle_message(message)

        if not message_handled:
            message_data = message.to_dict()
            message_data['detector'] = message.detector
            logger.debug(f"Unhandled frida message: {message_data}")

    def dynamic_instrument(self, script: frida.core.Script, is_main_process: bool) -> None:
        """
        Instrument the Frida script
        """
        for detector in self:
            detector.dynamic_instrument(script, is_main_process)

    def dynamic_before_analysis(self):
        """
        Runs just before starting the application for dynamic analysis
        """
        for detector in self:
            detector.dynamic_before_analysis()

    def dynamic_after_analysis(self):
        """
        Runs just after the application has run for dynamic analysis
        """
        for detector in self:
            detector.dynamic_after_analysis()

    def get_static_results(self) -> dict:
        """
        Get the results of all the detectors
        """
        results = {}
        for detector in self:
            if Context().stage == 'static':
                i_results = detector.static_results
                results[detector.get_id()] = self._static_filter_libraries(i_results)
            else:
                results[detector.get_id()] = detector.static_results
        return results

    def get_dynamic_results(self) -> dict:
        """
        Get the results of all the detectors
        """
        modules = IntervalTree()
        for module in Context().modules:
            base = int(module['base'], 16)
            modules[base:base+module['size']] = module

        results = {}
        for detector in self:
            results[detector.get_id()] = self._dynamic_filter_libraries(self._enhance_backtrace(detector.dynamic_results, modules))
        return results

    def _enhance_backtrace(self, results: any, modules: IntervalTree) -> any:
        """
        Enhance the backtrace of the results with module names
        :param results: The results to enhance
        :param modules: A list of modules and their addresses
        """
        if not isinstance(results, list):
            return results

        for item in results:
            if not isinstance(item, DynamicMessage) or item.context not in ['native', 'objc']:
                continue

            new_backtrace = []
            for addr in item.backtrace:
                module = list(modules[int(addr, 16)])
                if len(module) > 0:
                    new_backtrace.append({
                        'address': addr,
                        'module': module[0].data['name']
                    })
                else:
                    new_backtrace.append({
                        'address': addr,
                        'module': None
                    })
            item.backtrace = new_backtrace

        return results
    
    def _static_filter_libraries(self, messages: list[StaticMessage]) -> list[StaticMessage]:
        """
        Filter out static results of internal libraries
        :param messages: The messages to filter
        :return: The filtered messages
        """
        if not isinstance(messages, list):
            return messages
        
        filtered_messages = []

        for message in messages:
            if '/smali' in message.source:
                source = message.source.split('/smali')[1].split('/', 1)[1]

                if not any(source.startswith(library) for library in ['android/', 'androidx/']):
                    filtered_messages.append(message)
            else:
                filtered_messages.append(message)

        return filtered_messages
    
    def _dynamic_filter_libraries(self, messages: list[DynamicMessage]) -> list[DynamicMessage]:
        """
        Filter out dynamic results of internal libraries
        :param messages: The messages to filter
        :return: The filtered messages
        """
        if not isinstance(messages, list):
            return messages
        
        filtered_messages = []

        for message in messages:
            if not self._backtrace_okay(message):
                continue

            filtered_messages.append(message)

        return filtered_messages
    
    def _backtrace_okay(self, message: DynamicMessage) -> bool:
        """
        Check if the backtrace of a message indicates an internal call
        :param message: The message to check
        :return: True if the backtrace is okay, False otherwise
        """
        try:

            if message.context == 'java':
                # Java backtrace
                if message.backtrace[1] == 'android.app.Activity.onCreate(Native Method)':
                    # Call from Frida (frida/detectors/info.ts)
                    return False
            else:
                # Native backtrace
                if message.backtrace[0]['module'] == 'frida-agent-64.so':
                    # Call from Frida
                    return False
                
                if message.backtrace[0]['module'] == 'libxpc.dylib' and message.type == 'file' and message.file == '/private':
                    return False
                
                if message.backtrace[0]['module'] == 'libsystem_trace.dylib' and message.type == 'function' and message.function == 'sysctl':
                    return False
                
                if message.backtrace[0]['module'] == 'BaseBoard' and message.type == 'function' and message.function == '-[NSProcessInfo environment]':
                    return False
                
                if message.type == 'file' and message.file.startswith('/proc/') and all(trace['module'] in ['libc.so', 'libart.so', 'boot.oat', 'frida-agent-64.so'] for trace in message.backtrace):
                    # Probably an internal call from Android
                    message.confident = False
                
            return True
        except IndexError:
            return True

                 