from detectors.detector import Detector
from functools import cache
from inc.context import Context
from inc.util import data_path, pattern_to_regex
from models.message import SmaliStaticMessage, StringStaticMessage
import pyjson5
import hashlib
from inc.tools.codesearch import search_plaintext, search_smali

class EmulationDetector(Detector):
    def get_id(self) -> str:
        return 'emulation'

    @cache
    def _get_data(self) -> dict:
        with open(data_path(f'detectors/emulation/emulation-{Context().get_os()}.json5'), 'r') as f:
            return pyjson5.decode_io(f)

    def _matches_emulator_build_prop(self, property: str, value: str) -> bool:
        """
        Check if a build property matches an emulator build property
        :param property: The build property to check
        :param value: The value of the build property
        :return: True if the build property matches an emulator build property, False otherwise
        """
        data = self._get_data()
        value = str(value).lower()

        if property not in data['build']:
            return False

        result = any(x in value for x in data['build'][property])
        return result

    def static_analyze_plaintext(self) -> None:
        if 'static' in self._get_data():
            for text in self._get_data()['static']:
                for result in search_plaintext(text):
                    self.static_results.append(StringStaticMessage(result['source'], text, result))

        signature = 'Landroid/os/Build;->'
        for smali_file in search_smali(signature):
            for result in smali_file.find_call(signature, 'object', True):
                field = result['line'].split('->')[1].split(':')[0]
                result['comparisons'] = [c for c in result['comparisons'] if self._matches_emulator_build_prop(field, c['value'])]
                if len(result['comparisons']) == 0:
                    continue

                self.static_results.append(SmaliStaticMessage(smali_file.file, f'android.os.Build::{field}', result))

        for file in self._get_data()['files']:
            for result in search_plaintext(pattern_to_regex(file)):
                self.static_results.append(StringStaticMessage(result['source'], file, result))

        if Context().app.os == 'ios':
            for env_name in self._get_data()['environment']:
                for result in search_plaintext(pattern_to_regex(env_name)):
                    self.static_results.append(StringStaticMessage(result['source'], env_name, result))

    def dynamic_get_data(self) -> dict:
        data = self._get_data()
        retval = {
            'files': data['files'],
        }
        if Context().app.os == 'android':
            retval['build'] = { hashlib.md5(prop.encode()).hexdigest(): prop for prop in data['build'].keys() }
        elif Context().app.os == 'ios':
            retval['environment'] = data['environment']
        return {
            'emulation': retval
        }
