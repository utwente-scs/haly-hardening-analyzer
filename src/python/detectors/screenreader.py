from detectors.detector import Detector
from models.smali import Smali
from models.message import SmaliStaticMessage
from inc.tools.codesearch import search_smali

class ScreenreaderDetector(Detector):
    def get_id(self) -> str:
        return 'screenreader'

    def static_analyze_plaintext(self) -> None:
        # Check for SurfaceView.setSecure()
        signature = 'Landroid/view/SurfaceView;->setSecure(Z)V'
        for smali_file in search_smali(signature):
            for result in smali_file.find_call(signature):
                if len(result['args']) > 0 and result['args'][0] == 0:
                    continue
                self.static_results.append(SmaliStaticMessage(smali_file.file, 'android.view.SurfaceView::setSecure', result, len(result['args']) > 0 and result['args'][0] is not None))

        # Check for Window.setFlags()
        signature = 'Landroid/view/Window;->setFlags(II)V'
        for smali_file in search_smali(signature):
            for result in smali_file.find_call(signature):
                if len(result['args']) > 0 and result['args'][0] is not None:
                    # Check if FLAG_SECURE (0x2000) is set
                    if result['args'][0] & 0x2000 == 0:
                        continue
                if len(result['args']) > 1 and result['args'][1] is not None:
                    # Check if FLAG_SECURE (0x2000) is part of the mask
                    if result['args'][1] & 0x2000 == 0:
                        continue

                self.static_results.append(SmaliStaticMessage(smali_file.file, 'android.view.Window::setFlags', result, (len(result['args']) > 0 and result['args'][0] is not None) or (len(result['args']) > 1 and result['args'][1] is not None)))
