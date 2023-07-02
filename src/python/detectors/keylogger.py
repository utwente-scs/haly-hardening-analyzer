from detectors.detector import Detector
from models.message import SmaliStaticMessage, NativeFunctionStaticMessage
from inc.tools.codesearch import search_smali
from models.nativebinary import NativeBinary

class KeyloggerDetector(Detector):
    def get_id(self) -> str:
        return 'keylogger'

    def static_analyze_r2(self, binary: NativeBinary) -> None:
        # Check for UIResponder.textInputMode
        for result in binary.find_objc_call('textInputMode'):
            self.static_results.append(NativeFunctionStaticMessage(binary.path, 'UIResponder::textInputMode', result))

        # Check for UITextInputMode.activeInputModes
        for result in binary.find_objc_call('activeInputModes'):
            self.static_results.append(NativeFunctionStaticMessage(binary.path, 'UITextInputMode::activeInputModes', result))
    
        # Check for UIView.inputView assignments
        for result in binary.find_objc_call('setInputView'):
            self.static_results.append(NativeFunctionStaticMessage(binary.path, 'UIView::inputView', result))

    def static_analyze_plaintext(self) -> None:
        # Check for InputMethodManager.get(Enabled)InputMethodList()
        for function in ['getInputMethodList', 'getEnabledInputMethodList']:
            signature = f'Landroid/view/inputmethod/InputMethodManager;->{function}()Ljava/util/List;'
            for smali_file in search_smali(signature):
                for result in smali_file.find_call(signature):
                    self.static_results.append(SmaliStaticMessage(smali_file.file, f'android.view.inputmethod.InputMethodManager::{function}', result))

        # Check for Settings.Secure.getString(contentResolver, Settings.Secure.ENABLED_INPUT_METHODS | Settings.Secure.DEFAULT_INPUT_METHOD)
        signature =  'Landroid/provider/Settings$Secure;->getString(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;'
        for smali_file in search_smali(signature):
            for result in smali_file.find_call(signature):
                if len(result['args']) > 1 and result['args'][1] is not None:
                    if result['args'][1] not in ['enabled_input_methods', 'default_input_method']:
                        continue

                self.static_results.append(SmaliStaticMessage(smali_file.file, 'android.provider.Settings$Secure::getString', result, len(result['args']) > 1 and result['args'][1] is not None))

        # Check for EditText.setShowSoftInputOnFocus()
        signature = 'Landroid/widget/EditText;->setShowSoftInputOnFocus(Z)V'
        for smali_file in search_smali(signature):
            for result in smali_file.find_call(signature):
                if len(result['args']) > 0 and result['args'][0] == 1:
                    continue

                self.static_results.append(SmaliStaticMessage(smali_file.file, 'android.widget.EditText::setShowSoftInputOnFocus', result, len(result['args']) > 0 and result['args'][0] is not None))
