import { addJavaPreHook } from "../hooks/java";
import { addObjCPreHook } from "../hooks/objc";
import { logJavaFunction, logObjCFunction } from "../inc/log";

addJavaPreHook([
    'android.view.inputmethod.InputMethodManager::getInputMethodList',
    'android.view.inputmethod.InputMethodManager::getEnabledInputMethodList'
], [], (data) => {
    logJavaFunction(data)
});

addJavaPreHook('android.provider.Settings$Secure::getString', ['android.content.ContentResolver', 'str'], (data) => {
    if (data.args[1] == 'enabled_input_methods' || data.args[1] == 'default_input_method') {
        logJavaFunction(data)
    }
});

addJavaPreHook('android.widget.EditText::setShowSoftInputOnFocus', ['boolean'], (data) => {
    if (data.args[0] == false) {
        logJavaFunction(data)
    }
});

addObjCPreHook('-[UIResponder textInputMode]', 0, (data) => {
    logObjCFunction(data)
});

addObjCPreHook('+[UITextInputMode activeInputModes]', 0, (data) => {
    logObjCFunction(data)
});

addObjCPreHook('-[UIView inputView]', 0, (data) => {
    logObjCFunction(data)
});