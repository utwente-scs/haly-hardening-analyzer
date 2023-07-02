import { addJavaPostHook } from "../hooks/java";
import { addObjCPostHook } from "../hooks/objc";

// Pretend lockscreen is enabled
addJavaPostHook('android.app.KeyguardManager::isDeviceSecure', ['int'], (data) => {
    data.retval = true;
});

let checkFunctions = [
    'android.app.KeyguardManager::isKeyguardSecure',
    'android.app.admin.DevicePolicyManager::isActivePasswordSufficient',
    'android.app.admin.DevicePolicyManager::isActivePasswordSufficientForDeviceRequirement',
]
checkFunctions.forEach((fun) => {
    addJavaPostHook(fun, [], (data) => {
        data.retval = true;
    });
});

// Settings.Secure.getString(contentResolver, Settings.Secure.LOCK_PATTERN_ENABLED)
addJavaPostHook('android.provider.Settings$Secure::getString', ['android.content.ContentResolver', 'java.lang.String'], (data) => {
    if (data.args[1] == 'lock_pattern_autolock') {
        if (data.funName.includes('String')) {
            data.retval = '1';
        } else {
            data.retval = 1;
        }
    }
});

addObjCPostHook('-[LAContext canEvaluatePolicy:error:', 2, (data) => {
    data.retval.replace(Memory.alloc(4).writeUInt(1));
    data.args[1] = ptr(0);
});