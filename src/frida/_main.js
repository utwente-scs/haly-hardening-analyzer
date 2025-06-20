/******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ "./src/frida/detectors/debug.ts":
/*!**************************************!*\
  !*** ./src/frida/detectors/debug.ts ***!
  \**************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";

var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
exports.__esModule = true;
var java_1 = __webpack_require__(/*! ../hooks/java */ "./src/frida/hooks/java.ts");
var native_1 = __webpack_require__(/*! ../hooks/native */ "./src/frida/hooks/native.ts");
var log_1 = __webpack_require__(/*! ../inc/log */ "./src/frida/inc/log.ts");
(0, java_1.addJavaPostHook)('android.os.Debug::isDebuggerConnected', [], function (data) {
    (0, log_1.logJavaFunction)(data);
    data.retval = false;
});
(0, java_1.addJavaPostHook)('android.os.Debug::waitingForDebugger', [], function (data) {
    (0, log_1.logJavaFunction)(data);
    data.retval = false;
});
// We don't hook ContextWrapper.getApplicationInfo() because it would cause a lot of false positives
// and make the app unresponsive, even though it could be used to check the app for FLAG_DEBUGGABLE
(0, java_1.addJavaPostHook)('android.provider.Settings$Secure::getString', ['android.content.ContentResolver', 'str'], function (data) {
    if (['adb_enabled', 'development_settings_enabled', 'mock_location'].includes(data.args[1])) {
        (0, log_1.logJavaFunction)(data);
        if (data.funName.includes('String')) {
            data.retval = '0';
        }
        else {
            data.retval = 0;
        }
    }
});
(0, native_1.addPreHook)('ptrace', ['int', 'int', 'int', 'int'], function (data) {
    (0, log_1.logFunction)(data);
    // No need to patch value, we don't use tracing
});
if (Process.platform == 'darwin') {
    (0, native_1.addPreHook)('sysctl', ['ptr', 'uint', 'ptr', 'uint', 'ptr', 'uint'], function (data) {
        var mib = data.args[0];
        var ctl = mib.readU32();
        var kern = mib.add(4).readU32();
        var kernProc = mib.add(8).readU32();
        var kernProcPid = mib.add(12).readU32();
        if (ctl == 1 && kern == 14 && kernProc == 1) { // 1 = CTL_KERN, 14 = KERN_PROC, 1 = KERN_PROC_PID
            // https://msolarana.netlify.app/2018/09/14/anti-debugging/#using-sysctl
            // Returned value can be checked for P_TRACED flag
            var logArgs = [[ctl, kern, kernProc, kernProcPid]].concat(data.args.slice(1));
            (0, log_1.logFunction)(__assign(__assign({}, data), { args: logArgs }), false);
            // No need to patch return value, we don't use tracing
        }
    });
    (0, native_1.addPostHook)('getppid', [], function (data) {
        (0, log_1.logFunction)(data);
        // Parent process id should always be 1 (launchd)
        data.retval.replace(1);
    });
}


/***/ }),

/***/ "./src/frida/detectors/emulation.ts":
/*!******************************************!*\
  !*** ./src/frida/detectors/emulation.ts ***!
  \******************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

exports.__esModule = true;
var file_1 = __webpack_require__(/*! ../hooks/file */ "./src/frida/hooks/file.ts");
var native_1 = __webpack_require__(/*! ../hooks/native */ "./src/frida/hooks/native.ts");
var log_1 = __webpack_require__(/*! ../inc/log */ "./src/frida/inc/log.ts");
var objc_1 = __webpack_require__(/*! ../hooks/objc */ "./src/frida/hooks/objc.ts");
// Hide blacklisted files
file_1.FileHooks.getInstance().accessFileHook(file_1.FilePattern.from(__webpack_require__.g.context.emulation.files), true);
// We cannot hook Build.{field} because it is not a method
// We could approach this using taint analysis by setting the Build fields to a unique value
// and check if these values are used in e.g. String.equals(), however this is slows down the app too much
if (Process.platform == 'darwin') {
    var simulatorEnvs_1 = __webpack_require__.g.context.emulation.environment;
    (0, native_1.addPreHook)('getenv', ['str'], function (data) {
        if (simulatorEnvs_1.indexOf(data.args[0]) >= 0) {
            (0, log_1.logFunction)(data);
        }
    }, 'libsystem_c.dylib');
    (0, objc_1.addObjCPreHook)('-[NSProcessInfo environment]', 0, function (data) {
        // Since this returns an NSArray of environment variables, we cannot be sure
        // if these environment variables are checked for simulator environment variables
        (0, log_1.logObjCFunction)(data, false);
    });
}


/***/ }),

/***/ "./src/frida/detectors/hooking.ts":
/*!****************************************!*\
  !*** ./src/frida/detectors/hooking.ts ***!
  \****************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";

var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
exports.__esModule = true;
var apps_1 = __webpack_require__(/*! ../hooks/apps */ "./src/frida/hooks/apps.ts");
var file_1 = __webpack_require__(/*! ../hooks/file */ "./src/frida/hooks/file.ts");
var native_1 = __webpack_require__(/*! ../hooks/native */ "./src/frida/hooks/native.ts");
var java_1 = __webpack_require__(/*! ../hooks/java */ "./src/frida/hooks/java.ts");
var log_1 = __webpack_require__(/*! ../inc/log */ "./src/frida/inc/log.ts");
var util_1 = __webpack_require__(/*! ../inc/util */ "./src/frida/inc/util.ts");
var socket_1 = __webpack_require__(/*! ../hooks/socket */ "./src/frida/hooks/socket.ts");
var fileHooks = file_1.FileHooks.getInstance();
var appsHooks = apps_1.AppsHooks.getInstance();
var filesPattern = file_1.FilePattern.from(__webpack_require__.g.context.hooking.files);
// Hide blacklisted files
fileHooks.accessFileHook(filesPattern, true);
appsHooks.blacklistAppsHook(__webpack_require__.g.context.hooking.apps);
// Hook _dyld_get_image_name
(0, native_1.addPostHook)('_dyld_get_image_name', ['int'], function (data) {
    if (data.args[0] == 0) {
        // Main app binary, always queried on app startup
        return;
    }
    var imageName = data.retval.isNull() ? null : data.retval.readUtf8String();
    var matches = imageName && filesPattern.some(function (item) { return item.matches(imageName); });
    if (matches) {
        data.retval.replace(Memory.allocUtf8String('nonexistentlib.dylib'));
    }
    (0, log_1.logFunction)(__assign(__assign({}, data), { args: [
            data.args[0],
            imageName
        ] }), false);
});
(0, native_1.addPostHook)('_dyld_image_count', [], function (data) {
    (0, log_1.logFunction)(data, false);
});
if (Java.available) {
    Java.perform(function () {
        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                [['str'], ['str', 'bool']].forEach(function (argTypes) {
                    (0, java_1.addJavaPreHook)(loader.loadClass, argTypes, function (data) {
                        // Check for attempts to load e.g. de.robv.android.xposed.XposedBridge
                        __webpack_require__.g.context.hooking.apps.forEach(function (app) {
                            if (data.args[0].toLowerCase().includes(app)) {
                                (0, log_1.logJavaFunction)(data);
                            }
                        });
                    }, false);
                });
            },
            onComplete: function () { }
        });
    });
}
// Add port hook for default Frida port (27042)
(0, socket_1.addOpenPortHook)(27042);
if (Java.available) {
    Java.perform(function () {
        // Hide Frida from /proc/<pid>/maps since tempFileNaming prefix can end up in maps.
        // https://github.com/sensepost/objection/blob/f47926e90ce8b6655ecb431730b6674e41bc5625/agent/src/android/pinning.ts#L43
        // https://github.com/frida/frida-java-bridge/blob/8b3790f7489ff5be7b19ddaccf5149d4e7738460/lib/class-factory.js#L94
        if (Java.classFactory.tempFileNaming.prefix == 'frida') {
            Java.classFactory.tempFileNaming.prefix = 'hardeninganalyzer';
        }
    });
}
// Modify /proc/<pid>/maps files
fileHooks.replaceFileHook('/proc/', 'maps', function (filename) {
    var maps = (0, util_1.readFile)(filename);
    if (maps == null) {
        (0, log_1.warn)("Failed to read " + filename);
        return null;
    }
    var modifiedMaps = '';
    for (var _i = 0, _a = maps.split('\n'); _i < _a.length; _i++) {
        var line = _a[_i];
        // Remove traces of frida from maps
        if (line.includes('frida'))
            continue;
        line = line.replace('rwxp', 'r-xp');
        modifiedMaps += line + '\n';
    }
    return modifiedMaps;
}, false);
// Modify /proc/<pid>/task/<tid>/status files
fileHooks.replaceFileHook('/proc/', 'status', function (filename) {
    var maps = (0, util_1.readFile)(filename);
    if (maps == null) {
        (0, log_1.warn)("Failed to read " + filename);
        return null;
    }
    var modifiedMaps = '';
    for (var _i = 0, _a = maps.split('\n'); _i < _a.length; _i++) {
        var line = _a[_i];
        // Remove traces of frida from thread names
        line = line.replace('gmain', 'Thread-1');
        line = line.replace('gum-js-loop', 'Thread-1');
        line = line.replace('gdbus', 'Thread-1');
        line = line.replace('linjector', 'Thread-1');
        line = line.replace('pool-spawner', 'Thread-1');
        line = line.replace('pool-frida', 'Thread-1');
        line = line.replace('frida-server', 'Thread-1');
        line = line.replace('frida_agent_main', 'Thread-1');
        line = line.replace('frida', 'Thread-1');
        modifiedMaps += line + '\n';
    }
    return modifiedMaps;
}, false);


/***/ }),

/***/ "./src/frida/detectors/info.ts":
/*!*************************************!*\
  !*** ./src/frida/detectors/info.ts ***!
  \*************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

var _a, _b, _c, _d, _e, _f, _g, _h;
exports.__esModule = true;
var java_1 = __webpack_require__(/*! ../hooks/java */ "./src/frida/hooks/java.ts");
(0, java_1.addJavaPreHook)('android.app.Activity::onCreate', ['android.os.Bundle'], function (data) {
    if (__webpack_require__.g.safeMode == 'yes')
        return;
    var packageName = data["this"].getPackageName();
    var pm = data["this"].getPackageManager();
    var packageInfo = pm.getPackageInfo(packageName, 0);
    var appInfo = data["this"].getApplicationInfo();
    var labelRes = appInfo.labelRes.value;
    var launchIntent = pm.getLaunchIntentForPackage(packageName);
    var info = {
        type: 'info',
        detector: 'info',
        info: {
            name: labelRes ? data["this"].getString(labelRes) : appInfo.nonLocalizedLabel.value,
            package: packageName,
            version_code: packageInfo.versionCode.value,
            version_name: packageInfo.versionName.value,
            min_sdk: appInfo.minSdkVersion.value,
            main_activity: launchIntent ? launchIntent.getComponent().getClassName() : null,
            permissions: pm.getPackageInfo(packageName, 4096).requestedPermissions.value
        }
    };
    send(info);
});
if (ObjC.available) {
    var infoDict = ObjC.classes.NSBundle.mainBundle().infoDictionary();
    var info = {
        type: 'info',
        detector: 'info',
        info: {
            name: ((_a = infoDict.objectForKey_("CFBundleDisplayName")) === null || _a === void 0 ? void 0 : _a.toString()) || ((_b = infoDict.objectForKey_("CFBundleName")) === null || _b === void 0 ? void 0 : _b.toString()),
            package: (_c = infoDict.objectForKey_("CFBundleIdentifier")) === null || _c === void 0 ? void 0 : _c.toString(),
            executable: (_d = infoDict.objectForKey_("CFBundleExecutable")) === null || _d === void 0 ? void 0 : _d.toString(),
            version_code: (_e = infoDict.objectForKey_("CFBundleVersion")) === null || _e === void 0 ? void 0 : _e.toString(),
            version_name: (_f = infoDict.objectForKey_("CFBundleShortVersionString")) === null || _f === void 0 ? void 0 : _f.toString(),
            min_sdk: (_g = infoDict.objectForKey_("MinimumOSVersion")) === null || _g === void 0 ? void 0 : _g.toString(),
            main_activity: (_h = infoDict.objectForKey_("UILaunchStoryboardName")) === null || _h === void 0 ? void 0 : _h.toString()
        }
    };
    send(info);
}


/***/ }),

/***/ "./src/frida/detectors/keylogger.ts":
/*!******************************************!*\
  !*** ./src/frida/detectors/keylogger.ts ***!
  \******************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

exports.__esModule = true;
var java_1 = __webpack_require__(/*! ../hooks/java */ "./src/frida/hooks/java.ts");
var objc_1 = __webpack_require__(/*! ../hooks/objc */ "./src/frida/hooks/objc.ts");
var log_1 = __webpack_require__(/*! ../inc/log */ "./src/frida/inc/log.ts");
(0, java_1.addJavaPreHook)([
    'android.view.inputmethod.InputMethodManager::getInputMethodList',
    'android.view.inputmethod.InputMethodManager::getEnabledInputMethodList'
], [], function (data) {
    (0, log_1.logJavaFunction)(data);
});
(0, java_1.addJavaPreHook)('android.provider.Settings$Secure::getString', ['android.content.ContentResolver', 'str'], function (data) {
    if (data.args[1] == 'enabled_input_methods' || data.args[1] == 'default_input_method') {
        (0, log_1.logJavaFunction)(data);
    }
});
(0, java_1.addJavaPreHook)('android.widget.EditText::setShowSoftInputOnFocus', ['boolean'], function (data) {
    if (data.args[0] == false) {
        (0, log_1.logJavaFunction)(data);
    }
});
(0, objc_1.addObjCPreHook)('-[UIResponder textInputMode]', 0, function (data) {
    (0, log_1.logObjCFunction)(data);
});
(0, objc_1.addObjCPreHook)('+[UITextInputMode activeInputModes]', 0, function (data) {
    (0, log_1.logObjCFunction)(data);
});
(0, objc_1.addObjCPreHook)('-[UIView inputView]', 0, function (data) {
    (0, log_1.logObjCFunction)(data);
});


/***/ }),

/***/ "./src/frida/detectors/lockscreen.ts":
/*!*******************************************!*\
  !*** ./src/frida/detectors/lockscreen.ts ***!
  \*******************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

exports.__esModule = true;
var java_1 = __webpack_require__(/*! ../hooks/java */ "./src/frida/hooks/java.ts");
var objc_1 = __webpack_require__(/*! ../hooks/objc */ "./src/frida/hooks/objc.ts");
// Pretend lockscreen is enabled
(0, java_1.addJavaPostHook)('android.app.KeyguardManager::isDeviceSecure', ['int'], function (data) {
    data.retval = true;
});
var checkFunctions = [
    'android.app.KeyguardManager::isKeyguardSecure',
    'android.app.admin.DevicePolicyManager::isActivePasswordSufficient',
    'android.app.admin.DevicePolicyManager::isActivePasswordSufficientForDeviceRequirement',
];
checkFunctions.forEach(function (fun) {
    (0, java_1.addJavaPostHook)(fun, [], function (data) {
        data.retval = true;
    });
});
// Settings.Secure.getString(contentResolver, Settings.Secure.LOCK_PATTERN_ENABLED)
(0, java_1.addJavaPostHook)('android.provider.Settings$Secure::getString', ['android.content.ContentResolver', 'java.lang.String'], function (data) {
    if (data.args[1] == 'lock_pattern_autolock') {
        if (data.funName.includes('String')) {
            data.retval = '1';
        }
        else {
            data.retval = 1;
        }
    }
});
(0, objc_1.addObjCPostHook)('-[LAContext canEvaluatePolicy:error:', 2, function (data) {
    data.retval.replace(Memory.alloc(4).writeUInt(1));
    data.args[1] = ptr(0);
});


/***/ }),

/***/ "./src/frida/detectors/pinning.ts":
/*!****************************************!*\
  !*** ./src/frida/detectors/pinning.ts ***!
  \****************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

exports.__esModule = true;
var java_1 = __webpack_require__(/*! ../hooks/java */ "./src/frida/hooks/java.ts");
var native_1 = __webpack_require__(/*! ../hooks/native */ "./src/frida/hooks/native.ts");
var objc_1 = __webpack_require__(/*! ../hooks/objc */ "./src/frida/hooks/objc.ts");
var log_1 = __webpack_require__(/*! ../inc/log */ "./src/frida/inc/log.ts");
////////////////////////////
// Android Pinning bypass //
////////////////////////////
// https://github.com/NEU-SNS/app-tls-pinning/blob/b0469990ad37c3068c227a44aa5f5bfb824ec3f7/code/certificate-pinning/DynamicAnalysis/frida/bypass_all_pinning.js
// TrustManager (Android < 7)
if (Java.available) {
    Java.perform(function () {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var TrustManager = Java.registerClass({
            // Implement a custom TrustManager
            name: 'nl.wilcovanbeijnum.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) { },
                checkServerTrusted: function (chain, authType) { },
                getAcceptedIssuers: function () { return []; }
            }
        });
        var trustManagers = [TrustManager.$new()];
        (0, java_1.addJavaPreHook)('javax.net.ssl.SSLContext::init', ['[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'], function (data) {
            // Override the init method, specifying the custom TrustManager
            data.args[1] = trustManagers;
            (0, log_1.logJavaFunction)(data, false);
        }, false);
    });
}
var returnVoidHook = function (data, confident) {
    if (confident === void 0) { confident = true; }
    (0, log_1.logJavaFunction)(data, confident);
};
var returnTrueHook = function (data, confident) {
    if (confident === void 0) { confident = true; }
    (0, log_1.logJavaFunction)(data, confident);
    return true;
};
var okhttp3Pins = function (data) {
    if (data["this"].findMatchingPins) {
        return data["this"].findMatchingPins(data.args[0]).size() > 0;
    }
    else if (data["this"].getPins) {
        return data["this"].getPins().size() > 0;
    }
    else {
        return false;
    }
};
// OkHTTPv3
(0, java_1.addJavaReplaceHook)('okhttp3.CertificatePinner::check', ['str', 'java.util.List'], function (data) { return returnVoidHook(data, okhttp3Pins(data)); });
(0, java_1.addJavaReplaceHook)('okhttp3.CertificatePinner::check', ['str', 'java.security.cert.Certificate'], function (data) { return returnVoidHook(data, okhttp3Pins(data)); });
(0, java_1.addJavaReplaceHook)('okhttp3.CertificatePinner::check', ['str', 'str'], function (data) {
    (0, log_1.logJavaFunction)(data, okhttp3Pins(data));
    return data.args[1];
});
(0, java_1.addJavaReplaceHook)('okhttp3.CertificatePinner::check', ['str', 'kotlin.jvm.functions.Function0'], function (data) { return returnVoidHook(data, data["this"].getPins().size() > 0); });
// Trustkit
(0, java_1.addJavaReplaceHook)('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier::verify', ['str', 'javax.net.ssl.SSLSession'], function (data) { return returnTrueHook(data, false); });
(0, java_1.addJavaReplaceHook)('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier::verify', ['str', 'java.security.cert.X509Certificate'], function (data) { return returnTrueHook(data, false); });
(0, java_1.addJavaReplaceHook)('com.datatheorem.android.trustkit.pinning.PinningTrustManager::checkServerTrusted', ['[Ljava.security.cert.X509Certificate;', 'str'], function (data) { return returnVoidHook(data, data["this"].serverConfig.shouldEnforcePinning()); });
// TrustManagerImpl (Android > 7)
(0, java_1.addJavaReplaceHook)('com.android.org.conscrypt.TrustManagerImpl::verifyChain', ['[Ljava.security.cert.X509Certificate;', '[Ljava.security.cert.TrustAnchor;', 'str', 'boolean', '[B', '[B'], function (data) {
    (0, log_1.logJavaFunction)(data, data.args[1].length > 0);
    return data.args[0];
});
// Appcelerator Titanium PinningTrustManager
(0, java_1.addJavaReplaceHook)('appcelerator.https.PinningTrustManager::checkServerTrusted', ['[Ljava.security.cert.X509Certificate;', 'str'], function (data) { return returnVoidHook(data, false); });
// Fabric PinningTrustManager
(0, java_1.addJavaReplaceHook)('io.fabric.sdk.android.services.network.PinningTrustManager::checkServerTrusted', ['[Ljava.security.cert.X509Certificate;', 'str'], function (data) { return returnVoidHook(data, data["this"].pins.size() > 0); });
// Conscrypt OpenSSLSocketImpl
(0, java_1.addJavaReplaceHook)('com.android.org.conscrypt.OpenSSLSocketImpl::verifyCertificateChain', ['[J', 'str'], function (data) { return returnVoidHook(data, false); });
// Conscrypt OpenSSLEngineSocketImpl
(0, java_1.addJavaReplaceHook)('com.android.org.conscrypt.OpenSSLEngineSocketImpl::verifyCertificateChain', ['[J', 'str'], function (data) { return returnVoidHook(data, false); });
// Apache Harmony OpenSSLSocketImpl
(0, java_1.addJavaReplaceHook)('org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl::verifyCertificateChain', ['[[B', 'str'], function (data) { return returnVoidHook(data, false); });
// PhoneGap sslCertificateChecker
(0, java_1.addJavaReplaceHook)('nl.xservices.plugins.sslCertificateChecker::execute', ['str', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext'], function (data) { return returnTrueHook(data, data.args[1].getJSONArray(2).length() > 0); });
// IBM MobileFirst WLClient
(0, java_1.addJavaReplaceHook)('com.worklight.wlclient.api.WLClient::pinTrustedCertificatePublicKey', ['str'], returnVoidHook);
(0, java_1.addJavaReplaceHook)('com.worklight.wlclient.api.WLClient::pinTrustedCertificatePublicKey', ['str[]'], returnVoidHook);
// IBM WorkLight HostNameVerifierWithCertificatePinning
(0, java_1.addJavaReplaceHook)('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning::verify', ['str', 'javax.net.ssl.SSLSocket'], function (data) { return returnVoidHook(data, false); });
(0, java_1.addJavaReplaceHook)('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning::verify', ['str', 'java.security.cert.X509Certificate'], function (data) { return returnVoidHook(data, false); });
(0, java_1.addJavaReplaceHook)('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning::verify', ['str[]', 'str[]'], function (data) { return returnVoidHook(data, false); });
(0, java_1.addJavaReplaceHook)('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning::verify', ['str', 'javax.net.ssl.SSLSession'], function (data) { return returnTrueHook(data, false); });
// Conscrypt CertPinManager
(0, java_1.addJavaReplaceHook)('org.conscrypt.CertPinManager::checkChainPinning', ['str', 'java.util.List'], returnVoidHook);
// Conscrypt CertPinManager (Legacy)
(0, java_1.addJavaReplaceHook)('org.conscrypt.CertPinManager::isChainValid', ['str', 'java.util.List'], function (data) { return returnTrueHook; });
// CWAC-Netsecurity CertPinManager
(0, java_1.addJavaReplaceHook)('com.commonsware.cwac.netsecurity.conscrypt.CertPinManager::isChainValid', ['str', 'java.util.List'], returnTrueHook);
// Worklight Androidgap WLCertificatePinningPlugin
(0, java_1.addJavaReplaceHook)('com.worklight.androidgap.plugin.WLCertificatePinningPlugin::execute', ['str', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext'], returnTrueHook);
// Netty FingerprintTrustManagerFactory
(0, java_1.addJavaReplaceHook)('io.netty.handler.ssl.util.FingerprintTrustManagerFactory::checkTrusted', ['str', '[Ljava.security.cert.X509Certificate;'], function (data) { return returnVoidHook(data, data["this"].fingerprints.length > 0); });
// Squareup CertificatePinner
(0, java_1.addJavaReplaceHook)('com.squareup.okhttp.CertificatePinner::check', ['str', '[Ljava.security.cert.Certificate;'], function (data) { return returnVoidHook(data, data["this"].hostnameToPins.get(data.args[0]) != null); });
(0, java_1.addJavaReplaceHook)('com.squareup.okhttp.CertificatePinner::check', ['str', 'java.util.List'], function (data) { return returnVoidHook(data, data["this"].hostnameToPins.get(data.args[0]) != null); });
// Squareup OkHostnameVerifier
(0, java_1.addJavaReplaceHook)('com.squareup.okhttp.internal.tls.OkHostnameVerifier::verify', ['str', 'java.security.cert.X509Certificate'], function (data) { return returnTrueHook(data, false); });
(0, java_1.addJavaReplaceHook)('com.squareup.okhttp.internal.tls.OkHostnameVerifier::verify', ['str', 'javax.net.ssl.SSLSession'], function (data) { return returnTrueHook(data, false); });
// Android WebViewClient
(0, java_1.addJavaReplaceHook)('android.webkit.WebViewClient::onReceivedSslError', ['android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError'], function (data) { return returnVoidHook(data, false); });
(0, java_1.addJavaReplaceHook)('android.webkit.WebViewClient::onReceivedSslError', ['android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError'], function (data) { return returnVoidHook(data, false); });
(0, java_1.addJavaReplaceHook)('android.webkit.WebViewClient::onReceivedError', ['android.webkit.WebView', 'int', 'str', 'str'], function (data) { return returnVoidHook(data, false); });
(0, java_1.addJavaReplaceHook)('android.webkit.WebViewClient::onReceivedError', ['android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError'], function (data) { return returnVoidHook(data, false); });
// Apache Cordova WebViewClient
(0, java_1.addJavaReplaceHook)('org.apache.cordova.CordovaWebViewClient::onReceivedSslError', ['org.apache.cordova.CordovaWebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError'], function (data) {
    (0, log_1.logJavaFunction)(data, false);
    data.args[2].proceed();
});
// Boye AbstractVerifier
(0, java_1.addJavaReplaceHook)('ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier::verify', ['str', 'javax.net.ssl.SSLSocket'], function (data) { return returnVoidHook(data, false); });
// Apache AbstractVerifier
(0, java_1.addJavaReplaceHook)('org.apache.http.conn.ssl.AbstractVerifier::verify', ['str', 'str[]', 'str[]', 'boolean'], function (data) { return returnVoidHook(data, false); });
(0, java_1.addJavaReplaceHook)('org.apache.http.conn.ssl.AbstractVerifier::verify', ['str', 'java.security.cert.X509Certificate'], function (data) { return returnVoidHook(data, false); });
(0, java_1.addJavaReplaceHook)('org.apache.http.conn.ssl.AbstractVerifier::verify', ['str', 'javax.net.ssl.SSLSession'], function (data) { return returnTrueHook(data, false); });
(0, java_1.addJavaReplaceHook)('org.apache.http.conn.ssl.AbstractVerifier::verify', ['str', 'javax.net.ssl.SSLSocket'], function (data) { return returnVoidHook(data, false); });
// Chromium Cronet
(0, java_1.addJavaPreHook)('org.chromium.net.CronetEngine$Builder::enablePublicKeyPinningBypassForLocalTrustAnchors', ['boolean'], function (data) {
    data.args[0] = true;
});
(0, java_1.addJavaReplaceHook)('org.chromium.net.CronetEngine$Builder::addPublicKeyPins', ['str', 'java.util.Set', 'boolean', 'java.util.Date'], function (data) {
    (0, log_1.logJavaFunction)(data);
    return data["this"];
});
// Flutter Pinning packages http_certificate_pinning and ssl_pinning_plugin
(0, java_1.addJavaReplaceHook)('diefferson.http_certificate_pinning.HttpCertificatePinning::checkConnexion', ['java.lang.String', 'java.util.List', 'java.util.Map', 'int', 'java.lang.String'], returnTrueHook);
(0, java_1.addJavaReplaceHook)('com.macif.plugin.sslpinningplugin.SslPinningPlugin::checkPinning', ['java.lang.String', 'java.util.List', 'java.util.Map', 'int', 'java.lang.String'], returnTrueHook);
// Commbank KIAWhitelist 
(0, java_1.addJavaReplaceHook)('com.ICTSecurity.KIA.KIAWhitelist::verifyCertificate', ['str', 'str'], function (data) { return returnTrueHook(data, false); });
////////////////////////
// iOS Pinning bypass //
////////////////////////
// https://github.com/sensepost/objection/blob/f47926e90ce8b6655ecb431730b6674e41bc5625/agent/src/ios/pinning.ts
if (__webpack_require__.g.safeMode != 'yes') {
    // AFSecurityPolicy setSSLPinningMode
    (0, objc_1.addObjCPreHook)('-[AFSecurityPolicy setSSLPinningMode:]', 1, function (data) {
        if (!data.args[0].isNull()) {
            (0, log_1.logObjCFunction)(data);
            data.args[0] = ptr(0);
        }
    });
    // AFSecurityPolicy setAllowInvalidCertificates
    (0, objc_1.addObjCPreHook)('-[AFSecurityPolicy setAllowInvalidCertificates:]', 1, function (data) {
        data.args[0] = ptr(1); // true
    });
    // AFSecurityPolicy policyWithPinningMode
    (0, objc_1.addObjCPreHook)('+[AFSecurityPolicy policyWithPinningMode:]', 1, function (data) {
        if (!data.args[0].isNull()) {
            (0, log_1.logObjCFunction)(data);
            data.args[0] = ptr(0); // AFSSLPinningModeNone
        }
    });
    // AFSecurityPolicy policyWithPinningMode
    (0, objc_1.addObjCPreHook)('+[AFSecurityPolicy policyWithPinningMode:withPinnedCertificates:]', 2, function (data) {
        if (!data.args[0].isNull()) {
            (0, log_1.logObjCFunction)(data);
            data.args[0] = ptr(0); // AFSSLPinningModeNone
        }
    });
}
if (ObjC.available) {
    var NSURLCredential_1 = ObjC.classes.NSURLCredential;
    var resolver = new ApiResolver("objc");
    var search = resolver.enumerateMatches("-[* URLSession:didReceiveChallenge:completionHandler:]");
    for (var _i = 0, search_1 = search; _i < search_1.length; _i++) {
        var match = search_1[_i];
        Interceptor.attach(match.address, {
            onEnter: function (args) {
                var self = new ObjC.Object(args[0]);
                var selector = ObjC.selectorAsString(args[1]);
                var method = self.$methods.find(function (m) { return m.endsWith(' ' + selector); });
                var funName = method.substring(0, 1) + '[' + self.$className + ' ' + method.substring(2) + ']';
                (0, log_1.logObjCFunction)({
                    fun: null,
                    funName: funName,
                    self: self,
                    args: [args[2], args[3]],
                    "this": this,
                    detector: null
                }, false);
                var challenge = new ObjC.Object(args[3]);
                var completionHandler = new ObjC.Block(args[4]);
                var savedCompletionHandler = completionHandler.implementation;
                completionHandler.implementation = function () {
                    var credential = NSURLCredential_1.credentialForTrust_(challenge.protectionSpace().serverTrust());
                    var sender = challenge.sender();
                    if (sender != null) {
                        sender.useCredential_forAuthenticationChallenge_(credential, challenge);
                    }
                    savedCompletionHandler(0, credential);
                };
            }
        });
    }
}
// TSKPinningValidator evaluateTrust
(0, objc_1.addObjCPostHook)('-[TSKPinningValidator evaluateTrust:forHostname:]', 2, function (data) {
    if (!data.retval.isNull()) {
        (0, log_1.logObjCFunction)(data);
        data.retval.replace(ptr(0));
    }
});
// CustomURLConnectionDelegate isFingerprintTrusted
(0, objc_1.addObjCPostHook)('-[CustomURLConnectionDelegate isFingerprintTrusted:]', 1, function (data) {
    if (data.retval.isNull()) {
        (0, log_1.logObjCFunction)(data);
        data.retval.replace(ptr(1)); // true
    }
});
// SSLSetSessionOption
(0, native_1.addPreHook)('SSLSetSessionOption', ['ptr', 'int', 'int'], function (data) {
    if (data.args[1] == 0) { // option == SSLSessionOption.breakOnServerAuth
        (0, log_1.logFunction)(data, false);
        data.args[2] = 1; // true
    }
}, 'Security');
// SSLCreateContext
(0, native_1.addPostHook)('SSLCreateContext', ['ptr', 'int', 'int'], function (data) {
    var ctx = data.retval;
    if (!ctx.isNull()) {
        var SSLSetSessionOption = new NativeFunction(Module.findExportByName('Security', 'SSLSetSessionOption'), 'int', ['pointer', 'int', 'int']);
        SSLSetSessionOption(ctx, 0, 1); // SSLSessionOption.breakOnServerAuth true
    }
}, 'Security');
// SSLHandshake
(0, native_1.addPostHook)('SSLHandshake', ['ptr'], function (data) {
    if (data.retval.toInt32() == -9481) { // errSSLServerAuthCompleted
        var SSLHandshake = new NativeFunction(Module.findExportByName('Security', 'SSLHandshake'), 'int', ['pointer']);
        data.retval.replace(ptr(0));
        SSLHandshake(data.args[0]);
    }
}, 'Security');
// tls_helper_create_peer_trust and nw_tls_create_peer_trust
var functions = ['tls_helper_create_peer_trust', 'nw_tls_create_peer_trust'];
functions.forEach(function (functionName) {
    var func = Module.findExportByName(null, functionName);
    if (func != null) {
        Interceptor.replace(func, new NativeCallback(function (tls, server, trustRef) {
            return 0; // errSecSuccess
        }, 'int', ['pointer', 'bool', 'pointer']));
    }
});
// SSL_set_custom_verify
if (ObjC.available) {
    var customVerify = Module.findExportByName(null, 'SSL_CTX_set_custom_verify');
    if (customVerify == null) {
        customVerify = Module.findExportByName(null, 'SSL_set_custom_verify');
    }
    var pskIdentity = Module.findExportByName(null, 'SSL_get_psk_identity');
    if (customVerify != null && pskIdentity != null) {
        var SSL_set_custom_verify_1 = new NativeFunction(customVerify, 'void', ['pointer', 'int', 'pointer']);
        var SSL_get_psk_identity = new NativeFunction(pskIdentity, 'pointer', ['pointer']);
        var customVerifyCallback_1 = new NativeCallback(function (ssl, out_alert) {
            return 0;
        }, "int", ["pointer", "pointer"]);
        Interceptor.replace(SSL_set_custom_verify_1, new NativeCallback(function (ssl, mode, callback) {
            (0, log_1.logFunction)({
                syscall: 'SSL_set_custom_verify',
                args: [ssl, mode, callback],
                // @ts-ignore
                context: this,
                detector: null
            }, false);
            SSL_set_custom_verify_1(ssl, mode, customVerifyCallback_1);
        }, "void", ["pointer", "int", "pointer"]));
        Interceptor.replace(SSL_get_psk_identity, new NativeCallback(function (ssl) {
            return Memory.allocUtf8String('fakeIdentity');
        }, "pointer", ["pointer"]));
    }
}


/***/ }),

/***/ "./src/frida/detectors/root.ts":
/*!*************************************!*\
  !*** ./src/frida/detectors/root.ts ***!
  \*************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

exports.__esModule = true;
var apps_1 = __webpack_require__(/*! ../hooks/apps */ "./src/frida/hooks/apps.ts");
var file_1 = __webpack_require__(/*! ../hooks/file */ "./src/frida/hooks/file.ts");
var util_1 = __webpack_require__(/*! ../inc/util */ "./src/frida/inc/util.ts");
var log_1 = __webpack_require__(/*! ../inc/log */ "./src/frida/inc/log.ts");
var native_1 = __webpack_require__(/*! ../hooks/native */ "./src/frida/hooks/native.ts");
var socket_1 = __webpack_require__(/*! ../hooks/socket */ "./src/frida/hooks/socket.ts");
var fileHooks = file_1.FileHooks.getInstance();
var appsHooks = apps_1.AppsHooks.getInstance();
// Hide blacklisted files
fileHooks.accessFileHook(file_1.FilePattern.from(__webpack_require__.g.context.root.files.blacklist), true);
fileHooks.accessFileHook(file_1.FilePattern.from(__webpack_require__.g.context.root.files.log));
// Modify /proc/mounts and /proc/<pid>/mounts files
fileHooks.replaceFileHook('/proc/', 'mounts', getModifiedProcMounts);
fileHooks.roPermissionsFileHook(file_1.FilePattern.from(__webpack_require__.g.context.root.files.ro));
fixRootFlags();
// Add port hook for ssh ports
(0, socket_1.addOpenPortHook)(22);
(0, socket_1.addOpenPortHook)(2222);
appsHooks.blacklistAppsHook(__webpack_require__.g.context.root.apps.blacklist);
__webpack_require__.g.context.root.syscalls.forEach(function (syscall) {
    (0, native_1.addPostHook)(syscall, [], function (data) {
        (0, log_1.logFunction)(data);
        // We do not need to patch the return value here since the jailbreak 
        // we are using does not change the allowed syscalls
    });
});
function fixRootFlags() {
    var rootFlagsHandler = function (data) {
        if (data.args[0].isNull())
            return;
        (0, log_1.logFunction)(data, false);
        var mntonnamePtr = ptr(data.args[0]).add(0x58);
        if (mntonnamePtr.readCString() != "/") {
            return null;
        }
        // Assume that '/' is always first in the array and it'd the only fs that differs when jailbroken
        var flagsPtr = ptr(data.args[0]).add(0x40);
        // MNT_RDONLY | MNT_ROOTFS | MNT_DOVOLFS | MNT_JOURNALED | MNT_MULTILABEL | MNT_NOSUID | MNT_SNAPSHOT
        flagsPtr.writeU32(0x4480C009);
    };
    (0, native_1.addPostHook)('getfsstat', ['ptr', 'int', 'int'], rootFlagsHandler);
    (0, native_1.addPostHook)('getmntinfo', ['ptr', 'int'], rootFlagsHandler);
}
/**
 * Get a modified /proc/mounts file that doesn't contain blacklisted mount points
 */
function getModifiedProcMounts(filename) {
    var procMounts = (0, util_1.readFile)(filename);
    if (procMounts == null) {
        (0, log_1.warn)("Failed to read " + filename);
        return null;
    }
    // Get magisk mount point (e.g. /dev/lVGHs/.magisk/block/system_root => /dev/lVGHs) and add to blacklist
    var blacklist = __webpack_require__.g.context.root.mounts.blacklist;
    var magiskMount = procMounts
        .split('\n')
        .find(function (line) { return line.includes('/.magisk/'); });
    if (magiskMount) {
        magiskMount = magiskMount.split('/.magisk/')[0];
        var magiskMountPath = magiskMount.split(' ');
        blacklist.push(magiskMountPath[magiskMountPath.length - 1]);
    }
    var modifiedProcMounts = '';
    var _loop_1 = function (line) {
        if (blacklist.some(function (word) { return line.includes(word); }))
            return "continue";
        modifiedProcMounts += line + '\n';
    };
    for (var _i = 0, _a = procMounts.split('\n'); _i < _a.length; _i++) {
        var line = _a[_i];
        _loop_1(line);
    }
    return modifiedProcMounts;
}


/***/ }),

/***/ "./src/frida/detectors/screenreader.ts":
/*!*********************************************!*\
  !*** ./src/frida/detectors/screenreader.ts ***!
  \*********************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

exports.__esModule = true;
var java_1 = __webpack_require__(/*! ../hooks/java */ "./src/frida/hooks/java.ts");
var log_1 = __webpack_require__(/*! ../inc/log */ "./src/frida/inc/log.ts");
(0, java_1.addJavaPreHook)('android.view.SurfaceView::setSecure', ['boolean'], function (data) {
    if (data.args[0] == true) {
        (0, log_1.logJavaFunction)(data);
    }
});
(0, java_1.addJavaPreHook)('android.view.Window::setFlags', ['int', 'int'], function (data) {
    // Check if FLAG_SECURE (0x2000) is set
    if ((data.args[0] & 0x2000) != 0 && (data.args[1] & 0x2000) != 0) {
        (0, log_1.logJavaFunction)(data);
    }
});


/***/ }),

/***/ "./src/frida/detectors/svc.ts":
/*!************************************!*\
  !*** ./src/frida/detectors/svc.ts ***!
  \************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";

var __spreadArray = (this && this.__spreadArray) || function (to, from, pack) {
    if (pack || arguments.length === 2) for (var i = 0, l = from.length, ar; i < l; i++) {
        if (ar || !(i in from)) {
            if (!ar) ar = Array.prototype.slice.call(from, 0, i);
            ar[i] = from[i];
        }
    }
    return to.concat(ar || Array.prototype.slice.call(from));
};
exports.__esModule = true;
var util_1 = __webpack_require__(/*! ../inc/util */ "./src/frida/inc/util.ts");
var native_1 = __webpack_require__(/*! ../hooks/native */ "./src/frida/hooks/native.ts");
var log_1 = __webpack_require__(/*! ../inc/log */ "./src/frida/inc/log.ts");
(0, util_1.addRpcExports)({
    hookSvcs: hookSvcs
});
// List of svc instructions that could not be hooked when starting the app
var unhookedSvcs = [];
/**
 * Hook system calls by the addresses of the svc asm instructions
 * @param svcs svc instruction offsets, grouped by module name
 * @param appClass app class to use as the class loader when dynamically loading libraries
 */
function hookSvcs(svcs) {
    if (__webpack_require__.g.safeMode == 'yes')
        return;
    // Hook svcs
    Object.keys(svcs).forEach(function (moduleName) {
        var module = Process.findModuleByName(moduleName);
        var modulePath = svcs[moduleName][0]['path'];
        var loadSvcs = function () {
            svcs[moduleName].forEach(function (svc) {
                hookSvc(module.base, svc['offset'], module.name);
            });
        };
        var deferLoadSvcs = function (error) {
            (0, log_1.warn)("Failed to dynamically load library", moduleName, error);
            svcs[moduleName].forEach(function (svc) {
                unhookedSvcs.push({
                    module: moduleName,
                    address: svc['offset']
                });
            });
        };
        if (module == null) {
            // Try to load the module using System.loadLibrary
            // We don´t want to hook the svcs after the library is loaded by the app since we might miss 
            // some executions of svc calls just after the library is loaded because it takes some time for 
            // the hooks to be applied when the app is running
            // Instead we load and hook the library while the app is still paused
            if (Java.available) {
                Java.perform(function () {
                    try {
                        var Runtime = Java.use('java.lang.Runtime');
                        var classLoaderClass = void 0;
                        if (__webpack_require__.g.appClassLoader) {
                            classLoaderClass = __webpack_require__.g.appClassLoader;
                        }
                        else {
                            classLoaderClass = Java.classFactory.loader;
                        }
                        // loadLibrary(String libname, ClassLoader loader) is no longer available on newer Android versions
                        // so we use the undocumented function loadLibrary0(Class<?> fromClass, String libname) instead
                        // This might break on future Android versions
                        // TODO: Hook VMStack.getCallingClassLoader() to return the classloader of appClass instead
                        Runtime.getRuntime().loadLibrary0(classLoaderClass, modulePath);
                        module = Process.findModuleByName(moduleName);
                        loadSvcs();
                    }
                    catch (e) {
                        if (e.toString().includes('unable to intercept function')) {
                            // For some reason, some apps segfault if we catch this exception
                            // We ignore this error in src/python/dynamic.py
                            // TODO: Validate this does not prevent the rest of the script from running
                            throw e;
                        }
                        else {
                            deferLoadSvcs(e);
                        }
                    }
                });
            }
            else if (ObjC.available) {
                try {
                    var bundlePath = ObjC.classes.NSBundle.mainBundle().bundlePath();
                    bundlePath = bundlePath.stringByAppendingPathComponent_(modulePath);
                    if (modulePath.endsWith(".framework")) {
                        var bundle = ObjC.classes.NSBundle.bundleWithPath_(bundlePath);
                        if (bundle.isLoaded()) {
                            (0, log_1.warn)("Failed to dynamically load framework", moduleName, "framework already loaded but not available as a module");
                        }
                        if (bundle.load()) {
                            loadSvcs();
                        }
                        else {
                            deferLoadSvcs("failed to load bundle");
                        }
                    }
                    else if (modulePath.endsWith('.dylib')) {
                        var dlopen = new NativeFunction(Module.findExportByName(null, 'dlopen'), 'pointer', ['pointer', 'int']);
                        if (dlopen(Memory.allocUtf8String(bundlePath.UTF8String()), 9)) {
                            loadSvcs();
                        }
                        else {
                            deferLoadSvcs("failed to load dylib");
                        }
                    }
                    else {
                        deferLoadSvcs("unknown library type");
                    }
                }
                catch (e) {
                    deferLoadSvcs(e);
                }
            }
        }
        else {
            loadSvcs();
        }
    });
    var libdl = Process.platform == 'darwin' ? 'libdyld.dylib' : 'libdl.so';
    Interceptor.attach(Module.findExportByName(libdl, 'dlopen'), {
        onEnter: function () {
            hookUnhookedSvcs();
        }
    });
    if (Process.platform != 'darwin') {
        // Crashes the app if hooked on iOS
        Interceptor.attach(Module.findExportByName(libdl, 'dlsym'), {
            onEnter: function (args) {
                // Check if the function is JNI_OnLoad, which is called after a library is loaded
                if (args[1].readUtf8String() != 'JNI_OnLoad')
                    return;
                hookUnhookedSvcs();
            }
        });
    }
}
function hookSvc(moduleBaseAddress, svcAddress, module) {
    var syscall = null;
    var syscallArgs = [];
    var address = moduleBaseAddress.add(svcAddress);
    try {
        // On entering a svc syscall
        Interceptor.attach(address, function () {
            var _this = this;
            var id = this.context[Process.platform == 'darwin' ? 'x16' : 'x8'].toInt32();
            syscall = __webpack_require__.g.context.syscall_names[id];
            var appliedHooks = (0, native_1.getAppliedHooks)();
            if (appliedHooks[syscall] === undefined)
                return;
            var args = ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7'].map(function (arg) { return ptr(_this.context[arg]); });
            (0, log_1.log)({
                type: 'svc',
                context: 'native',
                "function": 'svc',
                args: args,
                confident: true,
                svc_id: id,
                svc_syscall: syscall
            }, this.context);
            appliedHooks[syscall].forEach(function (hook) {
                hook.args = (0, native_1.convertArgs)(args, hook.argTypes, syscall);
                if (hook.type === 'pre') {
                    var hookArgs = __spreadArray([], hook.args, true);
                    var data = { args: hook.args, syscall: syscall, context: _this, detector: hook.detector };
                    hook.handler(data);
                    // Replace arguments if they were changed
                    for (var i = 0; i < hookArgs.length; i++) {
                        if (hookArgs[i] !== hook.args[i]) {
                            // If string, use Memory.allocUtf8String
                            if (typeof hook.args[i] === 'string') {
                                _this.context['x' + i] = Memory.allocUtf8String(hook.args[i]);
                            }
                            else if (typeof hook.args[i] === 'number') {
                                if (hook.argTypes[i] === 'uint') {
                                    if (hook.argTypes[i] === 'uint' || hook.argTypes[i] === 'int') {
                                        _this.context['x' + i] = ptr(hook.args[i]);
                                    }
                                    else if (hook.argTypes[i] === 'long') {
                                        _this.context['x' + i].writeLong(hook.args[i]);
                                    }
                                }
                                else {
                                    _this.context['x' + i] = Memory.alloc(4).writeInt(hook.args[i]);
                                }
                            }
                            else {
                                _this.context['x' + i] = hook.args[i];
                            }
                        }
                    }
                }
            });
        });
        // On return from a svc syscall
        Interceptor.attach(address.add(4), function () {
            var _this = this;
            if (syscall == null)
                return;
            var appliedHooks = (0, native_1.getAppliedHooks)();
            if (appliedHooks[syscall] === undefined)
                return;
            // Create return value as InvocationReturnValue
            var returnValue = ptr(this.context['x0']);
            returnValue.replace = function (value) {
                _this.context['x0'] = value;
            };
            appliedHooks[syscall].forEach(function (hook) {
                if (hook.type === 'post') {
                    var data = { args: hook.args, syscall: syscall, retval: returnValue, context: _this, detector: hook.detector };
                    hook.handler(data);
                }
            });
        });
    }
    catch (e) {
        (0, log_1.warn)("Failed to hook svc at", address, e);
    }
}
function hookUnhookedSvcs() {
    var newUnhookedSvcs = [];
    unhookedSvcs.forEach(function (svc) {
        var module = Process.findModuleByName(svc['module']);
        if (module != null) {
            hookSvc(module.base, svc['address'], module.name);
        }
        else {
            newUnhookedSvcs.push(svc);
        }
    });
    unhookedSvcs = newUnhookedSvcs;
}


/***/ }),

/***/ "./src/frida/detectors/tamper.ts":
/*!***************************************!*\
  !*** ./src/frida/detectors/tamper.ts ***!
  \***************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

exports.__esModule = true;
var java_1 = __webpack_require__(/*! ../hooks/java */ "./src/frida/hooks/java.ts");
var objc_1 = __webpack_require__(/*! ../hooks/objc */ "./src/frida/hooks/objc.ts");
var log_1 = __webpack_require__(/*! ../inc/log */ "./src/frida/inc/log.ts");
var PM = 'android.app.ApplicationPackageManager';
(0, java_1.addJavaPreHook)("".concat(PM, "::getPackageInfo"), ['str', 'int'], function (data) {
    // Check if GET_SIGNATURES (0x40) or GET_SIGNING_CERTIFICATES (0x8000000) is set for current app
    if (data.args[0] != __webpack_require__.g.context.info.package || ((data.args[1] & 0x40) == 0 && (data.args[1] & 0x8000000) == 0))
        return;
    (0, log_1.logJavaFunction)(data, false);
});
(0, java_1.addJavaPreHook)("".concat(PM, "::getInstalledPackages"), ['int'], function (data) {
    // Check if GET_SIGNATURES (0x40) or GET_SIGNING_CERTIFICATES (0x8000000) is set
    if ((data.args[0] & 0x40) == 0 && (data.args[0] & 0x8000000) == 0)
        return;
    (0, log_1.logJavaFunction)(data, false);
});
(0, java_1.addJavaPreHook)("".concat(PM, "::hasSigningCertificate"), ['int', '[B', 'int'], function (data) {
    // TODO: Check uid
    (0, log_1.logJavaFunction)(data);
});
(0, java_1.addJavaPreHook)("".concat(PM, "::hasSigningCertificate"), ['str', '[B', 'int'], function (data) {
    (0, log_1.logJavaFunction)(data, data.args[0] == __webpack_require__.g.context.info.package);
});
// Check if Google Play Integrity API is used
(0, java_1.addJavaPreHook)('com.google.android.play.core.integrity.IntegrityManager::requestIntegrityToken', null, function (data) {
    (0, log_1.logJavaFunction)(data);
});
// Check if SafetyNet API is used
(0, java_1.addJavaPreHook)('com.google.android.gms.safetynet.SafetyNetClient::attest', ['[B', 'str'], function (data) {
    (0, log_1.logJavaFunction)(data);
});
(0, java_1.addJavaPreHook)('com.google.android.gms.safetynet.SafetyNetClient::attest', ['str', '[B'], function (data) {
    (0, log_1.logJavaFunction)(data);
});
// Check if DCAppAttestService is used
(0, objc_1.addObjCPreHook)('-[DCAppAttestService attestKey:clientDataHash:completionHandler:]', 0, function (data) {
    (0, log_1.logObjCFunction)(data);
});
// Check if app accesses bundle's subdirectory that contains the resource files
(0, objc_1.addObjCPreHook)('-[NSURL resourceURL]', 0, function (data) {
    (0, log_1.logObjCFunction)(data);
});
// check if app accesses file exists method (positive if in combination with access to bundle's subdirectory)
(0, objc_1.addObjCPreHook)('-[FileManager fileExists:atPath:isDirectory:]', 2, function (data) {
    (0, log_1.logObjCFunction)(data);
});


/***/ }),

/***/ "./src/frida/hooks/apps.ts":
/*!*********************************!*\
  !*** ./src/frida/hooks/apps.ts ***!
  \*********************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

exports.__esModule = true;
exports.AppsHooks = void 0;
var log_1 = __webpack_require__(/*! ../inc/log */ "./src/frida/inc/log.ts");
var java_1 = __webpack_require__(/*! ./java */ "./src/frida/hooks/java.ts");
var objc_1 = __webpack_require__(/*! ./objc */ "./src/frida/hooks/objc.ts");
var file_1 = __webpack_require__(/*! ./file */ "./src/frida/hooks/file.ts");
var AppsHooks = /** @class */ (function () {
    function AppsHooks() {
    }
    AppsHooks.getInstance = function () {
        if (!AppsHooks.instance) {
            AppsHooks.instance = new AppsHooks();
        }
        return AppsHooks.instance;
    };
    /**
     * Blacklist a list of apps, so that the analyzed app detects it as not being installed
     * @param apps list of apps to blacklist
     */
    AppsHooks.prototype.blacklistAppsHook = function (apps) {
        if (Process.platform == 'darwin') {
            this.blacklistAppsHookIOS(apps);
        }
        else {
            this.blacklistAppsHookAndroid(apps);
        }
    };
    /**
     * Blacklist apps on iOS
     * @param apps list of apps to blacklist
     */
    AppsHooks.prototype.blacklistAppsHookIOS = function (apps) {
        var blacklist = file_1.FilePattern.from(apps);
        var checkBlacklist = function (app, data, confident) {
            if (confident === void 0) { confident = true; }
            var appURI = app.split('://')[0];
            if (blacklist.some(function (item) { return item.matches(appURI); })) {
                (0, log_1.log)({
                    type: 'app',
                    context: 'objc',
                    app: app,
                    "function": data.funName,
                    args: data.args.map(function (arg) { return new ObjC.Object(arg).toString(); }),
                    confident: confident
                }, data["this"].context, data.detector);
                return true;
            }
            else {
                return false;
            }
        };
        (0, objc_1.addObjCPreHook)('-[NSApplication canOpenURL:]', 1, function (data) {
            var app = new ObjC.Object(data.args[0]).toString();
            if (checkBlacklist(app, data)) {
                data.args[0] = ObjC.classes.NSURL.URLWithString_(ObjC.classes.NSString.stringWithString_('doesnotexist://'));
            }
        });
        (0, objc_1.addObjCPreHook)('-[NSApplication openURL:]', 1, function (data) {
            var app = new ObjC.Object(data.args[0]).toString();
            if (checkBlacklist(app, data)) {
                data.args[0] = ObjC.classes.NSURL.URLWithString_(ObjC.classes.NSString.stringWithString_('doesnotexist://'));
            }
        });
    };
    /**
     * Blacklist apps on Android
     * @param apps list of apps to blacklist
     */
    AppsHooks.prototype.blacklistAppsHookAndroid = function (apps) {
        var checkBlacklist = function (app, data, confident) {
            if (confident === void 0) { confident = true; }
            if (apps.includes(app)) {
                (0, log_1.log)({
                    type: 'app',
                    context: 'java',
                    app: app,
                    "function": data.funName,
                    args: data.args,
                    backtrace: data.backtrace,
                    confident: confident
                }, data["this"].context, data.detector);
                return true;
            }
            else {
                return false;
            }
        };
        // Hook PackageManager
        // TODO: Check that this also covers the `pm list packages` command once https://github.com/frida/frida/issues/2422 is resolved
        this.blacklistPackageManagerSingleApp(checkBlacklist);
        this.blacklistPackageManagerMultiApp(checkBlacklist);
        // Hook Intent
        this.blacklistIntent(checkBlacklist);
        // Hook ChangedPackages.getPackageNames()
        (0, java_1.addJavaPostHook)('android.content.pm.ChangedPackages::getPackageNames', [], function (data) {
            var packages = data.retval;
            for (var i = 0; i < packages.size(); i++) {
                if (checkBlacklist(packages.get(i).toString(), data, false)) {
                    packages.remove(i);
                    i--;
                }
            }
        });
        // We could hook String comparison methods like String.equals to see if the app is comparing against a blacklisted app
        // but hooking String.equals is very slow and would slow down the app too much
    };
    /**
     * Blacklist apps on Android by hooking methods of the PackageManager class that take a single app as an argument
     * @param checkBlacklist function that checks if an app is blacklisted
     */
    AppsHooks.prototype.blacklistPackageManagerSingleApp = function (checkBlacklist) {
        var PM = 'android.app.ApplicationPackageManager';
        // Signature (String packageName)
        (0, java_1.addJavaPreHook)([
            "".concat(PM, "::getApplicationBanner"),
            "".concat(PM, "::getApplicationEnabledSetting"),
            "".concat(PM, "::getApplicationIcon"),
            "".concat(PM, "::getApplicationLogo"),
            "".concat(PM, "::getInstallSourceInfo"),
            "".concat(PM, "::getInstallerPackageName"),
            "".concat(PM, "::getLaunchIntentForPackage"),
            "".concat(PM, "::getLaunchIntentSenderForPackage"),
            "".concat(PM, "::getLeanbackLaunchIntentForPackage"),
            "".concat(PM, "::getPackageGids"),
            "".concat(PM, "::getResourcesForApplication"),
            "".concat(PM, "::getTargetSdkVersion"),
            "".concat(PM, "::isPackageSuspended")
        ], ['str'], function (data) {
            if (checkBlacklist(data.args[0], data)) {
                data.args[0] = 'doesnotexist';
            }
        });
        // Signature (String packageName, int flags)
        (0, java_1.addJavaPreHook)([
            "".concat(PM, "::getApplicationInfo"),
            "".concat(PM, "::getModuleInfo"),
            "".concat(PM, "::getPackageGids"),
            "".concat(PM, "::getPackageInfo"),
            "".concat(PM, "::getPackageUid")
        ], ['str', 'int'], function (data) {
            if (checkBlacklist(data.args[0], data)) {
                data.args[0] = 'doesnotexist';
            }
        });
        // Signature (String packageName, int resourceId, ApplicationInfo appInfo)
        (0, java_1.addJavaPreHook)([
            "".concat(PM, "::getDrawable"),
            "".concat(PM, "::getText"),
            "".concat(PM, "::getXml")
        ], ['str', 'int', 'android.content.pm.ApplicationInfo'], function (data) {
            if (checkBlacklist(data.args[0], data)) {
                data.args[0] = 'doesnotexist';
            }
        });
        // Signature (String packageName, PackageManager.ApplicationInfoFlags flags)
        (0, java_1.addJavaPreHook)(["".concat(PM, "::getApplicationInfo")], ['str', "".concat(PM, ".ApplicationInfoFlags")], function (data) {
            if (checkBlacklist(data.args[0], data)) {
                data.args[0] = 'doesnotexist';
            }
        });
        // Signature (String packageName, PackageManager.PackageInfoFlags flags)
        (0, java_1.addJavaPreHook)([
            "".concat(PM, "::getPackageGids"),
            "".concat(PM, "::getPackageInfo"),
            "".concat(PM, "::getPackageUid"),
        ], ['str', "".concat(PM, ".PackageInfoFlags")], function (data) {
            if (checkBlacklist(data.args[0], data)) {
                data.args[0] = 'doesnotexist';
            }
        });
        // Signature (String propertyName, String packageName)
        (0, java_1.addJavaPreHook)([
            "".concat(PM, "::checkPermission"),
            "".concat(PM, "::getProperty"),
        ], ['str', 'str'], function (data) {
            if (checkBlacklist(data.args[1], data)) {
                data.args[1] = 'doesnotexist';
            }
        });
    };
    /**
     * Blacklist apps on Android by hooking methods of the PackageManager class that take a list of apps as an argument
     * @param checkBlacklist function that checks if an app is blacklisted
     */
    AppsHooks.prototype.blacklistPackageManagerMultiApp = function (checkBlacklist) {
        var pm = 'android.app.ApplicationPackageManager';
        // Handler for methods that return List<ApplicationInfo | PackageInfo>
        var infoHandler = function (data) {
            var apps = data.retval;
            for (var i = 0; i < apps.size(); i++) {
                var app = Java.cast(apps.get(i), Java.use(apps.get(i).getClass().getName()));
                if (checkBlacklist(app.packageName.value, data)) {
                    apps.remove(i);
                    i--;
                }
            }
        };
        // Signature (int flags) => List<ApplicationInfo | PackageInfo>
        (0, java_1.addJavaPostHook)([
            "".concat(pm, "::getInstalledApplications"),
            "".concat(pm, "::getInstalledPackages")
        ], ['int'], infoHandler);
        // Signature (PackageManager.PackageInfoFlags flags) => List<PackageInfo>
        (0, java_1.addJavaPostHook)(["".concat(pm, "::getInstalledPackages")], ["".concat(pm, ".PackageInfoFlags")], infoHandler);
        // Signature (String[] permissions, int flags) => List<PackageInfo>
        (0, java_1.addJavaPostHook)(["".concat(pm, "::getPackagesHoldingPermissions")], ['str[]', 'int'], infoHandler);
        // Signature (String[] packages, PackageManager.PackageInfoFlags flags) => List<PackageInfo>
        (0, java_1.addJavaPostHook)(["".concat(pm, "::getPackagesHoldingPermissions")], ['str[]', "".concat(pm, ".PackageInfoFlags")], infoHandler);
        // Signature (int flags) => List<PackageInfo>
        (0, java_1.addJavaPostHook)(["".concat(pm, "::getPreferredPackages")], ['int'], infoHandler);
        // Signature (int flags) => List<ModuleInfo>
        (0, java_1.addJavaPostHook)(["".concat(pm, "::getInstalledModules")], ['int'], function (data) {
            var apps = data.retval;
            for (var i = 0; i < apps.size(); i++) {
                var app = Java.cast(apps.get(i), Java.use(apps.get(i).getClass().getName()));
                if (app == null)
                    continue;
                if (checkBlacklist(app.getPackageName(), data)) {
                    apps.remove(i);
                    i--;
                }
            }
        });
        // Signature (int uid) => String[]
        (0, java_1.addJavaPostHook)(["".concat(pm, "::getPackagesForUid")], ['int'], function (data) {
            var apps = data.retval;
            var newApps = [];
            for (var i = 0; i < apps.length; i++) {
                if (!checkBlacklist(apps[i], data)) {
                    newApps.push(apps[i]);
                }
            }
            data.retval = newApps;
        });
    };
    /**
     * Blacklist apps on Android by hooking methods of the Intent class
     * @param checkBlacklist function that checks if an app is blacklisted
     */
    AppsHooks.prototype.blacklistIntent = function (checkBlacklist) {
        var intent = 'android.content.Intent';
        (0, java_1.addJavaPreHook)("".concat(intent, "::setPackage"), ['str'], function (data) {
            if (checkBlacklist(data.args[0], data)) {
                data.args[0] = 'doesnotexist';
            }
        });
        (0, java_1.addJavaPreHook)("".concat(intent, "::setClassName"), ['str', 'str'], function (data) {
            if (checkBlacklist(data.args[0], data)) {
                data.args[0] = 'doesnotexist';
            }
        });
        (0, java_1.addJavaPreHook)("".concat(intent, "::setComponent"), ['android.content.ComponentName'], function (data) {
            if (data.args[0] == null)
                return;
            if (checkBlacklist(data.args[0].getPackageName(), data)) {
                data.args[0].setPackageName('doesnotexist');
            }
        });
    };
    return AppsHooks;
}());
exports.AppsHooks = AppsHooks;


/***/ }),

/***/ "./src/frida/hooks/file.ts":
/*!*********************************!*\
  !*** ./src/frida/hooks/file.ts ***!
  \*********************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

exports.__esModule = true;
exports.FileHooks = exports.FilePattern = void 0;
var native_1 = __webpack_require__(/*! ./native */ "./src/frida/hooks/native.ts");
var log_1 = __webpack_require__(/*! ../inc/log */ "./src/frida/inc/log.ts");
var util_1 = __webpack_require__(/*! ../inc/util */ "./src/frida/inc/util.ts");
/**
 * Class used to match file paths against a blacklist
 * Matching can be performed by filename or substring
 */
var FilePattern = /** @class */ (function () {
    /**
     * Construct a file pattern that can be used for blacklisting files
     * @param path path to match
     * @param matching matching method
     */
    function FilePattern(path, matching) {
        this.path = path.toLowerCase();
        this.matching = matching;
    }
    /**
     * Check if an absolute path matches this pattern
     * @param path absolute path to check
     * @returns true if path matches this pattern, false otherwise
     */
    FilePattern.prototype.matches = function (path) {
        if (path === null || path === undefined)
            return false;
        path = path.toLowerCase();
        // Ignore files of the current application
        if (path.includes(__webpack_require__.g.context.info.package))
            return false;
        if (__webpack_require__.g.context.info.executable && path.includes(__webpack_require__.g.context.info.executable + '.app'))
            return false;
        // Ignore frida internal files that are accessed during normal operation
        // TODO: See if there is a way to still detect when these files are accessed by 
        // the app instead of frida itself
        if (path.startsWith('/data/local/tmp/re.frida.server/linjector-') ||
            path.startsWith('/data/local/tmp/re.frida.server/frida-'))
            return false;
        switch (this.matching) {
            case 'contains':
                return path.includes(this.path);
            case 'filename':
                if (this.path.includes('/')) {
                    return path == this.path;
                }
                else {
                    return path.split('/').pop() == this.path;
                }
            case 'startsWith':
                return path.startsWith(this.path);
            case 'endsWith':
                return path.endsWith(this.path);
        }
    };
    /**
     * Construct a list of file patterns from a list of strings
     * A * at the start or end of a string is considered a wildcard
     * @param list list of strings
     * @returns list of file patterns
     */
    FilePattern.from = function (list) {
        return list.map(function (path) {
            var startsWithWildcard = path.startsWith('*');
            var endsWithWildcard = path.endsWith('*');
            var matching;
            if (startsWithWildcard && endsWithWildcard) {
                matching = 'contains';
                path = path.substring(1, path.length - 1);
            }
            else if (startsWithWildcard) {
                matching = 'endsWith';
                path = path.substring(1);
            }
            else if (endsWithWildcard) {
                matching = 'startsWith';
                path = path.substring(0, path.length - 1);
            }
            else {
                matching = 'filename';
            }
            return new FilePattern(path, matching);
        });
    };
    return FilePattern;
}());
exports.FilePattern = FilePattern;
/**
 * Singleton class wrapper used to easily add hooks to file operations
 */
var FileHooks = /** @class */ (function () {
    function FileHooks() {
        var _this = this;
        this.fileDescriptors = {};
        this.fileHandler = function (list, callback) {
            return function (data) {
                if (data.args.length < 1)
                    return;
                var path;
                if (typeof data.args[0] == 'string') {
                    // Args: path
                    path = data.args[0];
                }
                else if (data.args.length >= 2 && typeof data.args[0] == 'number' && typeof data.args[1] == 'string') {
                    // Args: fd, path
                    path = data.args[1];
                    if (data.args[0] && _this.fileDescriptors[data.args[0]])
                        path = _this.fileDescriptors[data.args[0]] + '/' + path;
                }
                else if (typeof data.args[0] == 'number') {
                    // Args: fd
                    path = _this.fileDescriptors[data.args[0]];
                }
                else {
                    return;
                }
                if (list.some(function (item) { return item.matches(path); })) {
                    logFile(data, path);
                    callback(data);
                }
            };
        };
        // Add hooks so we can associate file descriptors with file paths
        (0, native_1.addPostHook)(['open', 'open_dprotected_np', 'open_extended', 'open_nocancel', 'guarded_open_np', 'guarded_open_dprotected_np', 'creat'], ['str'], function (data) {
            if (data.retval.toInt32() < 0)
                return;
            _this.fileDescriptors[data.retval.toInt32()] = data.args[0];
        });
        (0, native_1.addPostHook)(['close', 'android_fdsan_close_with_tag', 'sys_close', 'sys_close_nocancel', 'guarded_close_np'], ['int'], function (data) {
            if (data.retval.toInt32() != 0)
                return;
            delete _this.fileDescriptors[data.args[0]];
        });
        (0, native_1.addPostHook)(['openat', 'openat_nocancel'], ['int', 'str'], function (data) {
            if (data.retval.toInt32() < 0)
                return;
            _this.fileDescriptors[data.retval.toInt32()] = _this.fileDescriptors[data.args[0]] + '/' + data.args[1];
        });
    }
    FileHooks.getInstance = function () {
        if (!FileHooks.instance) {
            FileHooks.instance = new FileHooks();
        }
        return FileHooks.instance;
    };
    /**
     * Adds hooks to file operations related to the listed files. Can also blacklist files so they are not visible to the app
     * @param list list of file paths
     * @param blacklist if true, the list is treated as a blacklist, otherwise the function will only log access to matching files
     */
    FileHooks.prototype.accessFileHook = function (list, blacklist) {
        if (blacklist === void 0) { blacklist = false; }
        // Args: path
        var fileHook = this.fileHandler(list, function (data) {
            if (blacklist) {
                data.args[0] = "/doesnotexist";
            }
        });
        // Args: fd, path
        var fileatHook = this.fileHandler(list, function (data) {
            if (blacklist) {
                data.args[1] = "/doesnotexist";
            }
        });
        // Args: fd
        var ffileHook = this.fileHandler(list, function (data) {
            // No need to check for blacklist, since the app would be unable to construct a file descriptor 
            // to these files since we hook open and openat
        });
        var openSyscalls = ['open', 'open_dprotected_np', 'open_extended', 'open_nocancel', 'guarded_open_np', 'guarded_open_dprotected_np', 'creat', 'access', 'access_extended'];
        (0, native_1.addPreHook)(openSyscalls, ['str'], fileHook);
        var openatSyscalls = ['openat', 'openat_nocancel', 'faccessat'];
        (0, native_1.addPreHook)(openatSyscalls, ['int', 'str'], fileatHook);
        var statSyscalls = ['lstat', 'stat', 'statfs', 'statvfs'];
        (0, native_1.addPreHook)(statSyscalls, ['str', 'ptr'], fileHook);
        var fstatSyscalls = ['fstat', 'sys_fstat', 'fstatfs', 'fstatvfs'];
        (0, native_1.addPreHook)(fstatSyscalls, ['int', 'ptr'], ffileHook);
        (0, native_1.addPreHook)('fstatat', ['int', 'str', 'ptr', 'int'], fileatHook);
        (0, native_1.addPreHook)('pathconf', ['str', 'int'], fileHook);
        (0, native_1.addPreHook)(['fpathconf', 'sys_fpathconf'], ['int', 'int'], ffileHook);
        (0, native_1.addPreHook)('getattrlist', ['str', 'ptr', 'ptr', 'int'], fileHook);
        (0, native_1.addPreHook)('fgetattrlist', ['int', 'ptr', 'ptr', 'int'], ffileHook);
        (0, native_1.addPreHook)('getattrlistat', ['int', 'str', 'ptr', 'ptr', 'int'], fileatHook);
        (0, native_1.addPreHook)('readlink', ['str'], fileHook);
        (0, native_1.addPreHook)('readlinkat', ['int', 'str'], fileatHook);
        var readlinkHook = function (data) {
            var linkPathIndex = 1;
            if (typeof data.args[0] != 'string') {
                linkPathIndex = 2;
            }
            if (list.some(function (item) { return item.matches(data.args[linkPathIndex]); })) {
                logFile(data, data.args[linkPathIndex]);
                if (blacklist) {
                    data.args[linkPathIndex] = '/dev/null';
                }
            }
        };
        (0, native_1.addPostHook)('readlink', ['str', 'str'], readlinkHook);
        (0, native_1.addPreHook)('readlinkat', ['int', 'str', 'str'], readlinkHook);
        // TODO: Blacklist individual directory entries
        (0, native_1.addPreHook)('getattrlistbulk', ['int', 'ptr', 'ptr', 'int', 'int'], ffileHook);
        (0, native_1.addPreHook)('getdirentriesattr', ['int', 'ptr', 'ptr', 'int', 'long', 'long', 'long', 'int'], ffileHook);
        (0, native_1.addPreHook)('getdirentries', ['int', 'ptr', 'int', 'ptr'], ffileHook);
        // Hook executing files
        var exec = ['execve', 'execv', 'execvp', 'execvpe'];
        (0, native_1.addPreHook)(exec, ['str', 'ptr'], fileHook);
        (0, native_1.addPreHook)('system', ['str'], fileHook);
    };
    /**
     * Virtually change permissions of files matching the list to read-only
     * @param list list of file paths
     */
    FileHooks.prototype.roPermissionsFileHook = function (list) {
        var stat = (0, util_1.syscall)('stat', 'int', ['pointer', 'pointer']);
        function setPermissions(statStruct) {
            // Set file permissions to read-only in st_mode
            // unsigned long+unsigned long = 8+8 = 16
            var permissions = statStruct.add(16).readU32();
            // Clear write permissions
            permissions = (permissions & ~146) >>> 0;
            statStruct.add(16).writeU32(permissions);
        }
        var setPermissionsHook = this.fileHandler(list, function (data) {
            var statStruct;
            if (typeof data.args[1] == 'number') {
                // Args: fd, stat
                statStruct = data.args[1];
            }
            else if (typeof data.args[2] == 'number') {
                // Args: fd, path, stat
                statStruct = data.args[2];
            }
            else {
                return;
            }
            setPermissions(statStruct);
        });
        (0, native_1.addPostHook)(['stat', 'stat_extended'], ['str', 'ptr'], setPermissionsHook);
        (0, native_1.addPostHook)(['lstat', 'lstat_extended'], ['str', 'ptr'], this.fileHandler(list, function (data) {
            // Use stat so we don't return a symlink
            stat(Memory.allocUtf8String(data.args[0]), data.args[1]);
            setPermissions(data.args[1]);
        }));
        (0, native_1.addPostHook)(['fstat', 'sys_fstat_extended', 'sys_fstat'], ['int', 'ptr'], setPermissionsHook);
        (0, native_1.addPreHook)(['fstatat'], ['int', 'str', 'ptr', 'int'], this.fileHandler(list, function (data) {
            // Unset AT_SYMLINK_NOFOLLOW
            data.args[3] &= ~0x100;
        }));
        (0, native_1.addPostHook)(['fstatat'], ['int', 'str', 'ptr', 'int'], setPermissionsHook);
        var setAccessibleHook = this.fileHandler(list, function (data) {
            var mode;
            if (typeof data.args[1] == 'number') {
                // Args: fd, mode
                mode = data.args[1];
            }
            else if (typeof data.args[2] == 'number') {
                // Args: fd, path, mode
                mode = data.args[2];
            }
            if (mode & 146) {
                data.retval.replace(-1);
                data.context.errno = 13; // EACCES
            }
        });
        (0, native_1.addPostHook)(['access', 'access_extended'], ['str', 'int'], setAccessibleHook);
        (0, native_1.addPostHook)('faccessat', ['int', 'str', 'int', 'int'], setAccessibleHook);
        (0, native_1.addPreHook)('readlink', ['str'], this.fileHandler(list, function (data) {
            data.args[0] = "/"; // Make sure EINVAL is returned (not a symlink)
        }));
        (0, native_1.addPreHook)('readlinkat', ['int', 'str'], this.fileHandler(list, function (data) {
            data.args[1] = "/"; // Make sure EINVAL is returned (not a symlink)
        }));
        var epermHook = this.fileHandler(list, function (data) {
            data.retval.replace(-1);
            data.context.errno = 1; // EPERM
        });
        var writeSyscalls = ['write', 'write_nocancel', 'writev', 'writev_nocancel', 'pwrite', 'pwrite_nocancel', 'pwritev', 'pwritev2', 'sys_pwritev', 'sys_pwritev_nocancel'];
        (0, native_1.addPreHook)(writeSyscalls, ['int', 'ptr', 'uint'], this.fileHandler(list, function (data) {
            data.args[2] = 0;
        }));
        (0, native_1.addPostHook)(writeSyscalls, ['int', 'ptr', 'uint'], epermHook);
        var guardedWriteSyscalls = ['guarded_write_np', 'guarded_pwrite_np', 'guarded_writev_np'];
        (0, native_1.addPreHook)(guardedWriteSyscalls, ['int', 'ptr', 'ptr', 'uint'], this.fileHandler(list, function (data) {
            data.args[3] = 0;
        }));
        (0, native_1.addPostHook)(guardedWriteSyscalls, ['int', 'ptr', 'ptr', 'uint'], epermHook);
    };
    /**
     * Virtually replace a (readonly) file with new context by hooking all file operations
     * @param path some parent directory of file to replace
     * @param filename name of file to replace
     * @param callback callback to generate new file contents
     */
    FileHooks.prototype.replaceFileHook = function (path, filename, callback, confident) {
        var _this = this;
        if (confident === void 0) { confident = true; }
        // Create a temporary file to replace a file
        var tmpDir = null;
        if (Process.platform == 'darwin') {
            if (ObjC.available) {
                // NSTemporaryDirectory()
                var NSTemporaryDirectory = new NativeFunction(Module.findExportByName(null, 'NSTemporaryDirectory'), 'pointer', []);
                tmpDir = (new ObjC.Object(NSTemporaryDirectory())).toString();
            }
            else {
                (0, log_1.error)("Cannot replace file on iOS without Objective-C runtime");
                return;
            }
        }
        else {
            // Android
            var packageId = __webpack_require__.g.context.info.package;
            tmpDir = "/data/data/" + packageId;
        }
        var open = (0, util_1.syscall)('open', 'int', ['pointer', 'int']);
        var close = (0, util_1.syscall)('close', 'int', ['int']);
        var replaceFileHandler = function (openPath, flags, data) {
            if (openPath != null && openPath.startsWith(path) && openPath.endsWith(filename)) {
                var newFile = callback(openPath);
                if (newFile != null) {
                    logFile(data, openPath, confident);
                    // Write newFile to temporary file
                    var tmpFile = tmpDir + '/' + openPath.replace(/\//g, '_') + '_' + (new Date()).getTime() + '.tmp';
                    var success = (0, util_1.writeFile)(tmpFile, newFile);
                    if (!success) {
                        (0, log_1.error)("Failed to write temporary file " + tmpFile + " for " + openPath + " replacement");
                        return;
                    }
                    // Replace file descriptor
                    var tmpFilePath = Memory.allocUtf8String(tmpFile);
                    var fd = open(tmpFilePath, flags);
                    if (fd == -1) {
                        (0, log_1.error)("Failed to open temporary file for " + openPath + " replacement");
                        return;
                    }
                    _this.fileDescriptors[fd] = openPath;
                    close(data.retval.toInt32());
                    data.retval.replace(fd);
                }
            }
        };
        (0, native_1.addPostHook)(['open', 'open_dprotected_np', 'open_extended', 'open_nocancel', 'guarded_open_np', 'guarded_open_dprotected_np', 'creat'], ['str', 'int'], function (data) {
            var openPath = data.args[0];
            replaceFileHandler(openPath, data.args[1], data);
        });
        (0, native_1.addPostHook)(['openat', 'openat_nocancel'], ['int', 'str', 'int'], function (data) {
            var openPath = data.args[1];
            if (data.args[0] && _this.fileDescriptors[data.args[0]])
                openPath = _this.fileDescriptors[data.args[0]] + '/' + openPath;
            replaceFileHandler(openPath, data.args[2], data);
        });
    };
    return FileHooks;
}());
exports.FileHooks = FileHooks;
function logFile(data, path, confident) {
    if (confident === void 0) { confident = true; }
    (0, log_1.log)({
        type: 'file',
        context: 'native',
        "function": data.syscall,
        args: data.args,
        confident: confident,
        file: path
    }, data.context.context, data.detector);
}


/***/ }),

/***/ "./src/frida/hooks/java.ts":
/*!*********************************!*\
  !*** ./src/frida/hooks/java.ts ***!
  \*********************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";

var __spreadArray = (this && this.__spreadArray) || function (to, from, pack) {
    if (pack || arguments.length === 2) for (var i = 0, l = from.length, ar; i < l; i++) {
        if (ar || !(i in from)) {
            if (!ar) ar = Array.prototype.slice.call(from, 0, i);
            ar[i] = from[i];
        }
    }
    return to.concat(ar || Array.prototype.slice.call(from));
};
exports.__esModule = true;
exports.addJavaReplaceHook = exports.addJavaPostHook = exports.addJavaPreHook = void 0;
var log_1 = __webpack_require__(/*! ../inc/log */ "./src/frida/inc/log.ts");
var appliedHooks = [];
/**
 * Hook a Java function before calling its original implementation, allowing for the modification of arguments
 * @param fun function to hook
 * @param argTypes types of the arguments of the function to hook. Used to find the correct overload of the function. If null, the first overload is used
 * @param handler callback function to call before the original function
 * @param initJava whether to initialize Java context before hooking. Set to false if you are already in a Java.perform() block
 * @param detector detector that called this function
 */
function addJavaPreHook(fun, argTypes, handler, initJava, detector) {
    if (argTypes === void 0) { argTypes = null; }
    if (initJava === void 0) { initJava = true; }
    if (detector === void 0) { detector = null; }
    addHook(fun, 'pre', argTypes, handler, initJava, detector);
}
exports.addJavaPreHook = addJavaPreHook;
/**
 * Hook a Java function after calling its original implementation, allowing for the modification of the return value
 * @param fun function to hook
 * @param argTypes types of the arguments of the function to hook. Used to find the correct overload of the function. If null, the first overload is used
 * @param handler callback function to call after the original function
 * @param initJava whether to initialize Java context before hooking. Set to false if you are already in a Java.perform() block
 * @param detector detector that called this function
 */
function addJavaPostHook(fun, argTypes, handler, initJava, detector) {
    if (argTypes === void 0) { argTypes = null; }
    if (initJava === void 0) { initJava = true; }
    if (detector === void 0) { detector = null; }
    addHook(fun, 'post', argTypes, handler, initJava, detector);
}
exports.addJavaPostHook = addJavaPostHook;
/**
 * Hook a Java function and replace its original implementation
 * @param fun function to hook
 * @param argTypes types of the arguments of the function to hook. Used to find the correct overload of the function. If null, the first overload is used
 * @param handler callback function to call instead of the original function
 * @param initJava whether to initialize Java context before hooking. Set to false if you are already in a Java.perform() block
 * @param detector detector that called this function
 */
function addJavaReplaceHook(fun, argTypes, handler, initJava, detector) {
    if (argTypes === void 0) { argTypes = null; }
    if (initJava === void 0) { initJava = true; }
    if (detector === void 0) { detector = null; }
    addHook(fun, 'replace', argTypes, handler, initJava, detector);
}
exports.addJavaReplaceHook = addJavaReplaceHook;
/**
 * Hook a Java function
 * @param fun function to hook
 * @param type type of hook to add
 * @param argTypes types of the arguments of the function to hook. Used to find the correct overload of the function. If null, the first overload is used
 * @param handler callback function to call when hooked function is called
 * @param initJava whether to initialize Java context before hooking. Set to false if you are already in a Java.perform() block
 * @param detector detector that called this function
 */
function addHook(fun, type, argTypes, handler, initJava, detector) {
    if (initJava === void 0) { initJava = true; }
    if (detector === void 0) { detector = null; }
    if (fun == 'android.provider.Settings$Secure::getString') {
        ['Secure', 'Global'].forEach(function (cls) {
            ['String', 'Int', 'Long', 'Float'].forEach(function (varType) {
                if (varType !== 'String' || cls === 'Global') {
                    addHook("android.provider.Settings$".concat(cls, "::get").concat(varType), type, argTypes, handler);
                }
                if (varType !== 'String') {
                    addHook("android.provider.Settings$".concat(cls, "::get").concat(varType), type, __spreadArray(__spreadArray([], argTypes, true), [varType.toLowerCase()], false), handler);
                }
            });
        });
    }
    if (fun instanceof Array) {
        // Add hook for every syscall in the array
        fun.forEach(function (f) {
            addHook(f, type, argTypes, handler);
        });
        return;
    }
    if (typeof fun !== 'string') {
        // Assume Java already initialized and we are in a Java.perform() block
        initJava = false;
    }
    if (initJava && !Java.available) {
        return;
    }
    // Replace argType 'str' with 'java.lang.String'  and '[]' with '[L...;'
    if (argTypes) {
        argTypes = argTypes.map(function (argType) {
            if (argType === 'str') {
                return 'java.lang.String';
            }
            else if (argType === 'str[]') {
                return '[Ljava.lang.String;';
            }
            else if (argType.endsWith('[]')) {
                return "[L".concat(argType.slice(0, -2), ";");
            }
            else {
                return argType;
            }
        });
    }
    if (initJava && !detector) {
        detector = (0, log_1.getDetector)();
    }
    var overwriteFunction = function () {
        var javaFun;
        var funName = null;
        if (typeof fun === 'string') {
            var cls = fun.split('::')[0];
            var name_1 = fun.split('::')[1];
            var javaCls = void 0;
            try {
                javaCls = Java.use(cls);
            }
            catch (e) {
                (0, log_1.debug)("[!] Unable to find class ".concat(cls, " in Java"));
                return;
            }
            javaFun = javaCls[name_1];
            if (!javaFun) {
                (0, log_1.debug)("[!] Unable to find function ".concat(fun, " in Java"));
                return;
            }
            funName = fun.replace('$', '.');
        }
        else {
            javaFun = fun;
        }
        try {
            if (argTypes !== null) {
                javaFun = javaFun.overload.apply(javaFun, argTypes);
            }
            if (!javaFun) {
                (0, log_1.debug)("[!] Unable to find overload of function ".concat(fun, " in Java"));
                return;
            }
        }
        catch (e) {
            (0, log_1.debug)("[!] Unable to find function ".concat(fun, " with argTypes ").concat(argTypes, " in Java"));
            return;
        }
        var isHooked = appliedHooks.find(function (hook) { return hook.javaFun === javaFun; });
        appliedHooks.push({ javaFun: javaFun, type: type, handler: handler, detector: detector });
        if (!isHooked) {
            javaFun.implementation = function () {
                var _this = this;
                var args = [];
                for (var _i = 0; _i < arguments.length; _i++) {
                    args[_i] = arguments[_i];
                }
                var trace = Java.use('java.lang.Exception').$new().getStackTrace();
                if (!funName) {
                    var method = trace[0];
                    funName = method.getClassName().replace('$', '.') + "::" + method.getMethodName();
                }
                var backtrace = trace.map(function (e) { return e.toString().trim(); });
                var hooks = appliedHooks.filter(function (hook) { return hook.javaFun === javaFun; });
                var replaced = false;
                var retval;
                hooks.forEach(function (hook) {
                    if (hook.type === 'replace') {
                        var data = { fun: javaFun, funName: funName, args: args, "this": _this, detector: hook.detector, backtrace: backtrace };
                        retval = hook.handler(data);
                        replaced = true;
                    }
                });
                if (replaced) {
                    return retval;
                }
                hooks.forEach(function (hook) {
                    if (hook.type === 'pre') {
                        var data = { fun: javaFun, funName: funName, args: args, "this": _this, detector: hook.detector, backtrace: backtrace };
                        hook.handler(data);
                        // Convert any string args to Java.lang.String
                        args.map(function (arg) { return arg instanceof String ? Java.use('java.lang.String').$new(arg) : arg; });
                    }
                });
                retval = javaFun.call.apply(javaFun, __spreadArray([this], args, false));
                var originalRetval = retval;
                hooks.forEach(function (hook) {
                    if (hook.type === 'post') {
                        var data = { fun: javaFun, funName: funName, args: args, "this": _this, retval: retval, detector: hook.detector, backtrace: backtrace };
                        hook.handler(data);
                        if (data.retval !== originalRetval) {
                            retval = data.retval;
                        }
                    }
                });
                return retval;
            };
        }
    };
    if (initJava) {
        Java.perform(overwriteFunction);
    }
    else {
        overwriteFunction();
    }
}


/***/ }),

/***/ "./src/frida/hooks/native.ts":
/*!***********************************!*\
  !*** ./src/frida/hooks/native.ts ***!
  \***********************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";

var __spreadArray = (this && this.__spreadArray) || function (to, from, pack) {
    if (pack || arguments.length === 2) for (var i = 0, l = from.length, ar; i < l; i++) {
        if (ar || !(i in from)) {
            if (!ar) ar = Array.prototype.slice.call(from, 0, i);
            ar[i] = from[i];
        }
    }
    return to.concat(ar || Array.prototype.slice.call(from));
};
exports.__esModule = true;
exports.convertArgs = exports.getAppliedHooks = exports.addPostHook = exports.addPreHook = void 0;
var log_1 = __webpack_require__(/*! ../inc/log */ "./src/frida/inc/log.ts");
var appliedHooks = {};
/**
 * Add a new hook to the given syscall(s) with a handler that is called before the syscall is executed (onEnter)
 * @param syscalls syscall or list of syscalls to intercept
 * @param argTypes list of types the arguments should be converted to
 * @param handler handler to call when the syscall is intercepted
 * @param mod module to search for the syscall in (defaults to null on macOS, libc.so on Android)
 */
function addPreHook(syscalls, argTypes, handler, mod) {
    if (argTypes === void 0) { argTypes = null; }
    if (mod === void 0) { mod = null; }
    addHook(syscalls, 'pre', argTypes, handler, mod);
}
exports.addPreHook = addPreHook;
/**
 * Add a new hook to the given syscall(s) with a handler that is called after the syscall has returned (onLeave)
 * @param syscalls syscall or list of syscalls to intercept
 * @param argTypes list of types the arguments should be converted to
 * @param handler handler to call when the syscall has returned
 * @param mod module to search for the syscall in (defaults to null on macOS, libc.so on Android)
 */
function addPostHook(syscalls, argTypes, handler, mod) {
    if (argTypes === void 0) { argTypes = null; }
    if (mod === void 0) { mod = null; }
    addHook(syscalls, 'post', argTypes, handler, mod);
}
exports.addPostHook = addPostHook;
/**
 * Add a new hook to the given syscall(s)
 * @param syscall syscall or list of syscalls to intercept
 * @param type call handler either on onEnter (pre) or onLeave (post)
 * @param argTypes list of types the arguments should be converted to
 * @param handler handler to call when the syscall is intercepted
 * @param mod module to search for the syscall in (defaults to null on macOS, libc.so on Android)
 */
function addHook(syscall, type, argTypes, handler, mod) {
    if (mod === void 0) { mod = null; }
    if (syscall instanceof Array) {
        // Add hook for every syscall in the array
        syscall.forEach(function (s) {
            addHook(s, type, argTypes, handler);
        });
        return;
    }
    // Also add a hook for the 64 bit version of the syscall
    if (!syscall.endsWith('64'))
        addHook(syscall + '64', type, argTypes, handler);
    if (mod === null) {
        // On iOS, the syscalls are spread over multiple modules so we let Frida find the correct module
        mod = Process.platform === 'darwin' ? null : 'libc.so';
    }
    var syscallPointer = Module.findExportByName(mod, syscall);
    if (syscallPointer === null) {
        if (!syscall.endsWith('64')) {
            var androidOnlySyscalls = ['android_fdsan_close_with_tag', 'android_fdsan_set_owner_tag', 'readdir64_r', 'execvpe'];
            if (Process.platform == 'darwin' && androidOnlySyscalls.indexOf(syscall) >= 0)
                return;
            (0, log_1.debug)("[!] Unable to find syscall", syscall);
        }
        return;
    }
    var detector = (0, log_1.getDetector)();
    if (appliedHooks[syscall] === undefined) {
        // We only apply one hook to a syscall because we get undefined behaviour when we attach multiple times
        appliedHooks[syscall] = [];
        appliedHooks[syscall].push({ syscall: syscall, type: type, argTypes: argTypes, handler: handler, detector: detector, args: null });
        Interceptor.attach(syscallPointer, {
            onEnter: function (args) {
                var _this = this;
                var hooks = appliedHooks[syscall];
                hooks.forEach(function (hook) {
                    // Save arguments for post hook
                    hook.args = convertArgs(args, hook.argTypes, syscall);
                    if (hook.type === 'pre') {
                        var hookArgs = __spreadArray([], hook.args, true);
                        var data = { args: hook.args, syscall: syscall, context: _this, detector: hook.detector };
                        hook.handler(data);
                        // Replace arguments if they were changed
                        for (var i = 0; i < hookArgs.length; i++) {
                            if (hookArgs[i] !== hook.args[i]) {
                                // If string, use Memory.allocUtf8String
                                if (typeof hook.args[i] === 'string') {
                                    args[i] = Memory.allocUtf8String(hook.args[i]);
                                }
                                else if (typeof hook.args[i] === 'number') {
                                    if (hook.argTypes[i] === 'uint' || hook.argTypes[i] === 'int') {
                                        args[i] = ptr(hook.args[i]);
                                    }
                                    else if (hook.argTypes[i] === 'long') {
                                        args[i].writeLong(hook.args[i]);
                                    }
                                }
                                else {
                                    args[i] = hook.args[i];
                                }
                            }
                        }
                    }
                });
            },
            onLeave: function (retval) {
                var _this = this;
                var hooks = appliedHooks[syscall];
                hooks.forEach(function (hook) {
                    if (hook.type !== 'post')
                        return;
                    var data = { args: hook.args, retval: retval, syscall: syscall, context: _this, detector: hook.detector };
                    hook.handler(data);
                });
            }
        });
    }
    else {
        appliedHooks[syscall].push({ syscall: syscall, type: type, argTypes: argTypes, handler: handler, detector: detector, args: null });
    }
}
/**
 * Get a list of all the hooked native functions
 * @returns list of all the hooked native functions as a dictionary mapping the syscall name to the hook
 */
function getAppliedHooks() {
    return appliedHooks;
}
exports.getAppliedHooks = getAppliedHooks;
/**
 * Convert arguments from NativePointers to the given types
 * @param args arguments as a list of NativePointers
 * @param argTypes types the arguments need to be converted to, indexes correspond with elements in args
 * @param syscall the syscall for which the arguments are converted
 * @returns list of converted arguments
 */
function convertArgs(args, argTypes, syscall) {
    if (argTypes === null)
        return args;
    var convertedArgs = [];
    // Convert argument types
    for (var i = 0; i < argTypes.length; i++) {
        try {
            switch (argTypes[i]) {
                case 'str':
                    convertedArgs.push(args[i].readCString());
                    break;
                case 'uint':
                    convertedArgs.push(args[i].toUInt32());
                    break;
                case 'int':
                    convertedArgs.push(args[i].toInt32());
                    break;
                case 'long':
                    convertedArgs.push(args[i].readLong());
                case 'ptr':
                    convertedArgs.push(args[i]);
                    break;
                case 'str[]':
                    convertedArgs.push([]);
                    var arrayI = 0;
                    while (!args[i].add(arrayI).readPointer().isNull()) {
                        convertedArgs[i].push(args[i].add(arrayI).readPointer().readCString());
                        arrayI += Process.pointerSize;
                    }
                default:
                    (0, log_1.debug)("argType", argTypes[i], "is not implemented");
                    convertedArgs.push(null);
            }
        }
        catch (e) {
            convertedArgs.push(null);
            if (e.toString().indexOf("access violation") != -1)
                continue;
            (0, log_1.debug)("Failed to convert argument", i, "of syscall", syscall, ":", e);
        }
    }
    return convertedArgs;
}
exports.convertArgs = convertArgs;


/***/ }),

/***/ "./src/frida/hooks/objc.ts":
/*!*********************************!*\
  !*** ./src/frida/hooks/objc.ts ***!
  \*********************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

exports.__esModule = true;
exports.addObjCPostHook = exports.addObjCPreHook = void 0;
var log_1 = __webpack_require__(/*! ../inc/log */ "./src/frida/inc/log.ts");
var appliedHooks = [];
/**
 * Hook an Objective-C function before calling its original implementation, allowing for the modification of arguments
 * @param fun function to hook
 * @param argCount number of arguments the function takes
 * @param handler callback function to call before the original function
 * @param detector detector that called this function
 */
function addObjCPreHook(fun, argCount, handler, detector) {
    if (detector === void 0) { detector = null; }
    addHook(fun, argCount, 'pre', handler, detector);
}
exports.addObjCPreHook = addObjCPreHook;
/**
 * Hook an Objective-C function after calling its original implementation, allowing for the modification of the return value
 * @param fun function to hook
 * @param argCount number of arguments the function takes
 * @param handler callback function to call after the original function
 * @param detector detector that called this function
 */
function addObjCPostHook(fun, argCount, handler, detector) {
    if (detector === void 0) { detector = null; }
    addHook(fun, argCount, 'post', handler, detector);
}
exports.addObjCPostHook = addObjCPostHook;
/**
 * Hook an Objective-C function and replace its original implementation
 * @param fun function to hook
 * @param argCount number of arguments the function takes
 * @param handler callback function to call instead of the original function
 * @param detector detector that called this function
 */
function addHook(fun, argCount, type, handler, detector) {
    if (detector === void 0) { detector = null; }
    // TODO: Does this work properly if the same function is hooked multiple times?
    if (fun instanceof Array) {
        // Add hook for every syscall in the array
        fun.forEach(function (f) {
            addHook(f, argCount, type, handler);
        });
        return;
    }
    if (!ObjC.available) {
        return;
    }
    if (detector == null) {
        detector = (0, log_1.getDetector)();
    }
    var objcFun;
    var funName = null;
    if (typeof fun === 'string') {
        var modifier = fun.substring(0, 1);
        var identifier = fun.substring(1).replace('[', '').replace(']', '').split(' ');
        var cls = identifier[0];
        var name_1 = identifier[1];
        var objcCls = ObjC.classes[cls];
        if (objcCls === undefined && cls == 'NSApplication') {
            cls = 'UIApplication';
            objcCls = ObjC.classes[cls];
        }
        if (objcCls === undefined) {
            (0, log_1.debug)("[!] Unable to find class ".concat(cls, " in Objective-C"));
            return;
        }
        objcFun = objcCls[modifier + ' ' + name_1];
        if (objcFun === undefined) {
            (0, log_1.debug)("[!] Unable to find function ".concat(fun, " in Objective-C"));
            return;
        }
    }
    else {
        objcFun = fun;
    }
    var isHooked = appliedHooks.find(function (h) { return h.objcFun === objcFun; });
    appliedHooks.push({ objcFun: objcFun, type: type, handler: handler, detector: detector });
    if (!isHooked) {
        var self_1;
        var selector_1;
        var funArgs_1;
        Interceptor.attach(objcFun.implementation, {
            onEnter: function (args) {
                var _this = this;
                self_1 = new ObjC.Object(args[0]);
                selector_1 = ObjC.selectorAsString(args[1]);
                funArgs_1 = [];
                for (var i = 0; i < argCount; i++) {
                    funArgs_1.push(args[i + 2]);
                }
                if (!funName) {
                    var method = self_1.$methods.find(function (m) { return m.endsWith(' ' + selector_1); });
                    funName = method.substring(0, 1) + '[' + self_1.$className + ' ' + method.substring(2) + ']';
                }
                var hooks = appliedHooks.filter(function (h) { return h.objcFun === objcFun; });
                hooks.forEach(function (hook) {
                    if (hook.type === 'pre') {
                        var data = { fun: objcFun, funName: funName, args: funArgs_1, self: self_1, "this": _this, detector: hook.detector };
                        hook.handler(data);
                        for (var i = 0; i < argCount; i++) {
                            args[i + 2] = funArgs_1[i];
                        }
                    }
                });
            },
            onLeave: function (retval) {
                var _this = this;
                var hooks = appliedHooks.filter(function (h) { return h.objcFun === objcFun; });
                hooks.forEach(function (hook) {
                    if (hook.type === 'post') {
                        var data = { fun: objcFun, funName: funName, args: funArgs_1, self: self_1, "this": _this, retval: retval, detector: hook.detector };
                        hook.handler(data);
                    }
                });
            }
        });
    }
}


/***/ }),

/***/ "./src/frida/hooks/socket.ts":
/*!***********************************!*\
  !*** ./src/frida/hooks/socket.ts ***!
  \***********************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";

var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
exports.__esModule = true;
exports.addOpenPortHook = void 0;
var log_1 = __webpack_require__(/*! ../inc/log */ "./src/frida/inc/log.ts");
var native_1 = __webpack_require__(/*! ./native */ "./src/frida/hooks/native.ts");
/**
 * Will pretend that the given port is unused even if it might be open, and log checks for this
 * @param port
 */
function addOpenPortHook(port) {
    var openPortHandler = function (data, sockaddr) {
        if (sockaddr.isNull())
            return;
        var ntohs = new NativeFunction(Module.findExportByName(null, 'ntohs'), 'uint', ['uint']);
        var ntohl = new NativeFunction(Module.findExportByName(null, 'ntohl'), 'uint', ['uint']);
        var sockFamily = sockaddr.readShort();
        var sockPort = ntohs(sockaddr.add(2).readUShort());
        var sockAddr = ntohl(sockaddr.add(4).readU32());
        if (sockFamily == 2 && sockPort == port && (sockAddr == 0 || sockAddr == 0x7f000001)) {
            (0, log_1.logFunction)(__assign(__assign({}, data), { args: [
                    {
                        family: sockFamily,
                        port: sockPort,
                        addr: sockAddr
                    },
                ] }));
            return true;
        }
        return false;
    };
    // Signature: int sockfd, struct sockaddr *addr, socklen_t addrlen
    var sockFunctions1 = ['connect', 'bind', 'accept', 'getpeername', 'getsockname'];
    (0, native_1.addPreHook)(sockFunctions1, ['int', 'ptr', 'ptr'], function (data) {
        var sockaddr = data.args[1];
        if (openPortHandler(data, sockaddr)) {
            // Assign random port
            sockaddr.add(2).writeUShort(0);
        }
    });
    (0, native_1.addPostHook)(sockFunctions1, ['int', 'ptr', 'ptr'], function (data) {
        var sockaddr = data.args[1];
        if (openPortHandler(data, sockaddr)) {
            // Restore port
            sockaddr.add(2).writeUShort(port);
        }
    });
    // Signature: int sockfd, void *buf, size_t len, int flags, struct sockaddr *addr, socklen_t *addrlen
    var sockFunctions2 = ['recvfrom', 'sendto'];
    (0, native_1.addPreHook)(sockFunctions2, ['int', 'ptr', 'int', 'int', 'ptr', 'ptr'], function (data) {
        var sockaddr = data.args[4];
        if (openPortHandler(data, sockaddr)) {
            // Assign random port
            sockaddr.add(2).writeUShort(0);
        }
    });
    (0, native_1.addPostHook)(sockFunctions2, ['int', 'ptr', 'int', 'int', 'ptr', 'ptr'], function (data) {
        var sockaddr = data.args[4];
        if (openPortHandler(data, sockaddr)) {
            // Restore port
            sockaddr.add(2).writeUShort(port);
        }
    });
}
exports.addOpenPortHook = addOpenPortHook;


/***/ }),

/***/ "./src/frida/inc/dump.ts":
/*!*******************************!*\
  !*** ./src/frida/inc/dump.ts ***!
  \*******************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

exports.__esModule = true;
var log_1 = __webpack_require__(/*! ./log */ "./src/frida/inc/log.ts");
var util_1 = __webpack_require__(/*! ./util */ "./src/frida/inc/util.ts");
/*
This file is a modified version of frida-ios-dump by AloneMonkey:
https://github.com/AloneMonkey/frida-ios-dump/blob/master/dump.js
Changes:
- Decrypt module in memory and send to python with Frida message instead of writing to file and copying with SCP
- Remove unused code
- Replace console.log with debug/warn function
- Add error handling to library loading
*/
Module.ensureInitialized('Foundation');
var O_RDONLY = 0;
var SEEK_SET = 0;
var SEEK_END = 2;
function allocStr(str) {
    return Memory.allocUtf8String(str);
}
function getU32(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    //@ts-ignore
    return Memory.readU32(addr);
}
function putU64(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    //@ts-ignore
    return Memory.writeU64(addr, n);
}
function malloc(size) {
    return Memory.alloc(size);
}
function getExportFunction(type, name, ret, args) {
    var nptr;
    nptr = Module.findExportByName(null, name);
    if (nptr === null) {
        (0, log_1.warn)("cannot find " + name);
        return null;
    }
    else {
        if (type === "f") {
            var funclet = new NativeFunction(nptr, ret, args);
            if (typeof funclet === "undefined") {
                (0, log_1.warn)("parse error " + name);
                return null;
            }
            return funclet;
        }
        else if (type === "d") {
            //@ts-ignore
            var datalet = Memory.readPointer(nptr);
            if (typeof datalet === "undefined") {
                (0, log_1.warn)("parse error " + name);
                return null;
            }
            return datalet;
        }
    }
}
var wrapper_open = getExportFunction("f", "open", "int", ["pointer", "int", "int"]);
var read = getExportFunction("f", "read", "int", ["int", "pointer", "int"]);
var lseek = getExportFunction("f", "lseek", "int64", ["int", "int64", "int"]);
var close = getExportFunction("f", "close", "int", ["int"]);
var dlopen = getExportFunction("f", "dlopen", "pointer", ["pointer", "int"]);
function open(pathname, flags, mode) {
    if (typeof pathname == "string") {
        pathname = allocStr(pathname);
    }
    return wrapper_open(pathname, flags, mode);
}
var modules = null;
function getAllAppModules() {
    modules = new Array();
    var tmpmods = Process.enumerateModules();
    for (var i = 0; i < tmpmods.length; i++) {
        if (tmpmods[i].path.indexOf(".app") != -1) {
            modules.push(tmpmods[i]);
        }
    }
    return modules;
}
var FAT_MAGIC = 0xcafebabe;
var FAT_CIGAM = 0xbebafeca;
var MH_MAGIC = 0xfeedface;
var MH_CIGAM = 0xcefaedfe;
var MH_MAGIC_64 = 0xfeedfacf;
var MH_CIGAM_64 = 0xcffaedfe;
var LC_ENCRYPTION_INFO = 0x21;
var LC_ENCRYPTION_INFO_64 = 0x2C;
function pad(str, n) {
    return Array(n - str.length + 1).join("0") + str;
}
function swap32(value) {
    value = pad(value.toString(16), 8);
    var result = "";
    for (var i = 0; i < value.length; i = i + 2) {
        result += value.charAt(value.length - i - 2);
        result += value.charAt(value.length - i - 1);
    }
    return parseInt(result, 16);
}
function dumpModule(name) {
    if (modules == null) {
        modules = getAllAppModules();
    }
    var targetmod = null;
    for (var i = 0; i < modules.length; i++) {
        if (modules[i].path.indexOf(name) != -1) {
            targetmod = modules[i];
            break;
        }
    }
    if (targetmod == null) {
        (0, log_1.warn)("Cannot find module");
        return;
    }
    var modbase = targetmod.base;
    var modpath = targetmod.path;
    var foldmodule = open(modpath, O_RDONLY, 0);
    if (foldmodule == -1) {
        (0, log_1.warn)("Cannot open file" + foldmodule);
        return;
    }
    var size_of_mach_header = 0;
    var magic = getU32(modbase);
    var cur_cpu_type = getU32(modbase.add(4));
    var cur_cpu_subtype = getU32(modbase.add(8));
    if (magic == MH_MAGIC || magic == MH_CIGAM) {
        size_of_mach_header = 28;
    }
    else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        size_of_mach_header = 32;
    }
    var BUFSIZE = 4096;
    var buffer = malloc(BUFSIZE);
    read(foldmodule, buffer, BUFSIZE);
    var fileoffset = 0;
    var filesize = 0;
    var fmodule_offset = 0;
    magic = getU32(buffer);
    if (magic == FAT_CIGAM || magic == FAT_MAGIC) {
        var off = 4;
        var archs = swap32(getU32(buffer.add(off)));
        for (var i = 0; i < archs; i++) {
            var cputype = swap32(getU32(buffer.add(off + 4)));
            var cpusubtype = swap32(getU32(buffer.add(off + 8)));
            if (cur_cpu_type == cputype && cur_cpu_subtype == cpusubtype) {
                fileoffset = swap32(getU32(buffer.add(off + 12)));
                filesize = swap32(getU32(buffer.add(off + 16)));
                break;
            }
            off += 20;
        }
        var fmodule = malloc(filesize);
        if (fileoffset == 0 || filesize == 0)
            return;
        lseek(foldmodule, fileoffset, SEEK_SET);
        //@ts-ignore
        for (var i = 0; i < parseInt(filesize / BUFSIZE); i++) {
            read(foldmodule, buffer, BUFSIZE);
            Memory.copy(fmodule.add(fmodule_offset), buffer, BUFSIZE);
            fmodule_offset += BUFSIZE;
        }
        if (filesize % BUFSIZE) {
            read(foldmodule, buffer, filesize % BUFSIZE);
            Memory.copy(fmodule.add(fmodule_offset), buffer, filesize % BUFSIZE);
            fmodule_offset += filesize % BUFSIZE;
        }
    }
    else {
        filesize = parseInt(lseek(foldmodule, 0, SEEK_END));
        var fmodule = malloc(filesize);
        var readLen = 0;
        lseek(foldmodule, 0, SEEK_SET);
        while (readLen = read(foldmodule, buffer, BUFSIZE)) {
            Memory.copy(fmodule.add(fmodule_offset), buffer, readLen);
            fmodule_offset += readLen;
        }
    }
    var ncmds = getU32(modbase.add(16));
    var off = size_of_mach_header;
    var offset_cryptid = -1;
    var crypt_off = 0;
    var crypt_size = 0;
    for (var i = 0; i < ncmds; i++) {
        var cmd = getU32(modbase.add(off));
        var cmdsize = getU32(modbase.add(off + 4));
        if (cmd == LC_ENCRYPTION_INFO || cmd == LC_ENCRYPTION_INFO_64) {
            offset_cryptid = off + 16;
            crypt_off = getU32(modbase.add(off + 8));
            crypt_size = getU32(modbase.add(off + 12));
        }
        off += cmdsize;
    }
    if (offset_cryptid != -1) {
        var tpbuf = malloc(8);
        putU64(tpbuf, 0);
        fmodule_offset = offset_cryptid;
        Memory.copy(fmodule.add(fmodule_offset), tpbuf, 4);
        fmodule_offset = crypt_off;
        Memory.copy(fmodule.add(fmodule_offset), modbase.add(crypt_off), crypt_size);
    }
    close(foldmodule);
    // Send max 64 MiB at a time
    var maxSize = 0x4000000;
    for (var offset = 0; offset < filesize; offset += maxSize) {
        var readLength = Math.min(maxSize, filesize - offset);
        send({ type: 'dump', complete: false, module: targetmod.name, path: modpath, offset: offset }, fmodule.add(offset).readByteArray(readLength));
    }
}
function loadAllDynamicLibrary(app_path) {
    var defaultManager = ObjC.classes.NSFileManager.defaultManager();
    var errorPtr = Memory.alloc(Process.pointerSize);
    //@ts-ignore
    Memory.writePointer(errorPtr, NULL);
    var filenames = defaultManager.contentsOfDirectoryAtPath_error_(app_path, errorPtr);
    for (var i = 0, l = filenames.count(); i < l; i++) {
        var file_name = filenames.objectAtIndex_(i);
        var file_path = app_path.stringByAppendingPathComponent_(file_name);
        if (file_name.hasSuffix_(".framework")) {
            var bundle = ObjC.classes.NSBundle.bundleWithPath_(file_path);
            if (bundle.isLoaded()) {
                (0, log_1.debug)(file_name + " has been loaded. ");
            }
            else {
                if (bundle.load()) {
                    (0, log_1.debug)("Load " + file_name + " success. ");
                }
                else {
                    (0, log_1.warn)("Load " + file_name + " failed. ");
                }
            }
        }
        else if (file_name.hasSuffix_(".bundle") ||
            file_name.hasSuffix_(".momd") ||
            file_name.hasSuffix_(".strings") ||
            file_name.hasSuffix_(".appex") ||
            file_name.hasSuffix_(".app") ||
            file_name.hasSuffix_(".lproj") ||
            file_name.hasSuffix_(".storyboardc")) {
            continue;
        }
        else {
            var isDirPtr = Memory.alloc(Process.pointerSize);
            //@ts-ignore
            Memory.writePointer(isDirPtr, NULL);
            defaultManager.fileExistsAtPath_isDirectory_(file_path, isDirPtr);
            //@ts-ignore
            if (Memory.readPointer(isDirPtr) == 1) {
                loadAllDynamicLibrary(file_path);
            }
            else {
                if (file_name.hasSuffix_(".dylib")) {
                    var is_loaded = 0;
                    for (var j = 0; j < modules.length; j++) {
                        if (modules[j].path.indexOf(file_name) != -1) {
                            is_loaded = 1;
                            (0, log_1.debug)(file_name + " has been dlopen.");
                            break;
                        }
                    }
                    if (!is_loaded) {
                        // Added error handling via try catch to prevent program from crashing
                        // when a library cannot be loaded.
                        var file_path_ptr = allocStr(file_path.UTF8String());
                        try {
                            if (dlopen(file_path_ptr, 9)) {
                                (0, log_1.debug)("dlopen " + file_name + " success. ");
                            }
                            else {
                                (0, log_1.warn)("dlopen " + file_name + " failed. ");
                            }
                        }
                        catch (e) {
                            (0, log_1.warn)("dlopen " + file_name + " failed: " + e.message);
                        }
                    }
                }
            }
        }
    }
}
function dumpModules() {
    modules = getAllAppModules();
    var app_path = ObjC.classes.NSBundle.mainBundle().bundlePath();
    loadAllDynamicLibrary(app_path);
    // start dump
    modules = getAllAppModules();
    for (var i = 0; i < modules.length; i++) {
        dumpModule(modules[i].path);
    }
    send({ type: 'dump', complete: true });
}
(0, util_1.addRpcExports)({
    dumpModules: dumpModules
});


/***/ }),

/***/ "./src/frida/inc/log.ts":
/*!******************************!*\
  !*** ./src/frida/inc/log.ts ***!
  \******************************/
/***/ ((__unused_webpack_module, exports) => {

"use strict";

exports.__esModule = true;
exports.debug = exports.info = exports.warn = exports.error = exports.getDetector = exports.logObjCFunction = exports.logJavaFunction = exports.logFunction = exports.log = void 0;
var sentModules = [];
/**
 * Send a message to Python
 * @param message message to send
 * @param context context of the program, used to attach a backtrace to the message
 * @param detector detector that called this function
 */
function log(data, context, detector) {
    if (detector === void 0) { detector = null; }
    // Extract detector caller from stack trace
    if (detector === null)
        detector = getDetector();
    data.detector = detector;
    var modules = Process.enumerateModules();
    if (modules.length > sentModules.length) {
        // New modules have been loaded, send them to python
        send({
            type: 'modules',
            modules: modules
        });
        sentModules = modules;
    }
    // Add native backtrace
    if (data.backtrace == undefined) {
        data.backtrace = Thread.backtrace(context, Backtracer.FUZZY);
    }
    if (Java.available && data.context != 'java') {
        // Add java backtrace
        Java.perform(function () {
            var trace = Java.use('java.lang.Exception').$new().getStackTrace();
            data['java_backtrace'] = trace.map(function (e) { return e.toString().trim(); });
            // Send to python
            send(data);
        });
    }
    else {
        // Send to python
        send(data);
    }
}
exports.log = log;
function logFunction(data, confident) {
    if (confident === void 0) { confident = true; }
    log({
        type: 'function',
        context: 'native',
        "function": data.syscall,
        args: data.args,
        confident: confident
    }, data.context.context, data.detector);
}
exports.logFunction = logFunction;
function logJavaFunction(data, confident) {
    if (confident === void 0) { confident = true; }
    log({
        type: 'function',
        context: 'java',
        "function": data.funName,
        args: data.args,
        backtrace: data.backtrace,
        confident: confident
    }, data["this"].context, data.detector);
}
exports.logJavaFunction = logJavaFunction;
function logObjCFunction(data, confident) {
    if (confident === void 0) { confident = true; }
    log({
        type: 'function',
        context: 'objc',
        "function": data.funName,
        args: data.args.map(function (arg) { return new ObjC.Object(arg).toString(); }),
        confident: confident
    }, data["this"].context, data.detector);
}
exports.logObjCFunction = logObjCFunction;
function getDetector() {
    var stack = (new Error()).stack;
    var detectorMatch = stack.match('detectors/([^\.]+).ts');
    if (detectorMatch) {
        return detectorMatch[1];
    }
    else if (stack.indexOf('/script1.js') == -1) {
        debug(stack);
        return null;
    }
}
exports.getDetector = getDetector;
function error() {
    var message = [];
    for (var _i = 0; _i < arguments.length; _i++) {
        message[_i] = arguments[_i];
    }
    send({
        type: 'log',
        level: 'error',
        message: message.join(' ')
    });
}
exports.error = error;
function warn() {
    var message = [];
    for (var _i = 0; _i < arguments.length; _i++) {
        message[_i] = arguments[_i];
    }
    send({
        type: 'log',
        level: 'warning',
        message: message.join(' ')
    });
}
exports.warn = warn;
function info() {
    var message = [];
    for (var _i = 0; _i < arguments.length; _i++) {
        message[_i] = arguments[_i];
    }
    send({
        type: 'log',
        level: 'info',
        message: message.join(' ')
    });
}
exports.info = info;
function debug() {
    var message = [];
    for (var _i = 0; _i < arguments.length; _i++) {
        message[_i] = arguments[_i];
    }
    send({
        type: 'log',
        level: 'debug',
        message: message.join(' ')
    });
}
exports.debug = debug;


/***/ }),

/***/ "./src/frida/inc/util.ts":
/*!*******************************!*\
  !*** ./src/frida/inc/util.ts ***!
  \*******************************/
/***/ ((__unused_webpack_module, exports) => {

"use strict";

exports.__esModule = true;
exports.addRpcExports = exports.writeFile = exports.readFile = exports.syscall = void 0;
/**
 * Create a NativeFunction that calls a syscall
 * @param name syscall name
 * @param returnValue return value type
 * @param args argument types
 * @returns NativeFunction or null if syscall doesn't exist
 */
function syscall(name, returnValue, args) {
    var addr = Module.findExportByName(null, name);
    if (addr === null)
        return null;
    return new NativeFunction(addr, returnValue, args);
}
exports.syscall = syscall;
/**
 * Read a file from the filesystem
 * @param path path to the file
 * @returns file contents or null if file doesn't exist
 */
function readFile(path) {
    var open = syscall('open', 'int', ['pointer', 'int']);
    var read = syscall('read', 'int', ['int', 'pointer', 'int']);
    var close = syscall('close', 'int', ['int']);
    var fd = open(Memory.allocUtf8String(path), 0);
    if (fd === -1)
        return null;
    var content = '';
    var buf = Memory.alloc(4096);
    while (true) {
        var readBytes = read(fd, buf, 4096);
        if (readBytes === -1)
            return null;
        if (readBytes === 0)
            break;
        content += buf.readUtf8String(readBytes);
    }
    close(fd);
    return content;
}
exports.readFile = readFile;
/**
 * Write content to a file in the filesystem
 * @param path file to write to
 * @param content content to write
 * @returns true if successful, false otherwise
 */
function writeFile(path, content) {
    try {
        // @ts-ignore
        var file = new File(path, 'w');
        // @ts-ignore
        file.write(content);
        // @ts-ignore
        file.flush();
        // @ts-ignore
        file.close();
        return true;
    }
    catch (e) {
        return false;
    }
}
exports.writeFile = writeFile;
/**
 * Add functions to the rpc.exports object
 * @param exports functions to add
 */
function addRpcExports(exports) {
    Object.assign(rpc.exports, exports);
}
exports.addRpcExports = addRpcExports;


/***/ }),

/***/ "./src/frida/detectors sync recursive \\.ts$":
/*!*****************************************!*\
  !*** ./src/frida/detectors/ sync \.ts$ ***!
  \*****************************************/
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

var map = {
	"./debug.ts": "./src/frida/detectors/debug.ts",
	"./emulation.ts": "./src/frida/detectors/emulation.ts",
	"./hooking.ts": "./src/frida/detectors/hooking.ts",
	"./info.ts": "./src/frida/detectors/info.ts",
	"./keylogger.ts": "./src/frida/detectors/keylogger.ts",
	"./lockscreen.ts": "./src/frida/detectors/lockscreen.ts",
	"./pinning.ts": "./src/frida/detectors/pinning.ts",
	"./root.ts": "./src/frida/detectors/root.ts",
	"./screenreader.ts": "./src/frida/detectors/screenreader.ts",
	"./svc.ts": "./src/frida/detectors/svc.ts",
	"./tamper.ts": "./src/frida/detectors/tamper.ts"
};


function webpackContext(req) {
	var id = webpackContextResolve(req);
	return __webpack_require__(id);
}
function webpackContextResolve(req) {
	if(!__webpack_require__.o(map, req)) {
		var e = new Error("Cannot find module '" + req + "'");
		e.code = 'MODULE_NOT_FOUND';
		throw e;
	}
	return map[req];
}
webpackContext.keys = function webpackContextKeys() {
	return Object.keys(map);
};
webpackContext.resolve = webpackContextResolve;
module.exports = webpackContext;
webpackContext.id = "./src/frida/detectors sync recursive \\.ts$";

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/global */
/******/ 	(() => {
/******/ 		__webpack_require__.g = (function() {
/******/ 			if (typeof globalThis === 'object') return globalThis;
/******/ 			try {
/******/ 				return this || new Function('return this')();
/******/ 			} catch (e) {
/******/ 				if (typeof window === 'object') return window;
/******/ 			}
/******/ 		})();
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/hasOwnProperty shorthand */
/******/ 	(() => {
/******/ 		__webpack_require__.o = (obj, prop) => (Object.prototype.hasOwnProperty.call(obj, prop))
/******/ 	})();
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry need to be wrapped in an IIFE because it need to be isolated against other modules in the chunk.
(() => {
/*!***************************!*\
  !*** ./src/frida/main.ts ***!
  \***************************/
__webpack_require__.g.context = '{{context}}';
__webpack_require__.g.safeMode = '{{safeMode}}';
if (Java.available) {
    // Save the application's class loader since the default class loader is
    // replaced by Frida's class loader after using Java.registerClass
    Java.perform(function () {
        __webpack_require__.g.appClassLoader = Java.classFactory.loader;
    });
}
__webpack_require__(/*! ./inc/util */ "./src/frida/inc/util.ts");
if (Process.platform == 'darwin') {
    __webpack_require__(/*! ./inc/dump */ "./src/frida/inc/dump.ts");
}
// Register detectors
var detectors = __webpack_require__("./src/frida/detectors sync recursive \\.ts$");
for (var _i = 0, _a = detectors.keys(); _i < _a.length; _i++) {
    var key = _a[_i];
    detectors(key);
}

})();

/******/ })()
;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,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QztBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxpQkFBaUI7QUFDakI7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsNEJBQTRCLHFCQUFxQjtBQUNqRDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsU0FBUztBQUNUO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsU0FBUztBQUNUO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxTQUFTO0FBQ1Q7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsU0FBUztBQUNUO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxTQUFTO0FBQ1Q7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsU0FBUztBQUNUO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxTQUFTO0FBQ1Q7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSw0QkFBNEIsaUJBQWlCO0FBQzdDO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSw0QkFBNEIsaUJBQWlCO0FBQzdDO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxTQUFTO0FBQ1Q7QUFDQTtBQUNBO0FBQ0E7QUFDQSw0QkFBNEIsaUJBQWlCO0FBQzdDO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxTQUFTO0FBQ1Q7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxTQUFTO0FBQ1Q7QUFDQTtBQUNBLENBQUM7QUFDRCxpQkFBaUI7Ozs7Ozs7Ozs7OztBQ3RRSjtBQUNiLGtCQUFrQjtBQUNsQixpQkFBaUIsR0FBRyxtQkFBbUI7QUFDdkMsZUFBZSxtQkFBTyxDQUFDLDZDQUFVO0FBQ2pDLFlBQVksbUJBQU8sQ0FBQywwQ0FBWTtBQUNoQyxhQUFhLG1CQUFPLENBQUMsNENBQWE7QUFDbEM7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsMEJBQTBCLHFCQUFNO0FBQ2hDO0FBQ0EsWUFBWSxxQkFBTSwwQ0FBMEMscUJBQU07QUFDbEU7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsQ0FBQztBQUNELG1CQUFtQjtBQUNuQjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsZ0RBQWdELDRCQUE0QjtBQUM1RTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLG9DQUFvQztBQUNwQztBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsU0FBUztBQUNUO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxTQUFTO0FBQ1Q7QUFDQTtBQUNBO0FBQ0E7QUFDQSxTQUFTO0FBQ1Q7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsNENBQTRDLGdEQUFnRDtBQUM1RjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxTQUFTO0FBQ1Q7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLHlDQUF5QztBQUN6QztBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0E7QUFDQSxn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VUFDQTtVQUNBOztVQUVBO1VBQ0E7O1VBRUE7VUFDQTtVQUNBOzs7OztXQ3RCQTtXQUNBO1dBQ0E7V0FDQTtXQUNBLEdBQUc7V0FDSDtXQUNBO1dBQ0EsQ0FBQzs7Ozs7V0NQRDs7Ozs7Ozs7OztBQ0FBLHFCQUFNLGNBQWMsU0FBUztBQUM3QixxQkFBTSxlQUFlLFVBQVU7QUFDL0I7QUFDQTtBQUNBO0FBQ0E7QUFDQSxRQUFRLHFCQUFNO0FBQ2QsS0FBSztBQUNMO0FBQ0EsbUJBQU8sQ0FBQywyQ0FBWTtBQUNwQjtBQUNBLElBQUksbUJBQU8sQ0FBQywyQ0FBWTtBQUN4QjtBQUNBO0FBQ0EsZ0JBQWdCLGtFQUE2QztBQUM3RCx3Q0FBd0MsZ0JBQWdCO0FBQ3hEO0FBQ0E7QUFDQSIsInNvdXJjZXMiOlsid2VicGFjazovL2ZyaWRhLWFuYWx5emVyLy4vc3JjL2ZyaWRhL2RldGVjdG9ycy9kZWJ1Zy50cyIsIndlYnBhY2s6Ly9mcmlkYS1hbmFseXplci8uL3NyYy9mcmlkYS9kZXRlY3RvcnMvZW11bGF0aW9uLnRzIiwid2VicGFjazovL2ZyaWRhLWFuYWx5emVyLy4vc3JjL2ZyaWRhL2RldGVjdG9ycy9ob29raW5nLnRzIiwid2VicGFjazovL2ZyaWRhLWFuYWx5emVyLy4vc3JjL2ZyaWRhL2RldGVjdG9ycy9pbmZvLnRzIiwid2VicGFjazovL2ZyaWRhLWFuYWx5emVyLy4vc3JjL2ZyaWRhL2RldGVjdG9ycy9rZXlsb2dnZXIudHMiLCJ3ZWJwYWNrOi8vZnJpZGEtYW5hbHl6ZXIvLi9zcmMvZnJpZGEvZGV0ZWN0b3JzL2xvY2tzY3JlZW4udHMiLCJ3ZWJwYWNrOi8vZnJpZGEtYW5hbHl6ZXIvLi9zcmMvZnJpZGEvZGV0ZWN0b3JzL3Bpbm5pbmcudHMiLCJ3ZWJwYWNrOi8vZnJpZGEtYW5hbHl6ZXIvLi9zcmMvZnJpZGEvZGV0ZWN0b3JzL3Jvb3QudHMiLCJ3ZWJwYWNrOi8vZnJpZGEtYW5hbHl6ZXIvLi9zcmMvZnJpZGEvZGV0ZWN0b3JzL3NjcmVlbnJlYWRlci50cyIsIndlYnBhY2s6Ly9mcmlkYS1hbmFseXplci8uL3NyYy9mcmlkYS9kZXRlY3RvcnMvc3ZjLnRzIiwid2VicGFjazovL2ZyaWRhLWFuYWx5emVyLy4vc3JjL2ZyaWRhL2RldGVjdG9ycy90YW1wZXIudHMiLCJ3ZWJwYWNrOi8vZnJpZGEtYW5hbHl6ZXIvLi9zcmMvZnJpZGEvaG9va3MvYXBwcy50cyIsIndlYnBhY2s6Ly9mcmlkYS1hbmFseXplci8uL3NyYy9mcmlkYS9ob29rcy9maWxlLnRzIiwid2VicGFjazovL2ZyaWRhLWFuYWx5emVyLy4vc3JjL2ZyaWRhL2hvb2tzL2phdmEudHMiLCJ3ZWJwYWNrOi8vZnJpZGEtYW5hbHl6ZXIvLi9zcmMvZnJpZGEvaG9va3MvbmF0aXZlLnRzIiwid2VicGFjazovL2ZyaWRhLWFuYWx5emVyLy4vc3JjL2ZyaWRhL2hvb2tzL29iamMudHMiLCJ3ZWJwYWNrOi8vZnJpZGEtYW5hbHl6ZXIvLi9zcmMvZnJpZGEvaG9va3Mvc29ja2V0LnRzIiwid2VicGFjazovL2ZyaWRhLWFuYWx5emVyLy4vc3JjL2ZyaWRhL2luYy9kdW1wLnRzIiwid2VicGFjazovL2ZyaWRhLWFuYWx5emVyLy4vc3JjL2ZyaWRhL2luYy9sb2cudHMiLCJ3ZWJwYWNrOi8vZnJpZGEtYW5hbHl6ZXIvLi9zcmMvZnJpZGEvaW5jL3V0aWwudHMiLCJ3ZWJwYWNrOi8vZnJpZGEtYW5hbHl6ZXIvLi9zcmMvZnJpZGEvZGV0ZWN0b3JzLyBzeW5jIFxcLnRzJCIsIndlYnBhY2s6Ly9mcmlkYS1hbmFseXplci93ZWJwYWNrL2Jvb3RzdHJhcCIsIndlYnBhY2s6Ly9mcmlkYS1hbmFseXplci93ZWJwYWNrL3J1bnRpbWUvZ2xvYmFsIiwid2VicGFjazovL2ZyaWRhLWFuYWx5emVyL3dlYnBhY2svcnVudGltZS9oYXNPd25Qcm9wZXJ0eSBzaG9ydGhhbmQiLCJ3ZWJwYWNrOi8vZnJpZGEtYW5hbHl6ZXIvLi9zcmMvZnJpZGEvbWFpbi50cyJdLCJzb3VyY2VzQ29udGVudCI6WyJcInVzZSBzdHJpY3RcIjtcbnZhciBfX2Fzc2lnbiA9ICh0aGlzICYmIHRoaXMuX19hc3NpZ24pIHx8IGZ1bmN0aW9uICgpIHtcbiAgICBfX2Fzc2lnbiA9IE9iamVjdC5hc3NpZ24gfHwgZnVuY3Rpb24odCkge1xuICAgICAgICBmb3IgKHZhciBzLCBpID0gMSwgbiA9IGFyZ3VtZW50cy5sZW5ndGg7IGkgPCBuOyBpKyspIHtcbiAgICAgICAgICAgIHMgPSBhcmd1bWVudHNbaV07XG4gICAgICAgICAgICBmb3IgKHZhciBwIGluIHMpIGlmIChPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwocywgcCkpXG4gICAgICAgICAgICAgICAgdFtwXSA9IHNbcF07XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHQ7XG4gICAgfTtcbiAgICByZXR1cm4gX19hc3NpZ24uYXBwbHkodGhpcywgYXJndW1lbnRzKTtcbn07XG5leHBvcnRzLl9fZXNNb2R1bGUgPSB0cnVlO1xudmFyIGphdmFfMSA9IHJlcXVpcmUoXCIuLi9ob29rcy9qYXZhXCIpO1xudmFyIG5hdGl2ZV8xID0gcmVxdWlyZShcIi4uL2hvb2tzL25hdGl2ZVwiKTtcbnZhciBsb2dfMSA9IHJlcXVpcmUoXCIuLi9pbmMvbG9nXCIpO1xuKDAsIGphdmFfMS5hZGRKYXZhUG9zdEhvb2spKCdhbmRyb2lkLm9zLkRlYnVnOjppc0RlYnVnZ2VyQ29ubmVjdGVkJywgW10sIGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgKDAsIGxvZ18xLmxvZ0phdmFGdW5jdGlvbikoZGF0YSk7XG4gICAgZGF0YS5yZXR2YWwgPSBmYWxzZTtcbn0pO1xuKDAsIGphdmFfMS5hZGRKYXZhUG9zdEhvb2spKCdhbmRyb2lkLm9zLkRlYnVnOjp3YWl0aW5nRm9yRGVidWdnZXInLCBbXSwgZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAoMCwgbG9nXzEubG9nSmF2YUZ1bmN0aW9uKShkYXRhKTtcbiAgICBkYXRhLnJldHZhbCA9IGZhbHNlO1xufSk7XG4vLyBXZSBkb24ndCBob29rIENvbnRleHRXcmFwcGVyLmdldEFwcGxpY2F0aW9uSW5mbygpIGJlY2F1c2UgaXQgd291bGQgY2F1c2UgYSBsb3Qgb2YgZmFsc2UgcG9zaXRpdmVzXG4vLyBhbmQgbWFrZSB0aGUgYXBwIHVucmVzcG9uc2l2ZSwgZXZlbiB0aG91Z2ggaXQgY291bGQgYmUgdXNlZCB0byBjaGVjayB0aGUgYXBwIGZvciBGTEFHX0RFQlVHR0FCTEVcbigwLCBqYXZhXzEuYWRkSmF2YVBvc3RIb29rKSgnYW5kcm9pZC5wcm92aWRlci5TZXR0aW5ncyRTZWN1cmU6OmdldFN0cmluZycsIFsnYW5kcm9pZC5jb250ZW50LkNvbnRlbnRSZXNvbHZlcicsICdzdHInXSwgZnVuY3Rpb24gKGRhdGEpIHtcbiAgICBpZiAoWydhZGJfZW5hYmxlZCcsICdkZXZlbG9wbWVudF9zZXR0aW5nc19lbmFibGVkJywgJ21vY2tfbG9jYXRpb24nXS5pbmNsdWRlcyhkYXRhLmFyZ3NbMV0pKSB7XG4gICAgICAgICgwLCBsb2dfMS5sb2dKYXZhRnVuY3Rpb24pKGRhdGEpO1xuICAgICAgICBpZiAoZGF0YS5mdW5OYW1lLmluY2x1ZGVzKCdTdHJpbmcnKSkge1xuICAgICAgICAgICAgZGF0YS5yZXR2YWwgPSAnMCc7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICBkYXRhLnJldHZhbCA9IDA7XG4gICAgICAgIH1cbiAgICB9XG59KTtcbigwLCBuYXRpdmVfMS5hZGRQcmVIb29rKSgncHRyYWNlJywgWydpbnQnLCAnaW50JywgJ2ludCcsICdpbnQnXSwgZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAoMCwgbG9nXzEubG9nRnVuY3Rpb24pKGRhdGEpO1xuICAgIC8vIE5vIG5lZWQgdG8gcGF0Y2ggdmFsdWUsIHdlIGRvbid0IHVzZSB0cmFjaW5nXG59KTtcbmlmIChQcm9jZXNzLnBsYXRmb3JtID09ICdkYXJ3aW4nKSB7XG4gICAgKDAsIG5hdGl2ZV8xLmFkZFByZUhvb2spKCdzeXNjdGwnLCBbJ3B0cicsICd1aW50JywgJ3B0cicsICd1aW50JywgJ3B0cicsICd1aW50J10sIGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgICAgIHZhciBtaWIgPSBkYXRhLmFyZ3NbMF07XG4gICAgICAgIHZhciBjdGwgPSBtaWIucmVhZFUzMigpO1xuICAgICAgICB2YXIga2VybiA9IG1pYi5hZGQoNCkucmVhZFUzMigpO1xuICAgICAgICB2YXIga2VyblByb2MgPSBtaWIuYWRkKDgpLnJlYWRVMzIoKTtcbiAgICAgICAgdmFyIGtlcm5Qcm9jUGlkID0gbWliLmFkZCgxMikucmVhZFUzMigpO1xuICAgICAgICBpZiAoY3RsID09IDEgJiYga2VybiA9PSAxNCAmJiBrZXJuUHJvYyA9PSAxKSB7IC8vIDEgPSBDVExfS0VSTiwgMTQgPSBLRVJOX1BST0MsIDEgPSBLRVJOX1BST0NfUElEXG4gICAgICAgICAgICAvLyBodHRwczovL21zb2xhcmFuYS5uZXRsaWZ5LmFwcC8yMDE4LzA5LzE0L2FudGktZGVidWdnaW5nLyN1c2luZy1zeXNjdGxcbiAgICAgICAgICAgIC8vIFJldHVybmVkIHZhbHVlIGNhbiBiZSBjaGVja2VkIGZvciBQX1RSQUNFRCBmbGFnXG4gICAgICAgICAgICB2YXIgbG9nQXJncyA9IFtbY3RsLCBrZXJuLCBrZXJuUHJvYywga2VyblByb2NQaWRdXS5jb25jYXQoZGF0YS5hcmdzLnNsaWNlKDEpKTtcbiAgICAgICAgICAgICgwLCBsb2dfMS5sb2dGdW5jdGlvbikoX19hc3NpZ24oX19hc3NpZ24oe30sIGRhdGEpLCB7IGFyZ3M6IGxvZ0FyZ3MgfSksIGZhbHNlKTtcbiAgICAgICAgICAgIC8vIE5vIG5lZWQgdG8gcGF0Y2ggcmV0dXJuIHZhbHVlLCB3ZSBkb24ndCB1c2UgdHJhY2luZ1xuICAgICAgICB9XG4gICAgfSk7XG4gICAgKDAsIG5hdGl2ZV8xLmFkZFBvc3RIb29rKSgnZ2V0cHBpZCcsIFtdLCBmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICAoMCwgbG9nXzEubG9nRnVuY3Rpb24pKGRhdGEpO1xuICAgICAgICAvLyBQYXJlbnQgcHJvY2VzcyBpZCBzaG91bGQgYWx3YXlzIGJlIDEgKGxhdW5jaGQpXG4gICAgICAgIGRhdGEucmV0dmFsLnJlcGxhY2UoMSk7XG4gICAgfSk7XG59XG4iLCJcInVzZSBzdHJpY3RcIjtcbmV4cG9ydHMuX19lc01vZHVsZSA9IHRydWU7XG52YXIgZmlsZV8xID0gcmVxdWlyZShcIi4uL2hvb2tzL2ZpbGVcIik7XG52YXIgbmF0aXZlXzEgPSByZXF1aXJlKFwiLi4vaG9va3MvbmF0aXZlXCIpO1xudmFyIGxvZ18xID0gcmVxdWlyZShcIi4uL2luYy9sb2dcIik7XG52YXIgb2JqY18xID0gcmVxdWlyZShcIi4uL2hvb2tzL29iamNcIik7XG4vLyBIaWRlIGJsYWNrbGlzdGVkIGZpbGVzXG5maWxlXzEuRmlsZUhvb2tzLmdldEluc3RhbmNlKCkuYWNjZXNzRmlsZUhvb2soZmlsZV8xLkZpbGVQYXR0ZXJuLmZyb20oZ2xvYmFsLmNvbnRleHQuZW11bGF0aW9uLmZpbGVzKSwgdHJ1ZSk7XG4vLyBXZSBjYW5ub3QgaG9vayBCdWlsZC57ZmllbGR9IGJlY2F1c2UgaXQgaXMgbm90IGEgbWV0aG9kXG4vLyBXZSBjb3VsZCBhcHByb2FjaCB0aGlzIHVzaW5nIHRhaW50IGFuYWx5c2lzIGJ5IHNldHRpbmcgdGhlIEJ1aWxkIGZpZWxkcyB0byBhIHVuaXF1ZSB2YWx1ZVxuLy8gYW5kIGNoZWNrIGlmIHRoZXNlIHZhbHVlcyBhcmUgdXNlZCBpbiBlLmcuIFN0cmluZy5lcXVhbHMoKSwgaG93ZXZlciB0aGlzIGlzIHNsb3dzIGRvd24gdGhlIGFwcCB0b28gbXVjaFxuaWYgKFByb2Nlc3MucGxhdGZvcm0gPT0gJ2RhcndpbicpIHtcbiAgICB2YXIgc2ltdWxhdG9yRW52c18xID0gZ2xvYmFsLmNvbnRleHQuZW11bGF0aW9uLmVudmlyb25tZW50O1xuICAgICgwLCBuYXRpdmVfMS5hZGRQcmVIb29rKSgnZ2V0ZW52JywgWydzdHInXSwgZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAgICAgaWYgKHNpbXVsYXRvckVudnNfMS5pbmRleE9mKGRhdGEuYXJnc1swXSkgPj0gMCkge1xuICAgICAgICAgICAgKDAsIGxvZ18xLmxvZ0Z1bmN0aW9uKShkYXRhKTtcbiAgICAgICAgfVxuICAgIH0sICdsaWJzeXN0ZW1fYy5keWxpYicpO1xuICAgICgwLCBvYmpjXzEuYWRkT2JqQ1ByZUhvb2spKCctW05TUHJvY2Vzc0luZm8gZW52aXJvbm1lbnRdJywgMCwgZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAgICAgLy8gU2luY2UgdGhpcyByZXR1cm5zIGFuIE5TQXJyYXkgb2YgZW52aXJvbm1lbnQgdmFyaWFibGVzLCB3ZSBjYW5ub3QgYmUgc3VyZVxuICAgICAgICAvLyBpZiB0aGVzZSBlbnZpcm9ubWVudCB2YXJpYWJsZXMgYXJlIGNoZWNrZWQgZm9yIHNpbXVsYXRvciBlbnZpcm9ubWVudCB2YXJpYWJsZXNcbiAgICAgICAgKDAsIGxvZ18xLmxvZ09iakNGdW5jdGlvbikoZGF0YSwgZmFsc2UpO1xuICAgIH0pO1xufVxuIiwiXCJ1c2Ugc3RyaWN0XCI7XG52YXIgX19hc3NpZ24gPSAodGhpcyAmJiB0aGlzLl9fYXNzaWduKSB8fCBmdW5jdGlvbiAoKSB7XG4gICAgX19hc3NpZ24gPSBPYmplY3QuYXNzaWduIHx8IGZ1bmN0aW9uKHQpIHtcbiAgICAgICAgZm9yICh2YXIgcywgaSA9IDEsIG4gPSBhcmd1bWVudHMubGVuZ3RoOyBpIDwgbjsgaSsrKSB7XG4gICAgICAgICAgICBzID0gYXJndW1lbnRzW2ldO1xuICAgICAgICAgICAgZm9yICh2YXIgcCBpbiBzKSBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKHMsIHApKVxuICAgICAgICAgICAgICAgIHRbcF0gPSBzW3BdO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiB0O1xuICAgIH07XG4gICAgcmV0dXJuIF9fYXNzaWduLmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7XG59O1xuZXhwb3J0cy5fX2VzTW9kdWxlID0gdHJ1ZTtcbnZhciBhcHBzXzEgPSByZXF1aXJlKFwiLi4vaG9va3MvYXBwc1wiKTtcbnZhciBmaWxlXzEgPSByZXF1aXJlKFwiLi4vaG9va3MvZmlsZVwiKTtcbnZhciBuYXRpdmVfMSA9IHJlcXVpcmUoXCIuLi9ob29rcy9uYXRpdmVcIik7XG52YXIgamF2YV8xID0gcmVxdWlyZShcIi4uL2hvb2tzL2phdmFcIik7XG52YXIgbG9nXzEgPSByZXF1aXJlKFwiLi4vaW5jL2xvZ1wiKTtcbnZhciB1dGlsXzEgPSByZXF1aXJlKFwiLi4vaW5jL3V0aWxcIik7XG52YXIgc29ja2V0XzEgPSByZXF1aXJlKFwiLi4vaG9va3Mvc29ja2V0XCIpO1xudmFyIGZpbGVIb29rcyA9IGZpbGVfMS5GaWxlSG9va3MuZ2V0SW5zdGFuY2UoKTtcbnZhciBhcHBzSG9va3MgPSBhcHBzXzEuQXBwc0hvb2tzLmdldEluc3RhbmNlKCk7XG52YXIgZmlsZXNQYXR0ZXJuID0gZmlsZV8xLkZpbGVQYXR0ZXJuLmZyb20oZ2xvYmFsLmNvbnRleHQuaG9va2luZy5maWxlcyk7XG4vLyBIaWRlIGJsYWNrbGlzdGVkIGZpbGVzXG5maWxlSG9va3MuYWNjZXNzRmlsZUhvb2soZmlsZXNQYXR0ZXJuLCB0cnVlKTtcbmFwcHNIb29rcy5ibGFja2xpc3RBcHBzSG9vayhnbG9iYWwuY29udGV4dC5ob29raW5nLmFwcHMpO1xuLy8gSG9vayBfZHlsZF9nZXRfaW1hZ2VfbmFtZVxuKDAsIG5hdGl2ZV8xLmFkZFBvc3RIb29rKSgnX2R5bGRfZ2V0X2ltYWdlX25hbWUnLCBbJ2ludCddLCBmdW5jdGlvbiAoZGF0YSkge1xuICAgIGlmIChkYXRhLmFyZ3NbMF0gPT0gMCkge1xuICAgICAgICAvLyBNYWluIGFwcCBiaW5hcnksIGFsd2F5cyBxdWVyaWVkIG9uIGFwcCBzdGFydHVwXG4gICAgICAgIHJldHVybjtcbiAgICB9XG4gICAgdmFyIGltYWdlTmFtZSA9IGRhdGEucmV0dmFsLmlzTnVsbCgpID8gbnVsbCA6IGRhdGEucmV0dmFsLnJlYWRVdGY4U3RyaW5nKCk7XG4gICAgdmFyIG1hdGNoZXMgPSBpbWFnZU5hbWUgJiYgZmlsZXNQYXR0ZXJuLnNvbWUoZnVuY3Rpb24gKGl0ZW0pIHsgcmV0dXJuIGl0ZW0ubWF0Y2hlcyhpbWFnZU5hbWUpOyB9KTtcbiAgICBpZiAobWF0Y2hlcykge1xuICAgICAgICBkYXRhLnJldHZhbC5yZXBsYWNlKE1lbW9yeS5hbGxvY1V0ZjhTdHJpbmcoJ25vbmV4aXN0ZW50bGliLmR5bGliJykpO1xuICAgIH1cbiAgICAoMCwgbG9nXzEubG9nRnVuY3Rpb24pKF9fYXNzaWduKF9fYXNzaWduKHt9LCBkYXRhKSwgeyBhcmdzOiBbXG4gICAgICAgICAgICBkYXRhLmFyZ3NbMF0sXG4gICAgICAgICAgICBpbWFnZU5hbWVcbiAgICAgICAgXSB9KSwgZmFsc2UpO1xufSk7XG4oMCwgbmF0aXZlXzEuYWRkUG9zdEhvb2spKCdfZHlsZF9pbWFnZV9jb3VudCcsIFtdLCBmdW5jdGlvbiAoZGF0YSkge1xuICAgICgwLCBsb2dfMS5sb2dGdW5jdGlvbikoZGF0YSwgZmFsc2UpO1xufSk7XG5pZiAoSmF2YS5hdmFpbGFibGUpIHtcbiAgICBKYXZhLnBlcmZvcm0oZnVuY3Rpb24gKCkge1xuICAgICAgICBKYXZhLmVudW1lcmF0ZUNsYXNzTG9hZGVycyh7XG4gICAgICAgICAgICBvbk1hdGNoOiBmdW5jdGlvbiAobG9hZGVyKSB7XG4gICAgICAgICAgICAgICAgW1snc3RyJ10sIFsnc3RyJywgJ2Jvb2wnXV0uZm9yRWFjaChmdW5jdGlvbiAoYXJnVHlwZXMpIHtcbiAgICAgICAgICAgICAgICAgICAgKDAsIGphdmFfMS5hZGRKYXZhUHJlSG9vaykobG9hZGVyLmxvYWRDbGFzcywgYXJnVHlwZXMsIGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBDaGVjayBmb3IgYXR0ZW1wdHMgdG8gbG9hZCBlLmcuIGRlLnJvYnYuYW5kcm9pZC54cG9zZWQuWHBvc2VkQnJpZGdlXG4gICAgICAgICAgICAgICAgICAgICAgICBnbG9iYWwuY29udGV4dC5ob29raW5nLmFwcHMuZm9yRWFjaChmdW5jdGlvbiAoYXBwKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGRhdGEuYXJnc1swXS50b0xvd2VyQ2FzZSgpLmluY2x1ZGVzKGFwcCkpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKDAsIGxvZ18xLmxvZ0phdmFGdW5jdGlvbikoZGF0YSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICAgIH0sIGZhbHNlKTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBvbkNvbXBsZXRlOiBmdW5jdGlvbiAoKSB7IH1cbiAgICAgICAgfSk7XG4gICAgfSk7XG59XG4vLyBBZGQgcG9ydCBob29rIGZvciBkZWZhdWx0IEZyaWRhIHBvcnQgKDI3MDQyKVxuKDAsIHNvY2tldF8xLmFkZE9wZW5Qb3J0SG9vaykoMjcwNDIpO1xuaWYgKEphdmEuYXZhaWxhYmxlKSB7XG4gICAgSmF2YS5wZXJmb3JtKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgLy8gSGlkZSBGcmlkYSBmcm9tIC9wcm9jLzxwaWQ+L21hcHMgc2luY2UgdGVtcEZpbGVOYW1pbmcgcHJlZml4IGNhbiBlbmQgdXAgaW4gbWFwcy5cbiAgICAgICAgLy8gaHR0cHM6Ly9naXRodWIuY29tL3NlbnNlcG9zdC9vYmplY3Rpb24vYmxvYi9mNDc5MjZlOTBjZThiNjY1NWVjYjQzMTczMGI2Njc0ZTQxYmM1NjI1L2FnZW50L3NyYy9hbmRyb2lkL3Bpbm5pbmcudHMjTDQzXG4gICAgICAgIC8vIGh0dHBzOi8vZ2l0aHViLmNvbS9mcmlkYS9mcmlkYS1qYXZhLWJyaWRnZS9ibG9iLzhiMzc5MGY3NDg5ZmY1YmU3YjE5ZGRhY2NmNTE0OWQ0ZTc3Mzg0NjAvbGliL2NsYXNzLWZhY3RvcnkuanMjTDk0XG4gICAgICAgIGlmIChKYXZhLmNsYXNzRmFjdG9yeS50ZW1wRmlsZU5hbWluZy5wcmVmaXggPT0gJ2ZyaWRhJykge1xuICAgICAgICAgICAgSmF2YS5jbGFzc0ZhY3RvcnkudGVtcEZpbGVOYW1pbmcucHJlZml4ID0gJ2hhcmRlbmluZ2FuYWx5emVyJztcbiAgICAgICAgfVxuICAgIH0pO1xufVxuLy8gTW9kaWZ5IC9wcm9jLzxwaWQ+L21hcHMgZmlsZXNcbmZpbGVIb29rcy5yZXBsYWNlRmlsZUhvb2soJy9wcm9jLycsICdtYXBzJywgZnVuY3Rpb24gKGZpbGVuYW1lKSB7XG4gICAgdmFyIG1hcHMgPSAoMCwgdXRpbF8xLnJlYWRGaWxlKShmaWxlbmFtZSk7XG4gICAgaWYgKG1hcHMgPT0gbnVsbCkge1xuICAgICAgICAoMCwgbG9nXzEud2FybikoXCJGYWlsZWQgdG8gcmVhZCBcIiArIGZpbGVuYW1lKTtcbiAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgfVxuICAgIHZhciBtb2RpZmllZE1hcHMgPSAnJztcbiAgICBmb3IgKHZhciBfaSA9IDAsIF9hID0gbWFwcy5zcGxpdCgnXFxuJyk7IF9pIDwgX2EubGVuZ3RoOyBfaSsrKSB7XG4gICAgICAgIHZhciBsaW5lID0gX2FbX2ldO1xuICAgICAgICAvLyBSZW1vdmUgdHJhY2VzIG9mIGZyaWRhIGZyb20gbWFwc1xuICAgICAgICBpZiAobGluZS5pbmNsdWRlcygnZnJpZGEnKSlcbiAgICAgICAgICAgIGNvbnRpbnVlO1xuICAgICAgICBsaW5lID0gbGluZS5yZXBsYWNlKCdyd3hwJywgJ3IteHAnKTtcbiAgICAgICAgbW9kaWZpZWRNYXBzICs9IGxpbmUgKyAnXFxuJztcbiAgICB9XG4gICAgcmV0dXJuIG1vZGlmaWVkTWFwcztcbn0sIGZhbHNlKTtcbi8vIE1vZGlmeSAvcHJvYy88cGlkPi90YXNrLzx0aWQ+L3N0YXR1cyBmaWxlc1xuZmlsZUhvb2tzLnJlcGxhY2VGaWxlSG9vaygnL3Byb2MvJywgJ3N0YXR1cycsIGZ1bmN0aW9uIChmaWxlbmFtZSkge1xuICAgIHZhciBtYXBzID0gKDAsIHV0aWxfMS5yZWFkRmlsZSkoZmlsZW5hbWUpO1xuICAgIGlmIChtYXBzID09IG51bGwpIHtcbiAgICAgICAgKDAsIGxvZ18xLndhcm4pKFwiRmFpbGVkIHRvIHJlYWQgXCIgKyBmaWxlbmFtZSk7XG4gICAgICAgIHJldHVybiBudWxsO1xuICAgIH1cbiAgICB2YXIgbW9kaWZpZWRNYXBzID0gJyc7XG4gICAgZm9yICh2YXIgX2kgPSAwLCBfYSA9IG1hcHMuc3BsaXQoJ1xcbicpOyBfaSA8IF9hLmxlbmd0aDsgX2krKykge1xuICAgICAgICB2YXIgbGluZSA9IF9hW19pXTtcbiAgICAgICAgLy8gUmVtb3ZlIHRyYWNlcyBvZiBmcmlkYSBmcm9tIHRocmVhZCBuYW1lc1xuICAgICAgICBsaW5lID0gbGluZS5yZXBsYWNlKCdnbWFpbicsICdUaHJlYWQtMScpO1xuICAgICAgICBsaW5lID0gbGluZS5yZXBsYWNlKCdndW0tanMtbG9vcCcsICdUaHJlYWQtMScpO1xuICAgICAgICBsaW5lID0gbGluZS5yZXBsYWNlKCdnZGJ1cycsICdUaHJlYWQtMScpO1xuICAgICAgICBsaW5lID0gbGluZS5yZXBsYWNlKCdsaW5qZWN0b3InLCAnVGhyZWFkLTEnKTtcbiAgICAgICAgbGluZSA9IGxpbmUucmVwbGFjZSgncG9vbC1zcGF3bmVyJywgJ1RocmVhZC0xJyk7XG4gICAgICAgIGxpbmUgPSBsaW5lLnJlcGxhY2UoJ3Bvb2wtZnJpZGEnLCAnVGhyZWFkLTEnKTtcbiAgICAgICAgbGluZSA9IGxpbmUucmVwbGFjZSgnZnJpZGEtc2VydmVyJywgJ1RocmVhZC0xJyk7XG4gICAgICAgIGxpbmUgPSBsaW5lLnJlcGxhY2UoJ2ZyaWRhX2FnZW50X21haW4nLCAnVGhyZWFkLTEnKTtcbiAgICAgICAgbGluZSA9IGxpbmUucmVwbGFjZSgnZnJpZGEnLCAnVGhyZWFkLTEnKTtcbiAgICAgICAgbW9kaWZpZWRNYXBzICs9IGxpbmUgKyAnXFxuJztcbiAgICB9XG4gICAgcmV0dXJuIG1vZGlmaWVkTWFwcztcbn0sIGZhbHNlKTtcbiIsIlwidXNlIHN0cmljdFwiO1xudmFyIF9hLCBfYiwgX2MsIF9kLCBfZSwgX2YsIF9nLCBfaDtcbmV4cG9ydHMuX19lc01vZHVsZSA9IHRydWU7XG52YXIgamF2YV8xID0gcmVxdWlyZShcIi4uL2hvb2tzL2phdmFcIik7XG4oMCwgamF2YV8xLmFkZEphdmFQcmVIb29rKSgnYW5kcm9pZC5hcHAuQWN0aXZpdHk6Om9uQ3JlYXRlJywgWydhbmRyb2lkLm9zLkJ1bmRsZSddLCBmdW5jdGlvbiAoZGF0YSkge1xuICAgIGlmIChnbG9iYWwuc2FmZU1vZGUgPT0gJ3llcycpXG4gICAgICAgIHJldHVybjtcbiAgICB2YXIgcGFja2FnZU5hbWUgPSBkYXRhW1widGhpc1wiXS5nZXRQYWNrYWdlTmFtZSgpO1xuICAgIHZhciBwbSA9IGRhdGFbXCJ0aGlzXCJdLmdldFBhY2thZ2VNYW5hZ2VyKCk7XG4gICAgdmFyIHBhY2thZ2VJbmZvID0gcG0uZ2V0UGFja2FnZUluZm8ocGFja2FnZU5hbWUsIDApO1xuICAgIHZhciBhcHBJbmZvID0gZGF0YVtcInRoaXNcIl0uZ2V0QXBwbGljYXRpb25JbmZvKCk7XG4gICAgdmFyIGxhYmVsUmVzID0gYXBwSW5mby5sYWJlbFJlcy52YWx1ZTtcbiAgICB2YXIgbGF1bmNoSW50ZW50ID0gcG0uZ2V0TGF1bmNoSW50ZW50Rm9yUGFja2FnZShwYWNrYWdlTmFtZSk7XG4gICAgdmFyIGluZm8gPSB7XG4gICAgICAgIHR5cGU6ICdpbmZvJyxcbiAgICAgICAgZGV0ZWN0b3I6ICdpbmZvJyxcbiAgICAgICAgaW5mbzoge1xuICAgICAgICAgICAgbmFtZTogbGFiZWxSZXMgPyBkYXRhW1widGhpc1wiXS5nZXRTdHJpbmcobGFiZWxSZXMpIDogYXBwSW5mby5ub25Mb2NhbGl6ZWRMYWJlbC52YWx1ZSxcbiAgICAgICAgICAgIHBhY2thZ2U6IHBhY2thZ2VOYW1lLFxuICAgICAgICAgICAgdmVyc2lvbl9jb2RlOiBwYWNrYWdlSW5mby52ZXJzaW9uQ29kZS52YWx1ZSxcbiAgICAgICAgICAgIHZlcnNpb25fbmFtZTogcGFja2FnZUluZm8udmVyc2lvbk5hbWUudmFsdWUsXG4gICAgICAgICAgICBtaW5fc2RrOiBhcHBJbmZvLm1pblNka1ZlcnNpb24udmFsdWUsXG4gICAgICAgICAgICBtYWluX2FjdGl2aXR5OiBsYXVuY2hJbnRlbnQgPyBsYXVuY2hJbnRlbnQuZ2V0Q29tcG9uZW50KCkuZ2V0Q2xhc3NOYW1lKCkgOiBudWxsLFxuICAgICAgICAgICAgcGVybWlzc2lvbnM6IHBtLmdldFBhY2thZ2VJbmZvKHBhY2thZ2VOYW1lLCA0MDk2KS5yZXF1ZXN0ZWRQZXJtaXNzaW9ucy52YWx1ZVxuICAgICAgICB9XG4gICAgfTtcbiAgICBzZW5kKGluZm8pO1xufSk7XG5pZiAoT2JqQy5hdmFpbGFibGUpIHtcbiAgICB2YXIgaW5mb0RpY3QgPSBPYmpDLmNsYXNzZXMuTlNCdW5kbGUubWFpbkJ1bmRsZSgpLmluZm9EaWN0aW9uYXJ5KCk7XG4gICAgdmFyIGluZm8gPSB7XG4gICAgICAgIHR5cGU6ICdpbmZvJyxcbiAgICAgICAgZGV0ZWN0b3I6ICdpbmZvJyxcbiAgICAgICAgaW5mbzoge1xuICAgICAgICAgICAgbmFtZTogKChfYSA9IGluZm9EaWN0Lm9iamVjdEZvcktleV8oXCJDRkJ1bmRsZURpc3BsYXlOYW1lXCIpKSA9PT0gbnVsbCB8fCBfYSA9PT0gdm9pZCAwID8gdm9pZCAwIDogX2EudG9TdHJpbmcoKSkgfHwgKChfYiA9IGluZm9EaWN0Lm9iamVjdEZvcktleV8oXCJDRkJ1bmRsZU5hbWVcIikpID09PSBudWxsIHx8IF9iID09PSB2b2lkIDAgPyB2b2lkIDAgOiBfYi50b1N0cmluZygpKSxcbiAgICAgICAgICAgIHBhY2thZ2U6IChfYyA9IGluZm9EaWN0Lm9iamVjdEZvcktleV8oXCJDRkJ1bmRsZUlkZW50aWZpZXJcIikpID09PSBudWxsIHx8IF9jID09PSB2b2lkIDAgPyB2b2lkIDAgOiBfYy50b1N0cmluZygpLFxuICAgICAgICAgICAgZXhlY3V0YWJsZTogKF9kID0gaW5mb0RpY3Qub2JqZWN0Rm9yS2V5XyhcIkNGQnVuZGxlRXhlY3V0YWJsZVwiKSkgPT09IG51bGwgfHwgX2QgPT09IHZvaWQgMCA/IHZvaWQgMCA6IF9kLnRvU3RyaW5nKCksXG4gICAgICAgICAgICB2ZXJzaW9uX2NvZGU6IChfZSA9IGluZm9EaWN0Lm9iamVjdEZvcktleV8oXCJDRkJ1bmRsZVZlcnNpb25cIikpID09PSBudWxsIHx8IF9lID09PSB2b2lkIDAgPyB2b2lkIDAgOiBfZS50b1N0cmluZygpLFxuICAgICAgICAgICAgdmVyc2lvbl9uYW1lOiAoX2YgPSBpbmZvRGljdC5vYmplY3RGb3JLZXlfKFwiQ0ZCdW5kbGVTaG9ydFZlcnNpb25TdHJpbmdcIikpID09PSBudWxsIHx8IF9mID09PSB2b2lkIDAgPyB2b2lkIDAgOiBfZi50b1N0cmluZygpLFxuICAgICAgICAgICAgbWluX3NkazogKF9nID0gaW5mb0RpY3Qub2JqZWN0Rm9yS2V5XyhcIk1pbmltdW1PU1ZlcnNpb25cIikpID09PSBudWxsIHx8IF9nID09PSB2b2lkIDAgPyB2b2lkIDAgOiBfZy50b1N0cmluZygpLFxuICAgICAgICAgICAgbWFpbl9hY3Rpdml0eTogKF9oID0gaW5mb0RpY3Qub2JqZWN0Rm9yS2V5XyhcIlVJTGF1bmNoU3Rvcnlib2FyZE5hbWVcIikpID09PSBudWxsIHx8IF9oID09PSB2b2lkIDAgPyB2b2lkIDAgOiBfaC50b1N0cmluZygpXG4gICAgICAgIH1cbiAgICB9O1xuICAgIHNlbmQoaW5mbyk7XG59XG4iLCJcInVzZSBzdHJpY3RcIjtcbmV4cG9ydHMuX19lc01vZHVsZSA9IHRydWU7XG52YXIgamF2YV8xID0gcmVxdWlyZShcIi4uL2hvb2tzL2phdmFcIik7XG52YXIgb2JqY18xID0gcmVxdWlyZShcIi4uL2hvb2tzL29iamNcIik7XG52YXIgbG9nXzEgPSByZXF1aXJlKFwiLi4vaW5jL2xvZ1wiKTtcbigwLCBqYXZhXzEuYWRkSmF2YVByZUhvb2spKFtcbiAgICAnYW5kcm9pZC52aWV3LmlucHV0bWV0aG9kLklucHV0TWV0aG9kTWFuYWdlcjo6Z2V0SW5wdXRNZXRob2RMaXN0JyxcbiAgICAnYW5kcm9pZC52aWV3LmlucHV0bWV0aG9kLklucHV0TWV0aG9kTWFuYWdlcjo6Z2V0RW5hYmxlZElucHV0TWV0aG9kTGlzdCdcbl0sIFtdLCBmdW5jdGlvbiAoZGF0YSkge1xuICAgICgwLCBsb2dfMS5sb2dKYXZhRnVuY3Rpb24pKGRhdGEpO1xufSk7XG4oMCwgamF2YV8xLmFkZEphdmFQcmVIb29rKSgnYW5kcm9pZC5wcm92aWRlci5TZXR0aW5ncyRTZWN1cmU6OmdldFN0cmluZycsIFsnYW5kcm9pZC5jb250ZW50LkNvbnRlbnRSZXNvbHZlcicsICdzdHInXSwgZnVuY3Rpb24gKGRhdGEpIHtcbiAgICBpZiAoZGF0YS5hcmdzWzFdID09ICdlbmFibGVkX2lucHV0X21ldGhvZHMnIHx8IGRhdGEuYXJnc1sxXSA9PSAnZGVmYXVsdF9pbnB1dF9tZXRob2QnKSB7XG4gICAgICAgICgwLCBsb2dfMS5sb2dKYXZhRnVuY3Rpb24pKGRhdGEpO1xuICAgIH1cbn0pO1xuKDAsIGphdmFfMS5hZGRKYXZhUHJlSG9vaykoJ2FuZHJvaWQud2lkZ2V0LkVkaXRUZXh0OjpzZXRTaG93U29mdElucHV0T25Gb2N1cycsIFsnYm9vbGVhbiddLCBmdW5jdGlvbiAoZGF0YSkge1xuICAgIGlmIChkYXRhLmFyZ3NbMF0gPT0gZmFsc2UpIHtcbiAgICAgICAgKDAsIGxvZ18xLmxvZ0phdmFGdW5jdGlvbikoZGF0YSk7XG4gICAgfVxufSk7XG4oMCwgb2JqY18xLmFkZE9iakNQcmVIb29rKSgnLVtVSVJlc3BvbmRlciB0ZXh0SW5wdXRNb2RlXScsIDAsIGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgKDAsIGxvZ18xLmxvZ09iakNGdW5jdGlvbikoZGF0YSk7XG59KTtcbigwLCBvYmpjXzEuYWRkT2JqQ1ByZUhvb2spKCcrW1VJVGV4dElucHV0TW9kZSBhY3RpdmVJbnB1dE1vZGVzXScsIDAsIGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgKDAsIGxvZ18xLmxvZ09iakNGdW5jdGlvbikoZGF0YSk7XG59KTtcbigwLCBvYmpjXzEuYWRkT2JqQ1ByZUhvb2spKCctW1VJVmlldyBpbnB1dFZpZXddJywgMCwgZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAoMCwgbG9nXzEubG9nT2JqQ0Z1bmN0aW9uKShkYXRhKTtcbn0pO1xuIiwiXCJ1c2Ugc3RyaWN0XCI7XG5leHBvcnRzLl9fZXNNb2R1bGUgPSB0cnVlO1xudmFyIGphdmFfMSA9IHJlcXVpcmUoXCIuLi9ob29rcy9qYXZhXCIpO1xudmFyIG9iamNfMSA9IHJlcXVpcmUoXCIuLi9ob29rcy9vYmpjXCIpO1xuLy8gUHJldGVuZCBsb2Nrc2NyZWVuIGlzIGVuYWJsZWRcbigwLCBqYXZhXzEuYWRkSmF2YVBvc3RIb29rKSgnYW5kcm9pZC5hcHAuS2V5Z3VhcmRNYW5hZ2VyOjppc0RldmljZVNlY3VyZScsIFsnaW50J10sIGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgZGF0YS5yZXR2YWwgPSB0cnVlO1xufSk7XG52YXIgY2hlY2tGdW5jdGlvbnMgPSBbXG4gICAgJ2FuZHJvaWQuYXBwLktleWd1YXJkTWFuYWdlcjo6aXNLZXlndWFyZFNlY3VyZScsXG4gICAgJ2FuZHJvaWQuYXBwLmFkbWluLkRldmljZVBvbGljeU1hbmFnZXI6OmlzQWN0aXZlUGFzc3dvcmRTdWZmaWNpZW50JyxcbiAgICAnYW5kcm9pZC5hcHAuYWRtaW4uRGV2aWNlUG9saWN5TWFuYWdlcjo6aXNBY3RpdmVQYXNzd29yZFN1ZmZpY2llbnRGb3JEZXZpY2VSZXF1aXJlbWVudCcsXG5dO1xuY2hlY2tGdW5jdGlvbnMuZm9yRWFjaChmdW5jdGlvbiAoZnVuKSB7XG4gICAgKDAsIGphdmFfMS5hZGRKYXZhUG9zdEhvb2spKGZ1biwgW10sIGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgICAgIGRhdGEucmV0dmFsID0gdHJ1ZTtcbiAgICB9KTtcbn0pO1xuLy8gU2V0dGluZ3MuU2VjdXJlLmdldFN0cmluZyhjb250ZW50UmVzb2x2ZXIsIFNldHRpbmdzLlNlY3VyZS5MT0NLX1BBVFRFUk5fRU5BQkxFRClcbigwLCBqYXZhXzEuYWRkSmF2YVBvc3RIb29rKSgnYW5kcm9pZC5wcm92aWRlci5TZXR0aW5ncyRTZWN1cmU6OmdldFN0cmluZycsIFsnYW5kcm9pZC5jb250ZW50LkNvbnRlbnRSZXNvbHZlcicsICdqYXZhLmxhbmcuU3RyaW5nJ10sIGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgaWYgKGRhdGEuYXJnc1sxXSA9PSAnbG9ja19wYXR0ZXJuX2F1dG9sb2NrJykge1xuICAgICAgICBpZiAoZGF0YS5mdW5OYW1lLmluY2x1ZGVzKCdTdHJpbmcnKSkge1xuICAgICAgICAgICAgZGF0YS5yZXR2YWwgPSAnMSc7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICBkYXRhLnJldHZhbCA9IDE7XG4gICAgICAgIH1cbiAgICB9XG59KTtcbigwLCBvYmpjXzEuYWRkT2JqQ1Bvc3RIb29rKSgnLVtMQUNvbnRleHQgY2FuRXZhbHVhdGVQb2xpY3k6ZXJyb3I6JywgMiwgZnVuY3Rpb24gKGRhdGEpIHtcbiAgICBkYXRhLnJldHZhbC5yZXBsYWNlKE1lbW9yeS5hbGxvYyg0KS53cml0ZVVJbnQoMSkpO1xuICAgIGRhdGEuYXJnc1sxXSA9IHB0cigwKTtcbn0pO1xuIiwiXCJ1c2Ugc3RyaWN0XCI7XG5leHBvcnRzLl9fZXNNb2R1bGUgPSB0cnVlO1xudmFyIGphdmFfMSA9IHJlcXVpcmUoXCIuLi9ob29rcy9qYXZhXCIpO1xudmFyIG5hdGl2ZV8xID0gcmVxdWlyZShcIi4uL2hvb2tzL25hdGl2ZVwiKTtcbnZhciBvYmpjXzEgPSByZXF1aXJlKFwiLi4vaG9va3Mvb2JqY1wiKTtcbnZhciBsb2dfMSA9IHJlcXVpcmUoXCIuLi9pbmMvbG9nXCIpO1xuLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1xuLy8gQW5kcm9pZCBQaW5uaW5nIGJ5cGFzcyAvL1xuLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1xuLy8gaHR0cHM6Ly9naXRodWIuY29tL05FVS1TTlMvYXBwLXRscy1waW5uaW5nL2Jsb2IvYjA0Njk5OTBhZDM3YzMwNjhjMjI3YTQ0YWE1ZjViZmI4MjRlYzNmNy9jb2RlL2NlcnRpZmljYXRlLXBpbm5pbmcvRHluYW1pY0FuYWx5c2lzL2ZyaWRhL2J5cGFzc19hbGxfcGlubmluZy5qc1xuLy8gVHJ1c3RNYW5hZ2VyIChBbmRyb2lkIDwgNylcbmlmIChKYXZhLmF2YWlsYWJsZSkge1xuICAgIEphdmEucGVyZm9ybShmdW5jdGlvbiAoKSB7XG4gICAgICAgIHZhciBYNTA5VHJ1c3RNYW5hZ2VyID0gSmF2YS51c2UoJ2phdmF4Lm5ldC5zc2wuWDUwOVRydXN0TWFuYWdlcicpO1xuICAgICAgICB2YXIgVHJ1c3RNYW5hZ2VyID0gSmF2YS5yZWdpc3RlckNsYXNzKHtcbiAgICAgICAgICAgIC8vIEltcGxlbWVudCBhIGN1c3RvbSBUcnVzdE1hbmFnZXJcbiAgICAgICAgICAgIG5hbWU6ICdubC53aWxjb3ZhbmJlaWpudW0uVHJ1c3RNYW5hZ2VyJyxcbiAgICAgICAgICAgIGltcGxlbWVudHM6IFtYNTA5VHJ1c3RNYW5hZ2VyXSxcbiAgICAgICAgICAgIG1ldGhvZHM6IHtcbiAgICAgICAgICAgICAgICBjaGVja0NsaWVudFRydXN0ZWQ6IGZ1bmN0aW9uIChjaGFpbiwgYXV0aFR5cGUpIHsgfSxcbiAgICAgICAgICAgICAgICBjaGVja1NlcnZlclRydXN0ZWQ6IGZ1bmN0aW9uIChjaGFpbiwgYXV0aFR5cGUpIHsgfSxcbiAgICAgICAgICAgICAgICBnZXRBY2NlcHRlZElzc3VlcnM6IGZ1bmN0aW9uICgpIHsgcmV0dXJuIFtdOyB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgICB2YXIgdHJ1c3RNYW5hZ2VycyA9IFtUcnVzdE1hbmFnZXIuJG5ldygpXTtcbiAgICAgICAgKDAsIGphdmFfMS5hZGRKYXZhUHJlSG9vaykoJ2phdmF4Lm5ldC5zc2wuU1NMQ29udGV4dDo6aW5pdCcsIFsnW0xqYXZheC5uZXQuc3NsLktleU1hbmFnZXI7JywgJ1tMamF2YXgubmV0LnNzbC5UcnVzdE1hbmFnZXI7JywgJ2phdmEuc2VjdXJpdHkuU2VjdXJlUmFuZG9tJ10sIGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgICAgICAgICAvLyBPdmVycmlkZSB0aGUgaW5pdCBtZXRob2QsIHNwZWNpZnlpbmcgdGhlIGN1c3RvbSBUcnVzdE1hbmFnZXJcbiAgICAgICAgICAgIGRhdGEuYXJnc1sxXSA9IHRydXN0TWFuYWdlcnM7XG4gICAgICAgICAgICAoMCwgbG9nXzEubG9nSmF2YUZ1bmN0aW9uKShkYXRhLCBmYWxzZSk7XG4gICAgICAgIH0sIGZhbHNlKTtcbiAgICB9KTtcbn1cbnZhciByZXR1cm5Wb2lkSG9vayA9IGZ1bmN0aW9uIChkYXRhLCBjb25maWRlbnQpIHtcbiAgICBpZiAoY29uZmlkZW50ID09PSB2b2lkIDApIHsgY29uZmlkZW50ID0gdHJ1ZTsgfVxuICAgICgwLCBsb2dfMS5sb2dKYXZhRnVuY3Rpb24pKGRhdGEsIGNvbmZpZGVudCk7XG59O1xudmFyIHJldHVyblRydWVIb29rID0gZnVuY3Rpb24gKGRhdGEsIGNvbmZpZGVudCkge1xuICAgIGlmIChjb25maWRlbnQgPT09IHZvaWQgMCkgeyBjb25maWRlbnQgPSB0cnVlOyB9XG4gICAgKDAsIGxvZ18xLmxvZ0phdmFGdW5jdGlvbikoZGF0YSwgY29uZmlkZW50KTtcbiAgICByZXR1cm4gdHJ1ZTtcbn07XG52YXIgb2todHRwM1BpbnMgPSBmdW5jdGlvbiAoZGF0YSkge1xuICAgIGlmIChkYXRhW1widGhpc1wiXS5maW5kTWF0Y2hpbmdQaW5zKSB7XG4gICAgICAgIHJldHVybiBkYXRhW1widGhpc1wiXS5maW5kTWF0Y2hpbmdQaW5zKGRhdGEuYXJnc1swXSkuc2l6ZSgpID4gMDtcbiAgICB9XG4gICAgZWxzZSBpZiAoZGF0YVtcInRoaXNcIl0uZ2V0UGlucykge1xuICAgICAgICByZXR1cm4gZGF0YVtcInRoaXNcIl0uZ2V0UGlucygpLnNpemUoKSA+IDA7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxufTtcbi8vIE9rSFRUUHYzXG4oMCwgamF2YV8xLmFkZEphdmFSZXBsYWNlSG9vaykoJ29raHR0cDMuQ2VydGlmaWNhdGVQaW5uZXI6OmNoZWNrJywgWydzdHInLCAnamF2YS51dGlsLkxpc3QnXSwgZnVuY3Rpb24gKGRhdGEpIHsgcmV0dXJuIHJldHVyblZvaWRIb29rKGRhdGEsIG9raHR0cDNQaW5zKGRhdGEpKTsgfSk7XG4oMCwgamF2YV8xLmFkZEphdmFSZXBsYWNlSG9vaykoJ29raHR0cDMuQ2VydGlmaWNhdGVQaW5uZXI6OmNoZWNrJywgWydzdHInLCAnamF2YS5zZWN1cml0eS5jZXJ0LkNlcnRpZmljYXRlJ10sIGZ1bmN0aW9uIChkYXRhKSB7IHJldHVybiByZXR1cm5Wb2lkSG9vayhkYXRhLCBva2h0dHAzUGlucyhkYXRhKSk7IH0pO1xuKDAsIGphdmFfMS5hZGRKYXZhUmVwbGFjZUhvb2spKCdva2h0dHAzLkNlcnRpZmljYXRlUGlubmVyOjpjaGVjaycsIFsnc3RyJywgJ3N0ciddLCBmdW5jdGlvbiAoZGF0YSkge1xuICAgICgwLCBsb2dfMS5sb2dKYXZhRnVuY3Rpb24pKGRhdGEsIG9raHR0cDNQaW5zKGRhdGEpKTtcbiAgICByZXR1cm4gZGF0YS5hcmdzWzFdO1xufSk7XG4oMCwgamF2YV8xLmFkZEphdmFSZXBsYWNlSG9vaykoJ29raHR0cDMuQ2VydGlmaWNhdGVQaW5uZXI6OmNoZWNrJywgWydzdHInLCAna290bGluLmp2bS5mdW5jdGlvbnMuRnVuY3Rpb24wJ10sIGZ1bmN0aW9uIChkYXRhKSB7IHJldHVybiByZXR1cm5Wb2lkSG9vayhkYXRhLCBkYXRhW1widGhpc1wiXS5nZXRQaW5zKCkuc2l6ZSgpID4gMCk7IH0pO1xuLy8gVHJ1c3RraXRcbigwLCBqYXZhXzEuYWRkSmF2YVJlcGxhY2VIb29rKSgnY29tLmRhdGF0aGVvcmVtLmFuZHJvaWQudHJ1c3RraXQucGlubmluZy5Pa0hvc3RuYW1lVmVyaWZpZXI6OnZlcmlmeScsIFsnc3RyJywgJ2phdmF4Lm5ldC5zc2wuU1NMU2Vzc2lvbiddLCBmdW5jdGlvbiAoZGF0YSkgeyByZXR1cm4gcmV0dXJuVHJ1ZUhvb2soZGF0YSwgZmFsc2UpOyB9KTtcbigwLCBqYXZhXzEuYWRkSmF2YVJlcGxhY2VIb29rKSgnY29tLmRhdGF0aGVvcmVtLmFuZHJvaWQudHJ1c3RraXQucGlubmluZy5Pa0hvc3RuYW1lVmVyaWZpZXI6OnZlcmlmeScsIFsnc3RyJywgJ2phdmEuc2VjdXJpdHkuY2VydC5YNTA5Q2VydGlmaWNhdGUnXSwgZnVuY3Rpb24gKGRhdGEpIHsgcmV0dXJuIHJldHVyblRydWVIb29rKGRhdGEsIGZhbHNlKTsgfSk7XG4oMCwgamF2YV8xLmFkZEphdmFSZXBsYWNlSG9vaykoJ2NvbS5kYXRhdGhlb3JlbS5hbmRyb2lkLnRydXN0a2l0LnBpbm5pbmcuUGlubmluZ1RydXN0TWFuYWdlcjo6Y2hlY2tTZXJ2ZXJUcnVzdGVkJywgWydbTGphdmEuc2VjdXJpdHkuY2VydC5YNTA5Q2VydGlmaWNhdGU7JywgJ3N0ciddLCBmdW5jdGlvbiAoZGF0YSkgeyByZXR1cm4gcmV0dXJuVm9pZEhvb2soZGF0YSwgZGF0YVtcInRoaXNcIl0uc2VydmVyQ29uZmlnLnNob3VsZEVuZm9yY2VQaW5uaW5nKCkpOyB9KTtcbi8vIFRydXN0TWFuYWdlckltcGwgKEFuZHJvaWQgPiA3KVxuKDAsIGphdmFfMS5hZGRKYXZhUmVwbGFjZUhvb2spKCdjb20uYW5kcm9pZC5vcmcuY29uc2NyeXB0LlRydXN0TWFuYWdlckltcGw6OnZlcmlmeUNoYWluJywgWydbTGphdmEuc2VjdXJpdHkuY2VydC5YNTA5Q2VydGlmaWNhdGU7JywgJ1tMamF2YS5zZWN1cml0eS5jZXJ0LlRydXN0QW5jaG9yOycsICdzdHInLCAnYm9vbGVhbicsICdbQicsICdbQiddLCBmdW5jdGlvbiAoZGF0YSkge1xuICAgICgwLCBsb2dfMS5sb2dKYXZhRnVuY3Rpb24pKGRhdGEsIGRhdGEuYXJnc1sxXS5sZW5ndGggPiAwKTtcbiAgICByZXR1cm4gZGF0YS5hcmdzWzBdO1xufSk7XG4vLyBBcHBjZWxlcmF0b3IgVGl0YW5pdW0gUGlubmluZ1RydXN0TWFuYWdlclxuKDAsIGphdmFfMS5hZGRKYXZhUmVwbGFjZUhvb2spKCdhcHBjZWxlcmF0b3IuaHR0cHMuUGlubmluZ1RydXN0TWFuYWdlcjo6Y2hlY2tTZXJ2ZXJUcnVzdGVkJywgWydbTGphdmEuc2VjdXJpdHkuY2VydC5YNTA5Q2VydGlmaWNhdGU7JywgJ3N0ciddLCBmdW5jdGlvbiAoZGF0YSkgeyByZXR1cm4gcmV0dXJuVm9pZEhvb2soZGF0YSwgZmFsc2UpOyB9KTtcbi8vIEZhYnJpYyBQaW5uaW5nVHJ1c3RNYW5hZ2VyXG4oMCwgamF2YV8xLmFkZEphdmFSZXBsYWNlSG9vaykoJ2lvLmZhYnJpYy5zZGsuYW5kcm9pZC5zZXJ2aWNlcy5uZXR3b3JrLlBpbm5pbmdUcnVzdE1hbmFnZXI6OmNoZWNrU2VydmVyVHJ1c3RlZCcsIFsnW0xqYXZhLnNlY3VyaXR5LmNlcnQuWDUwOUNlcnRpZmljYXRlOycsICdzdHInXSwgZnVuY3Rpb24gKGRhdGEpIHsgcmV0dXJuIHJldHVyblZvaWRIb29rKGRhdGEsIGRhdGFbXCJ0aGlzXCJdLnBpbnMuc2l6ZSgpID4gMCk7IH0pO1xuLy8gQ29uc2NyeXB0IE9wZW5TU0xTb2NrZXRJbXBsXG4oMCwgamF2YV8xLmFkZEphdmFSZXBsYWNlSG9vaykoJ2NvbS5hbmRyb2lkLm9yZy5jb25zY3J5cHQuT3BlblNTTFNvY2tldEltcGw6OnZlcmlmeUNlcnRpZmljYXRlQ2hhaW4nLCBbJ1tKJywgJ3N0ciddLCBmdW5jdGlvbiAoZGF0YSkgeyByZXR1cm4gcmV0dXJuVm9pZEhvb2soZGF0YSwgZmFsc2UpOyB9KTtcbi8vIENvbnNjcnlwdCBPcGVuU1NMRW5naW5lU29ja2V0SW1wbFxuKDAsIGphdmFfMS5hZGRKYXZhUmVwbGFjZUhvb2spKCdjb20uYW5kcm9pZC5vcmcuY29uc2NyeXB0Lk9wZW5TU0xFbmdpbmVTb2NrZXRJbXBsOjp2ZXJpZnlDZXJ0aWZpY2F0ZUNoYWluJywgWydbSicsICdzdHInXSwgZnVuY3Rpb24gKGRhdGEpIHsgcmV0dXJuIHJldHVyblZvaWRIb29rKGRhdGEsIGZhbHNlKTsgfSk7XG4vLyBBcGFjaGUgSGFybW9ueSBPcGVuU1NMU29ja2V0SW1wbFxuKDAsIGphdmFfMS5hZGRKYXZhUmVwbGFjZUhvb2spKCdvcmcuYXBhY2hlLmhhcm1vbnkueG5ldC5wcm92aWRlci5qc3NlLk9wZW5TU0xTb2NrZXRJbXBsOjp2ZXJpZnlDZXJ0aWZpY2F0ZUNoYWluJywgWydbW0InLCAnc3RyJ10sIGZ1bmN0aW9uIChkYXRhKSB7IHJldHVybiByZXR1cm5Wb2lkSG9vayhkYXRhLCBmYWxzZSk7IH0pO1xuLy8gUGhvbmVHYXAgc3NsQ2VydGlmaWNhdGVDaGVja2VyXG4oMCwgamF2YV8xLmFkZEphdmFSZXBsYWNlSG9vaykoJ25sLnhzZXJ2aWNlcy5wbHVnaW5zLnNzbENlcnRpZmljYXRlQ2hlY2tlcjo6ZXhlY3V0ZScsIFsnc3RyJywgJ29yZy5qc29uLkpTT05BcnJheScsICdvcmcuYXBhY2hlLmNvcmRvdmEuQ2FsbGJhY2tDb250ZXh0J10sIGZ1bmN0aW9uIChkYXRhKSB7IHJldHVybiByZXR1cm5UcnVlSG9vayhkYXRhLCBkYXRhLmFyZ3NbMV0uZ2V0SlNPTkFycmF5KDIpLmxlbmd0aCgpID4gMCk7IH0pO1xuLy8gSUJNIE1vYmlsZUZpcnN0IFdMQ2xpZW50XG4oMCwgamF2YV8xLmFkZEphdmFSZXBsYWNlSG9vaykoJ2NvbS53b3JrbGlnaHQud2xjbGllbnQuYXBpLldMQ2xpZW50OjpwaW5UcnVzdGVkQ2VydGlmaWNhdGVQdWJsaWNLZXknLCBbJ3N0ciddLCByZXR1cm5Wb2lkSG9vayk7XG4oMCwgamF2YV8xLmFkZEphdmFSZXBsYWNlSG9vaykoJ2NvbS53b3JrbGlnaHQud2xjbGllbnQuYXBpLldMQ2xpZW50OjpwaW5UcnVzdGVkQ2VydGlmaWNhdGVQdWJsaWNLZXknLCBbJ3N0cltdJ10sIHJldHVyblZvaWRIb29rKTtcbi8vIElCTSBXb3JrTGlnaHQgSG9zdE5hbWVWZXJpZmllcldpdGhDZXJ0aWZpY2F0ZVBpbm5pbmdcbigwLCBqYXZhXzEuYWRkSmF2YVJlcGxhY2VIb29rKSgnY29tLndvcmtsaWdodC53bGNsaWVudC5jZXJ0aWZpY2F0ZXBpbm5pbmcuSG9zdE5hbWVWZXJpZmllcldpdGhDZXJ0aWZpY2F0ZVBpbm5pbmc6OnZlcmlmeScsIFsnc3RyJywgJ2phdmF4Lm5ldC5zc2wuU1NMU29ja2V0J10sIGZ1bmN0aW9uIChkYXRhKSB7IHJldHVybiByZXR1cm5Wb2lkSG9vayhkYXRhLCBmYWxzZSk7IH0pO1xuKDAsIGphdmFfMS5hZGRKYXZhUmVwbGFjZUhvb2spKCdjb20ud29ya2xpZ2h0LndsY2xpZW50LmNlcnRpZmljYXRlcGlubmluZy5Ib3N0TmFtZVZlcmlmaWVyV2l0aENlcnRpZmljYXRlUGlubmluZzo6dmVyaWZ5JywgWydzdHInLCAnamF2YS5zZWN1cml0eS5jZXJ0Llg1MDlDZXJ0aWZpY2F0ZSddLCBmdW5jdGlvbiAoZGF0YSkgeyByZXR1cm4gcmV0dXJuVm9pZEhvb2soZGF0YSwgZmFsc2UpOyB9KTtcbigwLCBqYXZhXzEuYWRkSmF2YVJlcGxhY2VIb29rKSgnY29tLndvcmtsaWdodC53bGNsaWVudC5jZXJ0aWZpY2F0ZXBpbm5pbmcuSG9zdE5hbWVWZXJpZmllcldpdGhDZXJ0aWZpY2F0ZVBpbm5pbmc6OnZlcmlmeScsIFsnc3RyW10nLCAnc3RyW10nXSwgZnVuY3Rpb24gKGRhdGEpIHsgcmV0dXJuIHJldHVyblZvaWRIb29rKGRhdGEsIGZhbHNlKTsgfSk7XG4oMCwgamF2YV8xLmFkZEphdmFSZXBsYWNlSG9vaykoJ2NvbS53b3JrbGlnaHQud2xjbGllbnQuY2VydGlmaWNhdGVwaW5uaW5nLkhvc3ROYW1lVmVyaWZpZXJXaXRoQ2VydGlmaWNhdGVQaW5uaW5nOjp2ZXJpZnknLCBbJ3N0cicsICdqYXZheC5uZXQuc3NsLlNTTFNlc3Npb24nXSwgZnVuY3Rpb24gKGRhdGEpIHsgcmV0dXJuIHJldHVyblRydWVIb29rKGRhdGEsIGZhbHNlKTsgfSk7XG4vLyBDb25zY3J5cHQgQ2VydFBpbk1hbmFnZXJcbigwLCBqYXZhXzEuYWRkSmF2YVJlcGxhY2VIb29rKSgnb3JnLmNvbnNjcnlwdC5DZXJ0UGluTWFuYWdlcjo6Y2hlY2tDaGFpblBpbm5pbmcnLCBbJ3N0cicsICdqYXZhLnV0aWwuTGlzdCddLCByZXR1cm5Wb2lkSG9vayk7XG4vLyBDb25zY3J5cHQgQ2VydFBpbk1hbmFnZXIgKExlZ2FjeSlcbigwLCBqYXZhXzEuYWRkSmF2YVJlcGxhY2VIb29rKSgnb3JnLmNvbnNjcnlwdC5DZXJ0UGluTWFuYWdlcjo6aXNDaGFpblZhbGlkJywgWydzdHInLCAnamF2YS51dGlsLkxpc3QnXSwgZnVuY3Rpb24gKGRhdGEpIHsgcmV0dXJuIHJldHVyblRydWVIb29rOyB9KTtcbi8vIENXQUMtTmV0c2VjdXJpdHkgQ2VydFBpbk1hbmFnZXJcbigwLCBqYXZhXzEuYWRkSmF2YVJlcGxhY2VIb29rKSgnY29tLmNvbW1vbnN3YXJlLmN3YWMubmV0c2VjdXJpdHkuY29uc2NyeXB0LkNlcnRQaW5NYW5hZ2VyOjppc0NoYWluVmFsaWQnLCBbJ3N0cicsICdqYXZhLnV0aWwuTGlzdCddLCByZXR1cm5UcnVlSG9vayk7XG4vLyBXb3JrbGlnaHQgQW5kcm9pZGdhcCBXTENlcnRpZmljYXRlUGlubmluZ1BsdWdpblxuKDAsIGphdmFfMS5hZGRKYXZhUmVwbGFjZUhvb2spKCdjb20ud29ya2xpZ2h0LmFuZHJvaWRnYXAucGx1Z2luLldMQ2VydGlmaWNhdGVQaW5uaW5nUGx1Z2luOjpleGVjdXRlJywgWydzdHInLCAnb3JnLmpzb24uSlNPTkFycmF5JywgJ29yZy5hcGFjaGUuY29yZG92YS5DYWxsYmFja0NvbnRleHQnXSwgcmV0dXJuVHJ1ZUhvb2spO1xuLy8gTmV0dHkgRmluZ2VycHJpbnRUcnVzdE1hbmFnZXJGYWN0b3J5XG4oMCwgamF2YV8xLmFkZEphdmFSZXBsYWNlSG9vaykoJ2lvLm5ldHR5LmhhbmRsZXIuc3NsLnV0aWwuRmluZ2VycHJpbnRUcnVzdE1hbmFnZXJGYWN0b3J5OjpjaGVja1RydXN0ZWQnLCBbJ3N0cicsICdbTGphdmEuc2VjdXJpdHkuY2VydC5YNTA5Q2VydGlmaWNhdGU7J10sIGZ1bmN0aW9uIChkYXRhKSB7IHJldHVybiByZXR1cm5Wb2lkSG9vayhkYXRhLCBkYXRhW1widGhpc1wiXS5maW5nZXJwcmludHMubGVuZ3RoID4gMCk7IH0pO1xuLy8gU3F1YXJldXAgQ2VydGlmaWNhdGVQaW5uZXJcbigwLCBqYXZhXzEuYWRkSmF2YVJlcGxhY2VIb29rKSgnY29tLnNxdWFyZXVwLm9raHR0cC5DZXJ0aWZpY2F0ZVBpbm5lcjo6Y2hlY2snLCBbJ3N0cicsICdbTGphdmEuc2VjdXJpdHkuY2VydC5DZXJ0aWZpY2F0ZTsnXSwgZnVuY3Rpb24gKGRhdGEpIHsgcmV0dXJuIHJldHVyblZvaWRIb29rKGRhdGEsIGRhdGFbXCJ0aGlzXCJdLmhvc3RuYW1lVG9QaW5zLmdldChkYXRhLmFyZ3NbMF0pICE9IG51bGwpOyB9KTtcbigwLCBqYXZhXzEuYWRkSmF2YVJlcGxhY2VIb29rKSgnY29tLnNxdWFyZXVwLm9raHR0cC5DZXJ0aWZpY2F0ZVBpbm5lcjo6Y2hlY2snLCBbJ3N0cicsICdqYXZhLnV0aWwuTGlzdCddLCBmdW5jdGlvbiAoZGF0YSkgeyByZXR1cm4gcmV0dXJuVm9pZEhvb2soZGF0YSwgZGF0YVtcInRoaXNcIl0uaG9zdG5hbWVUb1BpbnMuZ2V0KGRhdGEuYXJnc1swXSkgIT0gbnVsbCk7IH0pO1xuLy8gU3F1YXJldXAgT2tIb3N0bmFtZVZlcmlmaWVyXG4oMCwgamF2YV8xLmFkZEphdmFSZXBsYWNlSG9vaykoJ2NvbS5zcXVhcmV1cC5va2h0dHAuaW50ZXJuYWwudGxzLk9rSG9zdG5hbWVWZXJpZmllcjo6dmVyaWZ5JywgWydzdHInLCAnamF2YS5zZWN1cml0eS5jZXJ0Llg1MDlDZXJ0aWZpY2F0ZSddLCBmdW5jdGlvbiAoZGF0YSkgeyByZXR1cm4gcmV0dXJuVHJ1ZUhvb2soZGF0YSwgZmFsc2UpOyB9KTtcbigwLCBqYXZhXzEuYWRkSmF2YVJlcGxhY2VIb29rKSgnY29tLnNxdWFyZXVwLm9raHR0cC5pbnRlcm5hbC50bHMuT2tIb3N0bmFtZVZlcmlmaWVyOjp2ZXJpZnknLCBbJ3N0cicsICdqYXZheC5uZXQuc3NsLlNTTFNlc3Npb24nXSwgZnVuY3Rpb24gKGRhdGEpIHsgcmV0dXJuIHJldHVyblRydWVIb29rKGRhdGEsIGZhbHNlKTsgfSk7XG4vLyBBbmRyb2lkIFdlYlZpZXdDbGllbnRcbigwLCBqYXZhXzEuYWRkSmF2YVJlcGxhY2VIb29rKSgnYW5kcm9pZC53ZWJraXQuV2ViVmlld0NsaWVudDo6b25SZWNlaXZlZFNzbEVycm9yJywgWydhbmRyb2lkLndlYmtpdC5XZWJWaWV3JywgJ2FuZHJvaWQud2Via2l0LlNzbEVycm9ySGFuZGxlcicsICdhbmRyb2lkLm5ldC5odHRwLlNzbEVycm9yJ10sIGZ1bmN0aW9uIChkYXRhKSB7IHJldHVybiByZXR1cm5Wb2lkSG9vayhkYXRhLCBmYWxzZSk7IH0pO1xuKDAsIGphdmFfMS5hZGRKYXZhUmVwbGFjZUhvb2spKCdhbmRyb2lkLndlYmtpdC5XZWJWaWV3Q2xpZW50OjpvblJlY2VpdmVkU3NsRXJyb3InLCBbJ2FuZHJvaWQud2Via2l0LldlYlZpZXcnLCAnYW5kcm9pZC53ZWJraXQuV2ViUmVzb3VyY2VSZXF1ZXN0JywgJ2FuZHJvaWQud2Via2l0LldlYlJlc291cmNlRXJyb3InXSwgZnVuY3Rpb24gKGRhdGEpIHsgcmV0dXJuIHJldHVyblZvaWRIb29rKGRhdGEsIGZhbHNlKTsgfSk7XG4oMCwgamF2YV8xLmFkZEphdmFSZXBsYWNlSG9vaykoJ2FuZHJvaWQud2Via2l0LldlYlZpZXdDbGllbnQ6Om9uUmVjZWl2ZWRFcnJvcicsIFsnYW5kcm9pZC53ZWJraXQuV2ViVmlldycsICdpbnQnLCAnc3RyJywgJ3N0ciddLCBmdW5jdGlvbiAoZGF0YSkgeyByZXR1cm4gcmV0dXJuVm9pZEhvb2soZGF0YSwgZmFsc2UpOyB9KTtcbigwLCBqYXZhXzEuYWRkSmF2YVJlcGxhY2VIb29rKSgnYW5kcm9pZC53ZWJraXQuV2ViVmlld0NsaWVudDo6b25SZWNlaXZlZEVycm9yJywgWydhbmRyb2lkLndlYmtpdC5XZWJWaWV3JywgJ2FuZHJvaWQud2Via2l0LldlYlJlc291cmNlUmVxdWVzdCcsICdhbmRyb2lkLndlYmtpdC5XZWJSZXNvdXJjZUVycm9yJ10sIGZ1bmN0aW9uIChkYXRhKSB7IHJldHVybiByZXR1cm5Wb2lkSG9vayhkYXRhLCBmYWxzZSk7IH0pO1xuLy8gQXBhY2hlIENvcmRvdmEgV2ViVmlld0NsaWVudFxuKDAsIGphdmFfMS5hZGRKYXZhUmVwbGFjZUhvb2spKCdvcmcuYXBhY2hlLmNvcmRvdmEuQ29yZG92YVdlYlZpZXdDbGllbnQ6Om9uUmVjZWl2ZWRTc2xFcnJvcicsIFsnb3JnLmFwYWNoZS5jb3Jkb3ZhLkNvcmRvdmFXZWJWaWV3JywgJ2FuZHJvaWQud2Via2l0LlNzbEVycm9ySGFuZGxlcicsICdhbmRyb2lkLm5ldC5odHRwLlNzbEVycm9yJ10sIGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgKDAsIGxvZ18xLmxvZ0phdmFGdW5jdGlvbikoZGF0YSwgZmFsc2UpO1xuICAgIGRhdGEuYXJnc1syXS5wcm9jZWVkKCk7XG59KTtcbi8vIEJveWUgQWJzdHJhY3RWZXJpZmllclxuKDAsIGphdmFfMS5hZGRKYXZhUmVwbGFjZUhvb2spKCdjaC5ib3llLmh0dHBjbGllbnRhbmRyb2lkbGliLmNvbm4uc3NsLkFic3RyYWN0VmVyaWZpZXI6OnZlcmlmeScsIFsnc3RyJywgJ2phdmF4Lm5ldC5zc2wuU1NMU29ja2V0J10sIGZ1bmN0aW9uIChkYXRhKSB7IHJldHVybiByZXR1cm5Wb2lkSG9vayhkYXRhLCBmYWxzZSk7IH0pO1xuLy8gQXBhY2hlIEFic3RyYWN0VmVyaWZpZXJcbigwLCBqYXZhXzEuYWRkSmF2YVJlcGxhY2VIb29rKSgnb3JnLmFwYWNoZS5odHRwLmNvbm4uc3NsLkFic3RyYWN0VmVyaWZpZXI6OnZlcmlmeScsIFsnc3RyJywgJ3N0cltdJywgJ3N0cltdJywgJ2Jvb2xlYW4nXSwgZnVuY3Rpb24gKGRhdGEpIHsgcmV0dXJuIHJldHVyblZvaWRIb29rKGRhdGEsIGZhbHNlKTsgfSk7XG4oMCwgamF2YV8xLmFkZEphdmFSZXBsYWNlSG9vaykoJ29yZy5hcGFjaGUuaHR0cC5jb25uLnNzbC5BYnN0cmFjdFZlcmlmaWVyOjp2ZXJpZnknLCBbJ3N0cicsICdqYXZhLnNlY3VyaXR5LmNlcnQuWDUwOUNlcnRpZmljYXRlJ10sIGZ1bmN0aW9uIChkYXRhKSB7IHJldHVybiByZXR1cm5Wb2lkSG9vayhkYXRhLCBmYWxzZSk7IH0pO1xuKDAsIGphdmFfMS5hZGRKYXZhUmVwbGFjZUhvb2spKCdvcmcuYXBhY2hlLmh0dHAuY29ubi5zc2wuQWJzdHJhY3RWZXJpZmllcjo6dmVyaWZ5JywgWydzdHInLCAnamF2YXgubmV0LnNzbC5TU0xTZXNzaW9uJ10sIGZ1bmN0aW9uIChkYXRhKSB7IHJldHVybiByZXR1cm5UcnVlSG9vayhkYXRhLCBmYWxzZSk7IH0pO1xuKDAsIGphdmFfMS5hZGRKYXZhUmVwbGFjZUhvb2spKCdvcmcuYXBhY2hlLmh0dHAuY29ubi5zc2wuQWJzdHJhY3RWZXJpZmllcjo6dmVyaWZ5JywgWydzdHInLCAnamF2YXgubmV0LnNzbC5TU0xTb2NrZXQnXSwgZnVuY3Rpb24gKGRhdGEpIHsgcmV0dXJuIHJldHVyblZvaWRIb29rKGRhdGEsIGZhbHNlKTsgfSk7XG4vLyBDaHJvbWl1bSBDcm9uZXRcbigwLCBqYXZhXzEuYWRkSmF2YVByZUhvb2spKCdvcmcuY2hyb21pdW0ubmV0LkNyb25ldEVuZ2luZSRCdWlsZGVyOjplbmFibGVQdWJsaWNLZXlQaW5uaW5nQnlwYXNzRm9yTG9jYWxUcnVzdEFuY2hvcnMnLCBbJ2Jvb2xlYW4nXSwgZnVuY3Rpb24gKGRhdGEpIHtcbiAgICBkYXRhLmFyZ3NbMF0gPSB0cnVlO1xufSk7XG4oMCwgamF2YV8xLmFkZEphdmFSZXBsYWNlSG9vaykoJ29yZy5jaHJvbWl1bS5uZXQuQ3JvbmV0RW5naW5lJEJ1aWxkZXI6OmFkZFB1YmxpY0tleVBpbnMnLCBbJ3N0cicsICdqYXZhLnV0aWwuU2V0JywgJ2Jvb2xlYW4nLCAnamF2YS51dGlsLkRhdGUnXSwgZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAoMCwgbG9nXzEubG9nSmF2YUZ1bmN0aW9uKShkYXRhKTtcbiAgICByZXR1cm4gZGF0YVtcInRoaXNcIl07XG59KTtcbi8vIEZsdXR0ZXIgUGlubmluZyBwYWNrYWdlcyBodHRwX2NlcnRpZmljYXRlX3Bpbm5pbmcgYW5kIHNzbF9waW5uaW5nX3BsdWdpblxuKDAsIGphdmFfMS5hZGRKYXZhUmVwbGFjZUhvb2spKCdkaWVmZmVyc29uLmh0dHBfY2VydGlmaWNhdGVfcGlubmluZy5IdHRwQ2VydGlmaWNhdGVQaW5uaW5nOjpjaGVja0Nvbm5leGlvbicsIFsnamF2YS5sYW5nLlN0cmluZycsICdqYXZhLnV0aWwuTGlzdCcsICdqYXZhLnV0aWwuTWFwJywgJ2ludCcsICdqYXZhLmxhbmcuU3RyaW5nJ10sIHJldHVyblRydWVIb29rKTtcbigwLCBqYXZhXzEuYWRkSmF2YVJlcGxhY2VIb29rKSgnY29tLm1hY2lmLnBsdWdpbi5zc2xwaW5uaW5ncGx1Z2luLlNzbFBpbm5pbmdQbHVnaW46OmNoZWNrUGlubmluZycsIFsnamF2YS5sYW5nLlN0cmluZycsICdqYXZhLnV0aWwuTGlzdCcsICdqYXZhLnV0aWwuTWFwJywgJ2ludCcsICdqYXZhLmxhbmcuU3RyaW5nJ10sIHJldHVyblRydWVIb29rKTtcbi8vIENvbW1iYW5rIEtJQVdoaXRlbGlzdCBcbigwLCBqYXZhXzEuYWRkSmF2YVJlcGxhY2VIb29rKSgnY29tLklDVFNlY3VyaXR5LktJQS5LSUFXaGl0ZWxpc3Q6OnZlcmlmeUNlcnRpZmljYXRlJywgWydzdHInLCAnc3RyJ10sIGZ1bmN0aW9uIChkYXRhKSB7IHJldHVybiByZXR1cm5UcnVlSG9vayhkYXRhLCBmYWxzZSk7IH0pO1xuLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vXG4vLyBpT1MgUGlubmluZyBieXBhc3MgLy9cbi8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1xuLy8gaHR0cHM6Ly9naXRodWIuY29tL3NlbnNlcG9zdC9vYmplY3Rpb24vYmxvYi9mNDc5MjZlOTBjZThiNjY1NWVjYjQzMTczMGI2Njc0ZTQxYmM1NjI1L2FnZW50L3NyYy9pb3MvcGlubmluZy50c1xuaWYgKGdsb2JhbC5zYWZlTW9kZSAhPSAneWVzJykge1xuICAgIC8vIEFGU2VjdXJpdHlQb2xpY3kgc2V0U1NMUGlubmluZ01vZGVcbiAgICAoMCwgb2JqY18xLmFkZE9iakNQcmVIb29rKSgnLVtBRlNlY3VyaXR5UG9saWN5IHNldFNTTFBpbm5pbmdNb2RlOl0nLCAxLCBmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICBpZiAoIWRhdGEuYXJnc1swXS5pc051bGwoKSkge1xuICAgICAgICAgICAgKDAsIGxvZ18xLmxvZ09iakNGdW5jdGlvbikoZGF0YSk7XG4gICAgICAgICAgICBkYXRhLmFyZ3NbMF0gPSBwdHIoMCk7XG4gICAgICAgIH1cbiAgICB9KTtcbiAgICAvLyBBRlNlY3VyaXR5UG9saWN5IHNldEFsbG93SW52YWxpZENlcnRpZmljYXRlc1xuICAgICgwLCBvYmpjXzEuYWRkT2JqQ1ByZUhvb2spKCctW0FGU2VjdXJpdHlQb2xpY3kgc2V0QWxsb3dJbnZhbGlkQ2VydGlmaWNhdGVzOl0nLCAxLCBmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICBkYXRhLmFyZ3NbMF0gPSBwdHIoMSk7IC8vIHRydWVcbiAgICB9KTtcbiAgICAvLyBBRlNlY3VyaXR5UG9saWN5IHBvbGljeVdpdGhQaW5uaW5nTW9kZVxuICAgICgwLCBvYmpjXzEuYWRkT2JqQ1ByZUhvb2spKCcrW0FGU2VjdXJpdHlQb2xpY3kgcG9saWN5V2l0aFBpbm5pbmdNb2RlOl0nLCAxLCBmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICBpZiAoIWRhdGEuYXJnc1swXS5pc051bGwoKSkge1xuICAgICAgICAgICAgKDAsIGxvZ18xLmxvZ09iakNGdW5jdGlvbikoZGF0YSk7XG4gICAgICAgICAgICBkYXRhLmFyZ3NbMF0gPSBwdHIoMCk7IC8vIEFGU1NMUGlubmluZ01vZGVOb25lXG4gICAgICAgIH1cbiAgICB9KTtcbiAgICAvLyBBRlNlY3VyaXR5UG9saWN5IHBvbGljeVdpdGhQaW5uaW5nTW9kZVxuICAgICgwLCBvYmpjXzEuYWRkT2JqQ1ByZUhvb2spKCcrW0FGU2VjdXJpdHlQb2xpY3kgcG9saWN5V2l0aFBpbm5pbmdNb2RlOndpdGhQaW5uZWRDZXJ0aWZpY2F0ZXM6XScsIDIsIGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgICAgIGlmICghZGF0YS5hcmdzWzBdLmlzTnVsbCgpKSB7XG4gICAgICAgICAgICAoMCwgbG9nXzEubG9nT2JqQ0Z1bmN0aW9uKShkYXRhKTtcbiAgICAgICAgICAgIGRhdGEuYXJnc1swXSA9IHB0cigwKTsgLy8gQUZTU0xQaW5uaW5nTW9kZU5vbmVcbiAgICAgICAgfVxuICAgIH0pO1xufVxuaWYgKE9iakMuYXZhaWxhYmxlKSB7XG4gICAgdmFyIE5TVVJMQ3JlZGVudGlhbF8xID0gT2JqQy5jbGFzc2VzLk5TVVJMQ3JlZGVudGlhbDtcbiAgICB2YXIgcmVzb2x2ZXIgPSBuZXcgQXBpUmVzb2x2ZXIoXCJvYmpjXCIpO1xuICAgIHZhciBzZWFyY2ggPSByZXNvbHZlci5lbnVtZXJhdGVNYXRjaGVzKFwiLVsqIFVSTFNlc3Npb246ZGlkUmVjZWl2ZUNoYWxsZW5nZTpjb21wbGV0aW9uSGFuZGxlcjpdXCIpO1xuICAgIGZvciAodmFyIF9pID0gMCwgc2VhcmNoXzEgPSBzZWFyY2g7IF9pIDwgc2VhcmNoXzEubGVuZ3RoOyBfaSsrKSB7XG4gICAgICAgIHZhciBtYXRjaCA9IHNlYXJjaF8xW19pXTtcbiAgICAgICAgSW50ZXJjZXB0b3IuYXR0YWNoKG1hdGNoLmFkZHJlc3MsIHtcbiAgICAgICAgICAgIG9uRW50ZXI6IGZ1bmN0aW9uIChhcmdzKSB7XG4gICAgICAgICAgICAgICAgdmFyIHNlbGYgPSBuZXcgT2JqQy5PYmplY3QoYXJnc1swXSk7XG4gICAgICAgICAgICAgICAgdmFyIHNlbGVjdG9yID0gT2JqQy5zZWxlY3RvckFzU3RyaW5nKGFyZ3NbMV0pO1xuICAgICAgICAgICAgICAgIHZhciBtZXRob2QgPSBzZWxmLiRtZXRob2RzLmZpbmQoZnVuY3Rpb24gKG0pIHsgcmV0dXJuIG0uZW5kc1dpdGgoJyAnICsgc2VsZWN0b3IpOyB9KTtcbiAgICAgICAgICAgICAgICB2YXIgZnVuTmFtZSA9IG1ldGhvZC5zdWJzdHJpbmcoMCwgMSkgKyAnWycgKyBzZWxmLiRjbGFzc05hbWUgKyAnICcgKyBtZXRob2Quc3Vic3RyaW5nKDIpICsgJ10nO1xuICAgICAgICAgICAgICAgICgwLCBsb2dfMS5sb2dPYmpDRnVuY3Rpb24pKHtcbiAgICAgICAgICAgICAgICAgICAgZnVuOiBudWxsLFxuICAgICAgICAgICAgICAgICAgICBmdW5OYW1lOiBmdW5OYW1lLFxuICAgICAgICAgICAgICAgICAgICBzZWxmOiBzZWxmLFxuICAgICAgICAgICAgICAgICAgICBhcmdzOiBbYXJnc1syXSwgYXJnc1szXV0sXG4gICAgICAgICAgICAgICAgICAgIFwidGhpc1wiOiB0aGlzLFxuICAgICAgICAgICAgICAgICAgICBkZXRlY3RvcjogbnVsbFxuICAgICAgICAgICAgICAgIH0sIGZhbHNlKTtcbiAgICAgICAgICAgICAgICB2YXIgY2hhbGxlbmdlID0gbmV3IE9iakMuT2JqZWN0KGFyZ3NbM10pO1xuICAgICAgICAgICAgICAgIHZhciBjb21wbGV0aW9uSGFuZGxlciA9IG5ldyBPYmpDLkJsb2NrKGFyZ3NbNF0pO1xuICAgICAgICAgICAgICAgIHZhciBzYXZlZENvbXBsZXRpb25IYW5kbGVyID0gY29tcGxldGlvbkhhbmRsZXIuaW1wbGVtZW50YXRpb247XG4gICAgICAgICAgICAgICAgY29tcGxldGlvbkhhbmRsZXIuaW1wbGVtZW50YXRpb24gPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBjcmVkZW50aWFsID0gTlNVUkxDcmVkZW50aWFsXzEuY3JlZGVudGlhbEZvclRydXN0XyhjaGFsbGVuZ2UucHJvdGVjdGlvblNwYWNlKCkuc2VydmVyVHJ1c3QoKSk7XG4gICAgICAgICAgICAgICAgICAgIHZhciBzZW5kZXIgPSBjaGFsbGVuZ2Uuc2VuZGVyKCk7XG4gICAgICAgICAgICAgICAgICAgIGlmIChzZW5kZXIgIT0gbnVsbCkge1xuICAgICAgICAgICAgICAgICAgICAgICAgc2VuZGVyLnVzZUNyZWRlbnRpYWxfZm9yQXV0aGVudGljYXRpb25DaGFsbGVuZ2VfKGNyZWRlbnRpYWwsIGNoYWxsZW5nZSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgc2F2ZWRDb21wbGV0aW9uSGFuZGxlcigwLCBjcmVkZW50aWFsKTtcbiAgICAgICAgICAgICAgICB9O1xuICAgICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICB9XG59XG4vLyBUU0tQaW5uaW5nVmFsaWRhdG9yIGV2YWx1YXRlVHJ1c3RcbigwLCBvYmpjXzEuYWRkT2JqQ1Bvc3RIb29rKSgnLVtUU0tQaW5uaW5nVmFsaWRhdG9yIGV2YWx1YXRlVHJ1c3Q6Zm9ySG9zdG5hbWU6XScsIDIsIGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgaWYgKCFkYXRhLnJldHZhbC5pc051bGwoKSkge1xuICAgICAgICAoMCwgbG9nXzEubG9nT2JqQ0Z1bmN0aW9uKShkYXRhKTtcbiAgICAgICAgZGF0YS5yZXR2YWwucmVwbGFjZShwdHIoMCkpO1xuICAgIH1cbn0pO1xuLy8gQ3VzdG9tVVJMQ29ubmVjdGlvbkRlbGVnYXRlIGlzRmluZ2VycHJpbnRUcnVzdGVkXG4oMCwgb2JqY18xLmFkZE9iakNQb3N0SG9vaykoJy1bQ3VzdG9tVVJMQ29ubmVjdGlvbkRlbGVnYXRlIGlzRmluZ2VycHJpbnRUcnVzdGVkOl0nLCAxLCBmdW5jdGlvbiAoZGF0YSkge1xuICAgIGlmIChkYXRhLnJldHZhbC5pc051bGwoKSkge1xuICAgICAgICAoMCwgbG9nXzEubG9nT2JqQ0Z1bmN0aW9uKShkYXRhKTtcbiAgICAgICAgZGF0YS5yZXR2YWwucmVwbGFjZShwdHIoMSkpOyAvLyB0cnVlXG4gICAgfVxufSk7XG4vLyBTU0xTZXRTZXNzaW9uT3B0aW9uXG4oMCwgbmF0aXZlXzEuYWRkUHJlSG9vaykoJ1NTTFNldFNlc3Npb25PcHRpb24nLCBbJ3B0cicsICdpbnQnLCAnaW50J10sIGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgaWYgKGRhdGEuYXJnc1sxXSA9PSAwKSB7IC8vIG9wdGlvbiA9PSBTU0xTZXNzaW9uT3B0aW9uLmJyZWFrT25TZXJ2ZXJBdXRoXG4gICAgICAgICgwLCBsb2dfMS5sb2dGdW5jdGlvbikoZGF0YSwgZmFsc2UpO1xuICAgICAgICBkYXRhLmFyZ3NbMl0gPSAxOyAvLyB0cnVlXG4gICAgfVxufSwgJ1NlY3VyaXR5Jyk7XG4vLyBTU0xDcmVhdGVDb250ZXh0XG4oMCwgbmF0aXZlXzEuYWRkUG9zdEhvb2spKCdTU0xDcmVhdGVDb250ZXh0JywgWydwdHInLCAnaW50JywgJ2ludCddLCBmdW5jdGlvbiAoZGF0YSkge1xuICAgIHZhciBjdHggPSBkYXRhLnJldHZhbDtcbiAgICBpZiAoIWN0eC5pc051bGwoKSkge1xuICAgICAgICB2YXIgU1NMU2V0U2Vzc2lvbk9wdGlvbiA9IG5ldyBOYXRpdmVGdW5jdGlvbihNb2R1bGUuZmluZEV4cG9ydEJ5TmFtZSgnU2VjdXJpdHknLCAnU1NMU2V0U2Vzc2lvbk9wdGlvbicpLCAnaW50JywgWydwb2ludGVyJywgJ2ludCcsICdpbnQnXSk7XG4gICAgICAgIFNTTFNldFNlc3Npb25PcHRpb24oY3R4LCAwLCAxKTsgLy8gU1NMU2Vzc2lvbk9wdGlvbi5icmVha09uU2VydmVyQXV0aCB0cnVlXG4gICAgfVxufSwgJ1NlY3VyaXR5Jyk7XG4vLyBTU0xIYW5kc2hha2VcbigwLCBuYXRpdmVfMS5hZGRQb3N0SG9vaykoJ1NTTEhhbmRzaGFrZScsIFsncHRyJ10sIGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgaWYgKGRhdGEucmV0dmFsLnRvSW50MzIoKSA9PSAtOTQ4MSkgeyAvLyBlcnJTU0xTZXJ2ZXJBdXRoQ29tcGxldGVkXG4gICAgICAgIHZhciBTU0xIYW5kc2hha2UgPSBuZXcgTmF0aXZlRnVuY3Rpb24oTW9kdWxlLmZpbmRFeHBvcnRCeU5hbWUoJ1NlY3VyaXR5JywgJ1NTTEhhbmRzaGFrZScpLCAnaW50JywgWydwb2ludGVyJ10pO1xuICAgICAgICBkYXRhLnJldHZhbC5yZXBsYWNlKHB0cigwKSk7XG4gICAgICAgIFNTTEhhbmRzaGFrZShkYXRhLmFyZ3NbMF0pO1xuICAgIH1cbn0sICdTZWN1cml0eScpO1xuLy8gdGxzX2hlbHBlcl9jcmVhdGVfcGVlcl90cnVzdCBhbmQgbndfdGxzX2NyZWF0ZV9wZWVyX3RydXN0XG52YXIgZnVuY3Rpb25zID0gWyd0bHNfaGVscGVyX2NyZWF0ZV9wZWVyX3RydXN0JywgJ253X3Rsc19jcmVhdGVfcGVlcl90cnVzdCddO1xuZnVuY3Rpb25zLmZvckVhY2goZnVuY3Rpb24gKGZ1bmN0aW9uTmFtZSkge1xuICAgIHZhciBmdW5jID0gTW9kdWxlLmZpbmRFeHBvcnRCeU5hbWUobnVsbCwgZnVuY3Rpb25OYW1lKTtcbiAgICBpZiAoZnVuYyAhPSBudWxsKSB7XG4gICAgICAgIEludGVyY2VwdG9yLnJlcGxhY2UoZnVuYywgbmV3IE5hdGl2ZUNhbGxiYWNrKGZ1bmN0aW9uICh0bHMsIHNlcnZlciwgdHJ1c3RSZWYpIHtcbiAgICAgICAgICAgIHJldHVybiAwOyAvLyBlcnJTZWNTdWNjZXNzXG4gICAgICAgIH0sICdpbnQnLCBbJ3BvaW50ZXInLCAnYm9vbCcsICdwb2ludGVyJ10pKTtcbiAgICB9XG59KTtcbi8vIFNTTF9zZXRfY3VzdG9tX3ZlcmlmeVxuaWYgKE9iakMuYXZhaWxhYmxlKSB7XG4gICAgdmFyIGN1c3RvbVZlcmlmeSA9IE1vZHVsZS5maW5kRXhwb3J0QnlOYW1lKG51bGwsICdTU0xfQ1RYX3NldF9jdXN0b21fdmVyaWZ5Jyk7XG4gICAgaWYgKGN1c3RvbVZlcmlmeSA9PSBudWxsKSB7XG4gICAgICAgIGN1c3RvbVZlcmlmeSA9IE1vZHVsZS5maW5kRXhwb3J0QnlOYW1lKG51bGwsICdTU0xfc2V0X2N1c3RvbV92ZXJpZnknKTtcbiAgICB9XG4gICAgdmFyIHBza0lkZW50aXR5ID0gTW9kdWxlLmZpbmRFeHBvcnRCeU5hbWUobnVsbCwgJ1NTTF9nZXRfcHNrX2lkZW50aXR5Jyk7XG4gICAgaWYgKGN1c3RvbVZlcmlmeSAhPSBudWxsICYmIHBza0lkZW50aXR5ICE9IG51bGwpIHtcbiAgICAgICAgdmFyIFNTTF9zZXRfY3VzdG9tX3ZlcmlmeV8xID0gbmV3IE5hdGl2ZUZ1bmN0aW9uKGN1c3RvbVZlcmlmeSwgJ3ZvaWQnLCBbJ3BvaW50ZXInLCAnaW50JywgJ3BvaW50ZXInXSk7XG4gICAgICAgIHZhciBTU0xfZ2V0X3Bza19pZGVudGl0eSA9IG5ldyBOYXRpdmVGdW5jdGlvbihwc2tJZGVudGl0eSwgJ3BvaW50ZXInLCBbJ3BvaW50ZXInXSk7XG4gICAgICAgIHZhciBjdXN0b21WZXJpZnlDYWxsYmFja18xID0gbmV3IE5hdGl2ZUNhbGxiYWNrKGZ1bmN0aW9uIChzc2wsIG91dF9hbGVydCkge1xuICAgICAgICAgICAgcmV0dXJuIDA7XG4gICAgICAgIH0sIFwiaW50XCIsIFtcInBvaW50ZXJcIiwgXCJwb2ludGVyXCJdKTtcbiAgICAgICAgSW50ZXJjZXB0b3IucmVwbGFjZShTU0xfc2V0X2N1c3RvbV92ZXJpZnlfMSwgbmV3IE5hdGl2ZUNhbGxiYWNrKGZ1bmN0aW9uIChzc2wsIG1vZGUsIGNhbGxiYWNrKSB7XG4gICAgICAgICAgICAoMCwgbG9nXzEubG9nRnVuY3Rpb24pKHtcbiAgICAgICAgICAgICAgICBzeXNjYWxsOiAnU1NMX3NldF9jdXN0b21fdmVyaWZ5JyxcbiAgICAgICAgICAgICAgICBhcmdzOiBbc3NsLCBtb2RlLCBjYWxsYmFja10sXG4gICAgICAgICAgICAgICAgLy8gQHRzLWlnbm9yZVxuICAgICAgICAgICAgICAgIGNvbnRleHQ6IHRoaXMsXG4gICAgICAgICAgICAgICAgZGV0ZWN0b3I6IG51bGxcbiAgICAgICAgICAgIH0sIGZhbHNlKTtcbiAgICAgICAgICAgIFNTTF9zZXRfY3VzdG9tX3ZlcmlmeV8xKHNzbCwgbW9kZSwgY3VzdG9tVmVyaWZ5Q2FsbGJhY2tfMSk7XG4gICAgICAgIH0sIFwidm9pZFwiLCBbXCJwb2ludGVyXCIsIFwiaW50XCIsIFwicG9pbnRlclwiXSkpO1xuICAgICAgICBJbnRlcmNlcHRvci5yZXBsYWNlKFNTTF9nZXRfcHNrX2lkZW50aXR5LCBuZXcgTmF0aXZlQ2FsbGJhY2soZnVuY3Rpb24gKHNzbCkge1xuICAgICAgICAgICAgcmV0dXJuIE1lbW9yeS5hbGxvY1V0ZjhTdHJpbmcoJ2Zha2VJZGVudGl0eScpO1xuICAgICAgICB9LCBcInBvaW50ZXJcIiwgW1wicG9pbnRlclwiXSkpO1xuICAgIH1cbn1cbiIsIlwidXNlIHN0cmljdFwiO1xuZXhwb3J0cy5fX2VzTW9kdWxlID0gdHJ1ZTtcbnZhciBhcHBzXzEgPSByZXF1aXJlKFwiLi4vaG9va3MvYXBwc1wiKTtcbnZhciBmaWxlXzEgPSByZXF1aXJlKFwiLi4vaG9va3MvZmlsZVwiKTtcbnZhciB1dGlsXzEgPSByZXF1aXJlKFwiLi4vaW5jL3V0aWxcIik7XG52YXIgbG9nXzEgPSByZXF1aXJlKFwiLi4vaW5jL2xvZ1wiKTtcbnZhciBuYXRpdmVfMSA9IHJlcXVpcmUoXCIuLi9ob29rcy9uYXRpdmVcIik7XG52YXIgc29ja2V0XzEgPSByZXF1aXJlKFwiLi4vaG9va3Mvc29ja2V0XCIpO1xudmFyIGZpbGVIb29rcyA9IGZpbGVfMS5GaWxlSG9va3MuZ2V0SW5zdGFuY2UoKTtcbnZhciBhcHBzSG9va3MgPSBhcHBzXzEuQXBwc0hvb2tzLmdldEluc3RhbmNlKCk7XG4vLyBIaWRlIGJsYWNrbGlzdGVkIGZpbGVzXG5maWxlSG9va3MuYWNjZXNzRmlsZUhvb2soZmlsZV8xLkZpbGVQYXR0ZXJuLmZyb20oZ2xvYmFsLmNvbnRleHQucm9vdC5maWxlcy5ibGFja2xpc3QpLCB0cnVlKTtcbmZpbGVIb29rcy5hY2Nlc3NGaWxlSG9vayhmaWxlXzEuRmlsZVBhdHRlcm4uZnJvbShnbG9iYWwuY29udGV4dC5yb290LmZpbGVzLmxvZykpO1xuLy8gTW9kaWZ5IC9wcm9jL21vdW50cyBhbmQgL3Byb2MvPHBpZD4vbW91bnRzIGZpbGVzXG5maWxlSG9va3MucmVwbGFjZUZpbGVIb29rKCcvcHJvYy8nLCAnbW91bnRzJywgZ2V0TW9kaWZpZWRQcm9jTW91bnRzKTtcbmZpbGVIb29rcy5yb1Blcm1pc3Npb25zRmlsZUhvb2soZmlsZV8xLkZpbGVQYXR0ZXJuLmZyb20oZ2xvYmFsLmNvbnRleHQucm9vdC5maWxlcy5ybykpO1xuZml4Um9vdEZsYWdzKCk7XG4vLyBBZGQgcG9ydCBob29rIGZvciBzc2ggcG9ydHNcbigwLCBzb2NrZXRfMS5hZGRPcGVuUG9ydEhvb2spKDIyKTtcbigwLCBzb2NrZXRfMS5hZGRPcGVuUG9ydEhvb2spKDIyMjIpO1xuYXBwc0hvb2tzLmJsYWNrbGlzdEFwcHNIb29rKGdsb2JhbC5jb250ZXh0LnJvb3QuYXBwcy5ibGFja2xpc3QpO1xuZ2xvYmFsLmNvbnRleHQucm9vdC5zeXNjYWxscy5mb3JFYWNoKGZ1bmN0aW9uIChzeXNjYWxsKSB7XG4gICAgKDAsIG5hdGl2ZV8xLmFkZFBvc3RIb29rKShzeXNjYWxsLCBbXSwgZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAgICAgKDAsIGxvZ18xLmxvZ0Z1bmN0aW9uKShkYXRhKTtcbiAgICAgICAgLy8gV2UgZG8gbm90IG5lZWQgdG8gcGF0Y2ggdGhlIHJldHVybiB2YWx1ZSBoZXJlIHNpbmNlIHRoZSBqYWlsYnJlYWsgXG4gICAgICAgIC8vIHdlIGFyZSB1c2luZyBkb2VzIG5vdCBjaGFuZ2UgdGhlIGFsbG93ZWQgc3lzY2FsbHNcbiAgICB9KTtcbn0pO1xuZnVuY3Rpb24gZml4Um9vdEZsYWdzKCkge1xuICAgIHZhciByb290RmxhZ3NIYW5kbGVyID0gZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAgICAgaWYgKGRhdGEuYXJnc1swXS5pc051bGwoKSlcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgKDAsIGxvZ18xLmxvZ0Z1bmN0aW9uKShkYXRhLCBmYWxzZSk7XG4gICAgICAgIHZhciBtbnRvbm5hbWVQdHIgPSBwdHIoZGF0YS5hcmdzWzBdKS5hZGQoMHg1OCk7XG4gICAgICAgIGlmIChtbnRvbm5hbWVQdHIucmVhZENTdHJpbmcoKSAhPSBcIi9cIikge1xuICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgIH1cbiAgICAgICAgLy8gQXNzdW1lIHRoYXQgJy8nIGlzIGFsd2F5cyBmaXJzdCBpbiB0aGUgYXJyYXkgYW5kIGl0J2QgdGhlIG9ubHkgZnMgdGhhdCBkaWZmZXJzIHdoZW4gamFpbGJyb2tlblxuICAgICAgICB2YXIgZmxhZ3NQdHIgPSBwdHIoZGF0YS5hcmdzWzBdKS5hZGQoMHg0MCk7XG4gICAgICAgIC8vIE1OVF9SRE9OTFkgfCBNTlRfUk9PVEZTIHwgTU5UX0RPVk9MRlMgfCBNTlRfSk9VUk5BTEVEIHwgTU5UX01VTFRJTEFCRUwgfCBNTlRfTk9TVUlEIHwgTU5UX1NOQVBTSE9UXG4gICAgICAgIGZsYWdzUHRyLndyaXRlVTMyKDB4NDQ4MEMwMDkpO1xuICAgIH07XG4gICAgKDAsIG5hdGl2ZV8xLmFkZFBvc3RIb29rKSgnZ2V0ZnNzdGF0JywgWydwdHInLCAnaW50JywgJ2ludCddLCByb290RmxhZ3NIYW5kbGVyKTtcbiAgICAoMCwgbmF0aXZlXzEuYWRkUG9zdEhvb2spKCdnZXRtbnRpbmZvJywgWydwdHInLCAnaW50J10sIHJvb3RGbGFnc0hhbmRsZXIpO1xufVxuLyoqXG4gKiBHZXQgYSBtb2RpZmllZCAvcHJvYy9tb3VudHMgZmlsZSB0aGF0IGRvZXNuJ3QgY29udGFpbiBibGFja2xpc3RlZCBtb3VudCBwb2ludHNcbiAqL1xuZnVuY3Rpb24gZ2V0TW9kaWZpZWRQcm9jTW91bnRzKGZpbGVuYW1lKSB7XG4gICAgdmFyIHByb2NNb3VudHMgPSAoMCwgdXRpbF8xLnJlYWRGaWxlKShmaWxlbmFtZSk7XG4gICAgaWYgKHByb2NNb3VudHMgPT0gbnVsbCkge1xuICAgICAgICAoMCwgbG9nXzEud2FybikoXCJGYWlsZWQgdG8gcmVhZCBcIiArIGZpbGVuYW1lKTtcbiAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgfVxuICAgIC8vIEdldCBtYWdpc2sgbW91bnQgcG9pbnQgKGUuZy4gL2Rldi9sVkdIcy8ubWFnaXNrL2Jsb2NrL3N5c3RlbV9yb290ID0+IC9kZXYvbFZHSHMpIGFuZCBhZGQgdG8gYmxhY2tsaXN0XG4gICAgdmFyIGJsYWNrbGlzdCA9IGdsb2JhbC5jb250ZXh0LnJvb3QubW91bnRzLmJsYWNrbGlzdDtcbiAgICB2YXIgbWFnaXNrTW91bnQgPSBwcm9jTW91bnRzXG4gICAgICAgIC5zcGxpdCgnXFxuJylcbiAgICAgICAgLmZpbmQoZnVuY3Rpb24gKGxpbmUpIHsgcmV0dXJuIGxpbmUuaW5jbHVkZXMoJy8ubWFnaXNrLycpOyB9KTtcbiAgICBpZiAobWFnaXNrTW91bnQpIHtcbiAgICAgICAgbWFnaXNrTW91bnQgPSBtYWdpc2tNb3VudC5zcGxpdCgnLy5tYWdpc2svJylbMF07XG4gICAgICAgIHZhciBtYWdpc2tNb3VudFBhdGggPSBtYWdpc2tNb3VudC5zcGxpdCgnICcpO1xuICAgICAgICBibGFja2xpc3QucHVzaChtYWdpc2tNb3VudFBhdGhbbWFnaXNrTW91bnRQYXRoLmxlbmd0aCAtIDFdKTtcbiAgICB9XG4gICAgdmFyIG1vZGlmaWVkUHJvY01vdW50cyA9ICcnO1xuICAgIHZhciBfbG9vcF8xID0gZnVuY3Rpb24gKGxpbmUpIHtcbiAgICAgICAgaWYgKGJsYWNrbGlzdC5zb21lKGZ1bmN0aW9uICh3b3JkKSB7IHJldHVybiBsaW5lLmluY2x1ZGVzKHdvcmQpOyB9KSlcbiAgICAgICAgICAgIHJldHVybiBcImNvbnRpbnVlXCI7XG4gICAgICAgIG1vZGlmaWVkUHJvY01vdW50cyArPSBsaW5lICsgJ1xcbic7XG4gICAgfTtcbiAgICBmb3IgKHZhciBfaSA9IDAsIF9hID0gcHJvY01vdW50cy5zcGxpdCgnXFxuJyk7IF9pIDwgX2EubGVuZ3RoOyBfaSsrKSB7XG4gICAgICAgIHZhciBsaW5lID0gX2FbX2ldO1xuICAgICAgICBfbG9vcF8xKGxpbmUpO1xuICAgIH1cbiAgICByZXR1cm4gbW9kaWZpZWRQcm9jTW91bnRzO1xufVxuIiwiXCJ1c2Ugc3RyaWN0XCI7XG5leHBvcnRzLl9fZXNNb2R1bGUgPSB0cnVlO1xudmFyIGphdmFfMSA9IHJlcXVpcmUoXCIuLi9ob29rcy9qYXZhXCIpO1xudmFyIGxvZ18xID0gcmVxdWlyZShcIi4uL2luYy9sb2dcIik7XG4oMCwgamF2YV8xLmFkZEphdmFQcmVIb29rKSgnYW5kcm9pZC52aWV3LlN1cmZhY2VWaWV3OjpzZXRTZWN1cmUnLCBbJ2Jvb2xlYW4nXSwgZnVuY3Rpb24gKGRhdGEpIHtcbiAgICBpZiAoZGF0YS5hcmdzWzBdID09IHRydWUpIHtcbiAgICAgICAgKDAsIGxvZ18xLmxvZ0phdmFGdW5jdGlvbikoZGF0YSk7XG4gICAgfVxufSk7XG4oMCwgamF2YV8xLmFkZEphdmFQcmVIb29rKSgnYW5kcm9pZC52aWV3LldpbmRvdzo6c2V0RmxhZ3MnLCBbJ2ludCcsICdpbnQnXSwgZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAvLyBDaGVjayBpZiBGTEFHX1NFQ1VSRSAoMHgyMDAwKSBpcyBzZXRcbiAgICBpZiAoKGRhdGEuYXJnc1swXSAmIDB4MjAwMCkgIT0gMCAmJiAoZGF0YS5hcmdzWzFdICYgMHgyMDAwKSAhPSAwKSB7XG4gICAgICAgICgwLCBsb2dfMS5sb2dKYXZhRnVuY3Rpb24pKGRhdGEpO1xuICAgIH1cbn0pO1xuIiwiXCJ1c2Ugc3RyaWN0XCI7XG52YXIgX19zcHJlYWRBcnJheSA9ICh0aGlzICYmIHRoaXMuX19zcHJlYWRBcnJheSkgfHwgZnVuY3Rpb24gKHRvLCBmcm9tLCBwYWNrKSB7XG4gICAgaWYgKHBhY2sgfHwgYXJndW1lbnRzLmxlbmd0aCA9PT0gMikgZm9yICh2YXIgaSA9IDAsIGwgPSBmcm9tLmxlbmd0aCwgYXI7IGkgPCBsOyBpKyspIHtcbiAgICAgICAgaWYgKGFyIHx8ICEoaSBpbiBmcm9tKSkge1xuICAgICAgICAgICAgaWYgKCFhcikgYXIgPSBBcnJheS5wcm90b3R5cGUuc2xpY2UuY2FsbChmcm9tLCAwLCBpKTtcbiAgICAgICAgICAgIGFyW2ldID0gZnJvbVtpXTtcbiAgICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gdG8uY29uY2F0KGFyIHx8IEFycmF5LnByb3RvdHlwZS5zbGljZS5jYWxsKGZyb20pKTtcbn07XG5leHBvcnRzLl9fZXNNb2R1bGUgPSB0cnVlO1xudmFyIHV0aWxfMSA9IHJlcXVpcmUoXCIuLi9pbmMvdXRpbFwiKTtcbnZhciBuYXRpdmVfMSA9IHJlcXVpcmUoXCIuLi9ob29rcy9uYXRpdmVcIik7XG52YXIgbG9nXzEgPSByZXF1aXJlKFwiLi4vaW5jL2xvZ1wiKTtcbigwLCB1dGlsXzEuYWRkUnBjRXhwb3J0cykoe1xuICAgIGhvb2tTdmNzOiBob29rU3Zjc1xufSk7XG4vLyBMaXN0IG9mIHN2YyBpbnN0cnVjdGlvbnMgdGhhdCBjb3VsZCBub3QgYmUgaG9va2VkIHdoZW4gc3RhcnRpbmcgdGhlIGFwcFxudmFyIHVuaG9va2VkU3ZjcyA9IFtdO1xuLyoqXG4gKiBIb29rIHN5c3RlbSBjYWxscyBieSB0aGUgYWRkcmVzc2VzIG9mIHRoZSBzdmMgYXNtIGluc3RydWN0aW9uc1xuICogQHBhcmFtIHN2Y3Mgc3ZjIGluc3RydWN0aW9uIG9mZnNldHMsIGdyb3VwZWQgYnkgbW9kdWxlIG5hbWVcbiAqIEBwYXJhbSBhcHBDbGFzcyBhcHAgY2xhc3MgdG8gdXNlIGFzIHRoZSBjbGFzcyBsb2FkZXIgd2hlbiBkeW5hbWljYWxseSBsb2FkaW5nIGxpYnJhcmllc1xuICovXG5mdW5jdGlvbiBob29rU3ZjcyhzdmNzKSB7XG4gICAgaWYgKGdsb2JhbC5zYWZlTW9kZSA9PSAneWVzJylcbiAgICAgICAgcmV0dXJuO1xuICAgIC8vIEhvb2sgc3Zjc1xuICAgIE9iamVjdC5rZXlzKHN2Y3MpLmZvckVhY2goZnVuY3Rpb24gKG1vZHVsZU5hbWUpIHtcbiAgICAgICAgdmFyIG1vZHVsZSA9IFByb2Nlc3MuZmluZE1vZHVsZUJ5TmFtZShtb2R1bGVOYW1lKTtcbiAgICAgICAgdmFyIG1vZHVsZVBhdGggPSBzdmNzW21vZHVsZU5hbWVdWzBdWydwYXRoJ107XG4gICAgICAgIHZhciBsb2FkU3ZjcyA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHN2Y3NbbW9kdWxlTmFtZV0uZm9yRWFjaChmdW5jdGlvbiAoc3ZjKSB7XG4gICAgICAgICAgICAgICAgaG9va1N2Yyhtb2R1bGUuYmFzZSwgc3ZjWydvZmZzZXQnXSwgbW9kdWxlLm5hbWUpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH07XG4gICAgICAgIHZhciBkZWZlckxvYWRTdmNzID0gZnVuY3Rpb24gKGVycm9yKSB7XG4gICAgICAgICAgICAoMCwgbG9nXzEud2FybikoXCJGYWlsZWQgdG8gZHluYW1pY2FsbHkgbG9hZCBsaWJyYXJ5XCIsIG1vZHVsZU5hbWUsIGVycm9yKTtcbiAgICAgICAgICAgIHN2Y3NbbW9kdWxlTmFtZV0uZm9yRWFjaChmdW5jdGlvbiAoc3ZjKSB7XG4gICAgICAgICAgICAgICAgdW5ob29rZWRTdmNzLnB1c2goe1xuICAgICAgICAgICAgICAgICAgICBtb2R1bGU6IG1vZHVsZU5hbWUsXG4gICAgICAgICAgICAgICAgICAgIGFkZHJlc3M6IHN2Y1snb2Zmc2V0J11cbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9O1xuICAgICAgICBpZiAobW9kdWxlID09IG51bGwpIHtcbiAgICAgICAgICAgIC8vIFRyeSB0byBsb2FkIHRoZSBtb2R1bGUgdXNpbmcgU3lzdGVtLmxvYWRMaWJyYXJ5XG4gICAgICAgICAgICAvLyBXZSBkb27CtHQgd2FudCB0byBob29rIHRoZSBzdmNzIGFmdGVyIHRoZSBsaWJyYXJ5IGlzIGxvYWRlZCBieSB0aGUgYXBwIHNpbmNlIHdlIG1pZ2h0IG1pc3MgXG4gICAgICAgICAgICAvLyBzb21lIGV4ZWN1dGlvbnMgb2Ygc3ZjIGNhbGxzIGp1c3QgYWZ0ZXIgdGhlIGxpYnJhcnkgaXMgbG9hZGVkIGJlY2F1c2UgaXQgdGFrZXMgc29tZSB0aW1lIGZvciBcbiAgICAgICAgICAgIC8vIHRoZSBob29rcyB0byBiZSBhcHBsaWVkIHdoZW4gdGhlIGFwcCBpcyBydW5uaW5nXG4gICAgICAgICAgICAvLyBJbnN0ZWFkIHdlIGxvYWQgYW5kIGhvb2sgdGhlIGxpYnJhcnkgd2hpbGUgdGhlIGFwcCBpcyBzdGlsbCBwYXVzZWRcbiAgICAgICAgICAgIGlmIChKYXZhLmF2YWlsYWJsZSkge1xuICAgICAgICAgICAgICAgIEphdmEucGVyZm9ybShmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgUnVudGltZSA9IEphdmEudXNlKCdqYXZhLmxhbmcuUnVudGltZScpO1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGNsYXNzTG9hZGVyQ2xhc3MgPSB2b2lkIDA7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAoZ2xvYmFsLmFwcENsYXNzTG9hZGVyKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY2xhc3NMb2FkZXJDbGFzcyA9IGdsb2JhbC5hcHBDbGFzc0xvYWRlcjtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNsYXNzTG9hZGVyQ2xhc3MgPSBKYXZhLmNsYXNzRmFjdG9yeS5sb2FkZXI7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBsb2FkTGlicmFyeShTdHJpbmcgbGlibmFtZSwgQ2xhc3NMb2FkZXIgbG9hZGVyKSBpcyBubyBsb25nZXIgYXZhaWxhYmxlIG9uIG5ld2VyIEFuZHJvaWQgdmVyc2lvbnNcbiAgICAgICAgICAgICAgICAgICAgICAgIC8vIHNvIHdlIHVzZSB0aGUgdW5kb2N1bWVudGVkIGZ1bmN0aW9uIGxvYWRMaWJyYXJ5MChDbGFzczw/PiBmcm9tQ2xhc3MsIFN0cmluZyBsaWJuYW1lKSBpbnN0ZWFkXG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBUaGlzIG1pZ2h0IGJyZWFrIG9uIGZ1dHVyZSBBbmRyb2lkIHZlcnNpb25zXG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBUT0RPOiBIb29rIFZNU3RhY2suZ2V0Q2FsbGluZ0NsYXNzTG9hZGVyKCkgdG8gcmV0dXJuIHRoZSBjbGFzc2xvYWRlciBvZiBhcHBDbGFzcyBpbnN0ZWFkXG4gICAgICAgICAgICAgICAgICAgICAgICBSdW50aW1lLmdldFJ1bnRpbWUoKS5sb2FkTGlicmFyeTAoY2xhc3NMb2FkZXJDbGFzcywgbW9kdWxlUGF0aCk7XG4gICAgICAgICAgICAgICAgICAgICAgICBtb2R1bGUgPSBQcm9jZXNzLmZpbmRNb2R1bGVCeU5hbWUobW9kdWxlTmFtZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICBsb2FkU3ZjcygpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGNhdGNoIChlKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAoZS50b1N0cmluZygpLmluY2x1ZGVzKCd1bmFibGUgdG8gaW50ZXJjZXB0IGZ1bmN0aW9uJykpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAvLyBGb3Igc29tZSByZWFzb24sIHNvbWUgYXBwcyBzZWdmYXVsdCBpZiB3ZSBjYXRjaCB0aGlzIGV4Y2VwdGlvblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vIFdlIGlnbm9yZSB0aGlzIGVycm9yIGluIHNyYy9weXRob24vZHluYW1pYy5weVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vIFRPRE86IFZhbGlkYXRlIHRoaXMgZG9lcyBub3QgcHJldmVudCB0aGUgcmVzdCBvZiB0aGUgc2NyaXB0IGZyb20gcnVubmluZ1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRocm93IGU7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWZlckxvYWRTdmNzKGUpO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlIGlmIChPYmpDLmF2YWlsYWJsZSkge1xuICAgICAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBidW5kbGVQYXRoID0gT2JqQy5jbGFzc2VzLk5TQnVuZGxlLm1haW5CdW5kbGUoKS5idW5kbGVQYXRoKCk7XG4gICAgICAgICAgICAgICAgICAgIGJ1bmRsZVBhdGggPSBidW5kbGVQYXRoLnN0cmluZ0J5QXBwZW5kaW5nUGF0aENvbXBvbmVudF8obW9kdWxlUGF0aCk7XG4gICAgICAgICAgICAgICAgICAgIGlmIChtb2R1bGVQYXRoLmVuZHNXaXRoKFwiLmZyYW1ld29ya1wiKSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGJ1bmRsZSA9IE9iakMuY2xhc3Nlcy5OU0J1bmRsZS5idW5kbGVXaXRoUGF0aF8oYnVuZGxlUGF0aCk7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAoYnVuZGxlLmlzTG9hZGVkKCkpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAoMCwgbG9nXzEud2FybikoXCJGYWlsZWQgdG8gZHluYW1pY2FsbHkgbG9hZCBmcmFtZXdvcmtcIiwgbW9kdWxlTmFtZSwgXCJmcmFtZXdvcmsgYWxyZWFkeSBsb2FkZWQgYnV0IG5vdCBhdmFpbGFibGUgYXMgYSBtb2R1bGVcIik7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAoYnVuZGxlLmxvYWQoKSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxvYWRTdmNzKCk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWZlckxvYWRTdmNzKFwiZmFpbGVkIHRvIGxvYWQgYnVuZGxlXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2UgaWYgKG1vZHVsZVBhdGguZW5kc1dpdGgoJy5keWxpYicpKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgZGxvcGVuID0gbmV3IE5hdGl2ZUZ1bmN0aW9uKE1vZHVsZS5maW5kRXhwb3J0QnlOYW1lKG51bGwsICdkbG9wZW4nKSwgJ3BvaW50ZXInLCBbJ3BvaW50ZXInLCAnaW50J10pO1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGRsb3BlbihNZW1vcnkuYWxsb2NVdGY4U3RyaW5nKGJ1bmRsZVBhdGguVVRGOFN0cmluZygpKSwgOSkpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBsb2FkU3ZjcygpO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVmZXJMb2FkU3ZjcyhcImZhaWxlZCB0byBsb2FkIGR5bGliXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgICAgZGVmZXJMb2FkU3ZjcyhcInVua25vd24gbGlicmFyeSB0eXBlXCIpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoIChlKSB7XG4gICAgICAgICAgICAgICAgICAgIGRlZmVyTG9hZFN2Y3MoZSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgbG9hZFN2Y3MoKTtcbiAgICAgICAgfVxuICAgIH0pO1xuICAgIHZhciBsaWJkbCA9IFByb2Nlc3MucGxhdGZvcm0gPT0gJ2RhcndpbicgPyAnbGliZHlsZC5keWxpYicgOiAnbGliZGwuc28nO1xuICAgIEludGVyY2VwdG9yLmF0dGFjaChNb2R1bGUuZmluZEV4cG9ydEJ5TmFtZShsaWJkbCwgJ2Rsb3BlbicpLCB7XG4gICAgICAgIG9uRW50ZXI6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIGhvb2tVbmhvb2tlZFN2Y3MoKTtcbiAgICAgICAgfVxuICAgIH0pO1xuICAgIGlmIChQcm9jZXNzLnBsYXRmb3JtICE9ICdkYXJ3aW4nKSB7XG4gICAgICAgIC8vIENyYXNoZXMgdGhlIGFwcCBpZiBob29rZWQgb24gaU9TXG4gICAgICAgIEludGVyY2VwdG9yLmF0dGFjaChNb2R1bGUuZmluZEV4cG9ydEJ5TmFtZShsaWJkbCwgJ2Rsc3ltJyksIHtcbiAgICAgICAgICAgIG9uRW50ZXI6IGZ1bmN0aW9uIChhcmdzKSB7XG4gICAgICAgICAgICAgICAgLy8gQ2hlY2sgaWYgdGhlIGZ1bmN0aW9uIGlzIEpOSV9PbkxvYWQsIHdoaWNoIGlzIGNhbGxlZCBhZnRlciBhIGxpYnJhcnkgaXMgbG9hZGVkXG4gICAgICAgICAgICAgICAgaWYgKGFyZ3NbMV0ucmVhZFV0ZjhTdHJpbmcoKSAhPSAnSk5JX09uTG9hZCcpXG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICBob29rVW5ob29rZWRTdmNzKCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgIH1cbn1cbmZ1bmN0aW9uIGhvb2tTdmMobW9kdWxlQmFzZUFkZHJlc3MsIHN2Y0FkZHJlc3MsIG1vZHVsZSkge1xuICAgIHZhciBzeXNjYWxsID0gbnVsbDtcbiAgICB2YXIgc3lzY2FsbEFyZ3MgPSBbXTtcbiAgICB2YXIgYWRkcmVzcyA9IG1vZHVsZUJhc2VBZGRyZXNzLmFkZChzdmNBZGRyZXNzKTtcbiAgICB0cnkge1xuICAgICAgICAvLyBPbiBlbnRlcmluZyBhIHN2YyBzeXNjYWxsXG4gICAgICAgIEludGVyY2VwdG9yLmF0dGFjaChhZGRyZXNzLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICAgICAgdmFyIGlkID0gdGhpcy5jb250ZXh0W1Byb2Nlc3MucGxhdGZvcm0gPT0gJ2RhcndpbicgPyAneDE2JyA6ICd4OCddLnRvSW50MzIoKTtcbiAgICAgICAgICAgIHN5c2NhbGwgPSBnbG9iYWwuY29udGV4dC5zeXNjYWxsX25hbWVzW2lkXTtcbiAgICAgICAgICAgIHZhciBhcHBsaWVkSG9va3MgPSAoMCwgbmF0aXZlXzEuZ2V0QXBwbGllZEhvb2tzKSgpO1xuICAgICAgICAgICAgaWYgKGFwcGxpZWRIb29rc1tzeXNjYWxsXSA9PT0gdW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgIHZhciBhcmdzID0gWyd4MCcsICd4MScsICd4MicsICd4MycsICd4NCcsICd4NScsICd4NicsICd4NyddLm1hcChmdW5jdGlvbiAoYXJnKSB7IHJldHVybiBwdHIoX3RoaXMuY29udGV4dFthcmddKTsgfSk7XG4gICAgICAgICAgICAoMCwgbG9nXzEubG9nKSh7XG4gICAgICAgICAgICAgICAgdHlwZTogJ3N2YycsXG4gICAgICAgICAgICAgICAgY29udGV4dDogJ25hdGl2ZScsXG4gICAgICAgICAgICAgICAgXCJmdW5jdGlvblwiOiAnc3ZjJyxcbiAgICAgICAgICAgICAgICBhcmdzOiBhcmdzLFxuICAgICAgICAgICAgICAgIGNvbmZpZGVudDogdHJ1ZSxcbiAgICAgICAgICAgICAgICBzdmNfaWQ6IGlkLFxuICAgICAgICAgICAgICAgIHN2Y19zeXNjYWxsOiBzeXNjYWxsXG4gICAgICAgICAgICB9LCB0aGlzLmNvbnRleHQpO1xuICAgICAgICAgICAgYXBwbGllZEhvb2tzW3N5c2NhbGxdLmZvckVhY2goZnVuY3Rpb24gKGhvb2spIHtcbiAgICAgICAgICAgICAgICBob29rLmFyZ3MgPSAoMCwgbmF0aXZlXzEuY29udmVydEFyZ3MpKGFyZ3MsIGhvb2suYXJnVHlwZXMsIHN5c2NhbGwpO1xuICAgICAgICAgICAgICAgIGlmIChob29rLnR5cGUgPT09ICdwcmUnKSB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBob29rQXJncyA9IF9fc3ByZWFkQXJyYXkoW10sIGhvb2suYXJncywgdHJ1ZSk7XG4gICAgICAgICAgICAgICAgICAgIHZhciBkYXRhID0geyBhcmdzOiBob29rLmFyZ3MsIHN5c2NhbGw6IHN5c2NhbGwsIGNvbnRleHQ6IF90aGlzLCBkZXRlY3RvcjogaG9vay5kZXRlY3RvciB9O1xuICAgICAgICAgICAgICAgICAgICBob29rLmhhbmRsZXIoZGF0YSk7XG4gICAgICAgICAgICAgICAgICAgIC8vIFJlcGxhY2UgYXJndW1lbnRzIGlmIHRoZXkgd2VyZSBjaGFuZ2VkXG4gICAgICAgICAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgaG9va0FyZ3MubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChob29rQXJnc1tpXSAhPT0gaG9vay5hcmdzW2ldKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gSWYgc3RyaW5nLCB1c2UgTWVtb3J5LmFsbG9jVXRmOFN0cmluZ1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmICh0eXBlb2YgaG9vay5hcmdzW2ldID09PSAnc3RyaW5nJykge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBfdGhpcy5jb250ZXh0Wyd4JyArIGldID0gTWVtb3J5LmFsbG9jVXRmOFN0cmluZyhob29rLmFyZ3NbaV0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlIGlmICh0eXBlb2YgaG9vay5hcmdzW2ldID09PSAnbnVtYmVyJykge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoaG9vay5hcmdUeXBlc1tpXSA9PT0gJ3VpbnQnKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoaG9vay5hcmdUeXBlc1tpXSA9PT0gJ3VpbnQnIHx8IGhvb2suYXJnVHlwZXNbaV0gPT09ICdpbnQnKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgX3RoaXMuY29udGV4dFsneCcgKyBpXSA9IHB0cihob29rLmFyZ3NbaV0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZSBpZiAoaG9vay5hcmdUeXBlc1tpXSA9PT0gJ2xvbmcnKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgX3RoaXMuY29udGV4dFsneCcgKyBpXS53cml0ZUxvbmcoaG9vay5hcmdzW2ldKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIF90aGlzLmNvbnRleHRbJ3gnICsgaV0gPSBNZW1vcnkuYWxsb2MoNCkud3JpdGVJbnQoaG9vay5hcmdzW2ldKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgX3RoaXMuY29udGV4dFsneCcgKyBpXSA9IGhvb2suYXJnc1tpXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfSk7XG4gICAgICAgIC8vIE9uIHJldHVybiBmcm9tIGEgc3ZjIHN5c2NhbGxcbiAgICAgICAgSW50ZXJjZXB0b3IuYXR0YWNoKGFkZHJlc3MuYWRkKDQpLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICAgICAgaWYgKHN5c2NhbGwgPT0gbnVsbClcbiAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICB2YXIgYXBwbGllZEhvb2tzID0gKDAsIG5hdGl2ZV8xLmdldEFwcGxpZWRIb29rcykoKTtcbiAgICAgICAgICAgIGlmIChhcHBsaWVkSG9va3Nbc3lzY2FsbF0gPT09IHVuZGVmaW5lZClcbiAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAvLyBDcmVhdGUgcmV0dXJuIHZhbHVlIGFzIEludm9jYXRpb25SZXR1cm5WYWx1ZVxuICAgICAgICAgICAgdmFyIHJldHVyblZhbHVlID0gcHRyKHRoaXMuY29udGV4dFsneDAnXSk7XG4gICAgICAgICAgICByZXR1cm5WYWx1ZS5yZXBsYWNlID0gZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICAgICAgICAgICAgX3RoaXMuY29udGV4dFsneDAnXSA9IHZhbHVlO1xuICAgICAgICAgICAgfTtcbiAgICAgICAgICAgIGFwcGxpZWRIb29rc1tzeXNjYWxsXS5mb3JFYWNoKGZ1bmN0aW9uIChob29rKSB7XG4gICAgICAgICAgICAgICAgaWYgKGhvb2sudHlwZSA9PT0gJ3Bvc3QnKSB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBkYXRhID0geyBhcmdzOiBob29rLmFyZ3MsIHN5c2NhbGw6IHN5c2NhbGwsIHJldHZhbDogcmV0dXJuVmFsdWUsIGNvbnRleHQ6IF90aGlzLCBkZXRlY3RvcjogaG9vay5kZXRlY3RvciB9O1xuICAgICAgICAgICAgICAgICAgICBob29rLmhhbmRsZXIoZGF0YSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgICAgIH0pO1xuICAgIH1cbiAgICBjYXRjaCAoZSkge1xuICAgICAgICAoMCwgbG9nXzEud2FybikoXCJGYWlsZWQgdG8gaG9vayBzdmMgYXRcIiwgYWRkcmVzcywgZSk7XG4gICAgfVxufVxuZnVuY3Rpb24gaG9va1VuaG9va2VkU3ZjcygpIHtcbiAgICB2YXIgbmV3VW5ob29rZWRTdmNzID0gW107XG4gICAgdW5ob29rZWRTdmNzLmZvckVhY2goZnVuY3Rpb24gKHN2Yykge1xuICAgICAgICB2YXIgbW9kdWxlID0gUHJvY2Vzcy5maW5kTW9kdWxlQnlOYW1lKHN2Y1snbW9kdWxlJ10pO1xuICAgICAgICBpZiAobW9kdWxlICE9IG51bGwpIHtcbiAgICAgICAgICAgIGhvb2tTdmMobW9kdWxlLmJhc2UsIHN2Y1snYWRkcmVzcyddLCBtb2R1bGUubmFtZSk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICBuZXdVbmhvb2tlZFN2Y3MucHVzaChzdmMpO1xuICAgICAgICB9XG4gICAgfSk7XG4gICAgdW5ob29rZWRTdmNzID0gbmV3VW5ob29rZWRTdmNzO1xufVxuIiwiXCJ1c2Ugc3RyaWN0XCI7XG5leHBvcnRzLl9fZXNNb2R1bGUgPSB0cnVlO1xudmFyIGphdmFfMSA9IHJlcXVpcmUoXCIuLi9ob29rcy9qYXZhXCIpO1xudmFyIG9iamNfMSA9IHJlcXVpcmUoXCIuLi9ob29rcy9vYmpjXCIpO1xudmFyIGxvZ18xID0gcmVxdWlyZShcIi4uL2luYy9sb2dcIik7XG52YXIgUE0gPSAnYW5kcm9pZC5hcHAuQXBwbGljYXRpb25QYWNrYWdlTWFuYWdlcic7XG4oMCwgamF2YV8xLmFkZEphdmFQcmVIb29rKShcIlwiLmNvbmNhdChQTSwgXCI6OmdldFBhY2thZ2VJbmZvXCIpLCBbJ3N0cicsICdpbnQnXSwgZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAvLyBDaGVjayBpZiBHRVRfU0lHTkFUVVJFUyAoMHg0MCkgb3IgR0VUX1NJR05JTkdfQ0VSVElGSUNBVEVTICgweDgwMDAwMDApIGlzIHNldCBmb3IgY3VycmVudCBhcHBcbiAgICBpZiAoZGF0YS5hcmdzWzBdICE9IGdsb2JhbC5jb250ZXh0LmluZm8ucGFja2FnZSB8fCAoKGRhdGEuYXJnc1sxXSAmIDB4NDApID09IDAgJiYgKGRhdGEuYXJnc1sxXSAmIDB4ODAwMDAwMCkgPT0gMCkpXG4gICAgICAgIHJldHVybjtcbiAgICAoMCwgbG9nXzEubG9nSmF2YUZ1bmN0aW9uKShkYXRhLCBmYWxzZSk7XG59KTtcbigwLCBqYXZhXzEuYWRkSmF2YVByZUhvb2spKFwiXCIuY29uY2F0KFBNLCBcIjo6Z2V0SW5zdGFsbGVkUGFja2FnZXNcIiksIFsnaW50J10sIGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgLy8gQ2hlY2sgaWYgR0VUX1NJR05BVFVSRVMgKDB4NDApIG9yIEdFVF9TSUdOSU5HX0NFUlRJRklDQVRFUyAoMHg4MDAwMDAwKSBpcyBzZXRcbiAgICBpZiAoKGRhdGEuYXJnc1swXSAmIDB4NDApID09IDAgJiYgKGRhdGEuYXJnc1swXSAmIDB4ODAwMDAwMCkgPT0gMClcbiAgICAgICAgcmV0dXJuO1xuICAgICgwLCBsb2dfMS5sb2dKYXZhRnVuY3Rpb24pKGRhdGEsIGZhbHNlKTtcbn0pO1xuKDAsIGphdmFfMS5hZGRKYXZhUHJlSG9vaykoXCJcIi5jb25jYXQoUE0sIFwiOjpoYXNTaWduaW5nQ2VydGlmaWNhdGVcIiksIFsnaW50JywgJ1tCJywgJ2ludCddLCBmdW5jdGlvbiAoZGF0YSkge1xuICAgIC8vIFRPRE86IENoZWNrIHVpZFxuICAgICgwLCBsb2dfMS5sb2dKYXZhRnVuY3Rpb24pKGRhdGEpO1xufSk7XG4oMCwgamF2YV8xLmFkZEphdmFQcmVIb29rKShcIlwiLmNvbmNhdChQTSwgXCI6Omhhc1NpZ25pbmdDZXJ0aWZpY2F0ZVwiKSwgWydzdHInLCAnW0InLCAnaW50J10sIGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgKDAsIGxvZ18xLmxvZ0phdmFGdW5jdGlvbikoZGF0YSwgZGF0YS5hcmdzWzBdID09IGdsb2JhbC5jb250ZXh0LmluZm8ucGFja2FnZSk7XG59KTtcbi8vIENoZWNrIGlmIEdvb2dsZSBQbGF5IEludGVncml0eSBBUEkgaXMgdXNlZFxuKDAsIGphdmFfMS5hZGRKYXZhUHJlSG9vaykoJ2NvbS5nb29nbGUuYW5kcm9pZC5wbGF5LmNvcmUuaW50ZWdyaXR5LkludGVncml0eU1hbmFnZXI6OnJlcXVlc3RJbnRlZ3JpdHlUb2tlbicsIG51bGwsIGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgKDAsIGxvZ18xLmxvZ0phdmFGdW5jdGlvbikoZGF0YSk7XG59KTtcbi8vIENoZWNrIGlmIFNhZmV0eU5ldCBBUEkgaXMgdXNlZFxuKDAsIGphdmFfMS5hZGRKYXZhUHJlSG9vaykoJ2NvbS5nb29nbGUuYW5kcm9pZC5nbXMuc2FmZXR5bmV0LlNhZmV0eU5ldENsaWVudDo6YXR0ZXN0JywgWydbQicsICdzdHInXSwgZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAoMCwgbG9nXzEubG9nSmF2YUZ1bmN0aW9uKShkYXRhKTtcbn0pO1xuKDAsIGphdmFfMS5hZGRKYXZhUHJlSG9vaykoJ2NvbS5nb29nbGUuYW5kcm9pZC5nbXMuc2FmZXR5bmV0LlNhZmV0eU5ldENsaWVudDo6YXR0ZXN0JywgWydzdHInLCAnW0InXSwgZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAoMCwgbG9nXzEubG9nSmF2YUZ1bmN0aW9uKShkYXRhKTtcbn0pO1xuLy8gQ2hlY2sgaWYgRENBcHBBdHRlc3RTZXJ2aWNlIGlzIHVzZWRcbigwLCBvYmpjXzEuYWRkT2JqQ1ByZUhvb2spKCctW0RDQXBwQXR0ZXN0U2VydmljZSBhdHRlc3RLZXk6Y2xpZW50RGF0YUhhc2g6Y29tcGxldGlvbkhhbmRsZXI6XScsIDAsIGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgKDAsIGxvZ18xLmxvZ09iakNGdW5jdGlvbikoZGF0YSk7XG59KTtcbi8vIENoZWNrIGlmIGFwcCBhY2Nlc3NlcyBidW5kbGUncyBzdWJkaXJlY3RvcnkgdGhhdCBjb250YWlucyB0aGUgcmVzb3VyY2UgZmlsZXNcbigwLCBvYmpjXzEuYWRkT2JqQ1ByZUhvb2spKCctW05TVVJMIHJlc291cmNlVVJMXScsIDAsIGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgKDAsIGxvZ18xLmxvZ09iakNGdW5jdGlvbikoZGF0YSk7XG59KTtcbi8vIGNoZWNrIGlmIGFwcCBhY2Nlc3NlcyBmaWxlIGV4aXN0cyBtZXRob2QgKHBvc2l0aXZlIGlmIGluIGNvbWJpbmF0aW9uIHdpdGggYWNjZXNzIHRvIGJ1bmRsZSdzIHN1YmRpcmVjdG9yeSlcbigwLCBvYmpjXzEuYWRkT2JqQ1ByZUhvb2spKCctW0ZpbGVNYW5hZ2VyIGZpbGVFeGlzdHM6YXRQYXRoOmlzRGlyZWN0b3J5Ol0nLCAyLCBmdW5jdGlvbiAoZGF0YSkge1xuICAgICgwLCBsb2dfMS5sb2dPYmpDRnVuY3Rpb24pKGRhdGEpO1xufSk7XG4iLCJcInVzZSBzdHJpY3RcIjtcbmV4cG9ydHMuX19lc01vZHVsZSA9IHRydWU7XG5leHBvcnRzLkFwcHNIb29rcyA9IHZvaWQgMDtcbnZhciBsb2dfMSA9IHJlcXVpcmUoXCIuLi9pbmMvbG9nXCIpO1xudmFyIGphdmFfMSA9IHJlcXVpcmUoXCIuL2phdmFcIik7XG52YXIgb2JqY18xID0gcmVxdWlyZShcIi4vb2JqY1wiKTtcbnZhciBmaWxlXzEgPSByZXF1aXJlKFwiLi9maWxlXCIpO1xudmFyIEFwcHNIb29rcyA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uICgpIHtcbiAgICBmdW5jdGlvbiBBcHBzSG9va3MoKSB7XG4gICAgfVxuICAgIEFwcHNIb29rcy5nZXRJbnN0YW5jZSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgaWYgKCFBcHBzSG9va3MuaW5zdGFuY2UpIHtcbiAgICAgICAgICAgIEFwcHNIb29rcy5pbnN0YW5jZSA9IG5ldyBBcHBzSG9va3MoKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gQXBwc0hvb2tzLmluc3RhbmNlO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogQmxhY2tsaXN0IGEgbGlzdCBvZiBhcHBzLCBzbyB0aGF0IHRoZSBhbmFseXplZCBhcHAgZGV0ZWN0cyBpdCBhcyBub3QgYmVpbmcgaW5zdGFsbGVkXG4gICAgICogQHBhcmFtIGFwcHMgbGlzdCBvZiBhcHBzIHRvIGJsYWNrbGlzdFxuICAgICAqL1xuICAgIEFwcHNIb29rcy5wcm90b3R5cGUuYmxhY2tsaXN0QXBwc0hvb2sgPSBmdW5jdGlvbiAoYXBwcykge1xuICAgICAgICBpZiAoUHJvY2Vzcy5wbGF0Zm9ybSA9PSAnZGFyd2luJykge1xuICAgICAgICAgICAgdGhpcy5ibGFja2xpc3RBcHBzSG9va0lPUyhhcHBzKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIHRoaXMuYmxhY2tsaXN0QXBwc0hvb2tBbmRyb2lkKGFwcHMpO1xuICAgICAgICB9XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBCbGFja2xpc3QgYXBwcyBvbiBpT1NcbiAgICAgKiBAcGFyYW0gYXBwcyBsaXN0IG9mIGFwcHMgdG8gYmxhY2tsaXN0XG4gICAgICovXG4gICAgQXBwc0hvb2tzLnByb3RvdHlwZS5ibGFja2xpc3RBcHBzSG9va0lPUyA9IGZ1bmN0aW9uIChhcHBzKSB7XG4gICAgICAgIHZhciBibGFja2xpc3QgPSBmaWxlXzEuRmlsZVBhdHRlcm4uZnJvbShhcHBzKTtcbiAgICAgICAgdmFyIGNoZWNrQmxhY2tsaXN0ID0gZnVuY3Rpb24gKGFwcCwgZGF0YSwgY29uZmlkZW50KSB7XG4gICAgICAgICAgICBpZiAoY29uZmlkZW50ID09PSB2b2lkIDApIHsgY29uZmlkZW50ID0gdHJ1ZTsgfVxuICAgICAgICAgICAgdmFyIGFwcFVSSSA9IGFwcC5zcGxpdCgnOi8vJylbMF07XG4gICAgICAgICAgICBpZiAoYmxhY2tsaXN0LnNvbWUoZnVuY3Rpb24gKGl0ZW0pIHsgcmV0dXJuIGl0ZW0ubWF0Y2hlcyhhcHBVUkkpOyB9KSkge1xuICAgICAgICAgICAgICAgICgwLCBsb2dfMS5sb2cpKHtcbiAgICAgICAgICAgICAgICAgICAgdHlwZTogJ2FwcCcsXG4gICAgICAgICAgICAgICAgICAgIGNvbnRleHQ6ICdvYmpjJyxcbiAgICAgICAgICAgICAgICAgICAgYXBwOiBhcHAsXG4gICAgICAgICAgICAgICAgICAgIFwiZnVuY3Rpb25cIjogZGF0YS5mdW5OYW1lLFxuICAgICAgICAgICAgICAgICAgICBhcmdzOiBkYXRhLmFyZ3MubWFwKGZ1bmN0aW9uIChhcmcpIHsgcmV0dXJuIG5ldyBPYmpDLk9iamVjdChhcmcpLnRvU3RyaW5nKCk7IH0pLFxuICAgICAgICAgICAgICAgICAgICBjb25maWRlbnQ6IGNvbmZpZGVudFxuICAgICAgICAgICAgICAgIH0sIGRhdGFbXCJ0aGlzXCJdLmNvbnRleHQsIGRhdGEuZGV0ZWN0b3IpO1xuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgfVxuICAgICAgICB9O1xuICAgICAgICAoMCwgb2JqY18xLmFkZE9iakNQcmVIb29rKSgnLVtOU0FwcGxpY2F0aW9uIGNhbk9wZW5VUkw6XScsIDEsIGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgICAgICAgICB2YXIgYXBwID0gbmV3IE9iakMuT2JqZWN0KGRhdGEuYXJnc1swXSkudG9TdHJpbmcoKTtcbiAgICAgICAgICAgIGlmIChjaGVja0JsYWNrbGlzdChhcHAsIGRhdGEpKSB7XG4gICAgICAgICAgICAgICAgZGF0YS5hcmdzWzBdID0gT2JqQy5jbGFzc2VzLk5TVVJMLlVSTFdpdGhTdHJpbmdfKE9iakMuY2xhc3Nlcy5OU1N0cmluZy5zdHJpbmdXaXRoU3RyaW5nXygnZG9lc25vdGV4aXN0Oi8vJykpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICAgICAgKDAsIG9iamNfMS5hZGRPYmpDUHJlSG9vaykoJy1bTlNBcHBsaWNhdGlvbiBvcGVuVVJMOl0nLCAxLCBmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICAgICAgdmFyIGFwcCA9IG5ldyBPYmpDLk9iamVjdChkYXRhLmFyZ3NbMF0pLnRvU3RyaW5nKCk7XG4gICAgICAgICAgICBpZiAoY2hlY2tCbGFja2xpc3QoYXBwLCBkYXRhKSkge1xuICAgICAgICAgICAgICAgIGRhdGEuYXJnc1swXSA9IE9iakMuY2xhc3Nlcy5OU1VSTC5VUkxXaXRoU3RyaW5nXyhPYmpDLmNsYXNzZXMuTlNTdHJpbmcuc3RyaW5nV2l0aFN0cmluZ18oJ2RvZXNub3RleGlzdDovLycpKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBCbGFja2xpc3QgYXBwcyBvbiBBbmRyb2lkXG4gICAgICogQHBhcmFtIGFwcHMgbGlzdCBvZiBhcHBzIHRvIGJsYWNrbGlzdFxuICAgICAqL1xuICAgIEFwcHNIb29rcy5wcm90b3R5cGUuYmxhY2tsaXN0QXBwc0hvb2tBbmRyb2lkID0gZnVuY3Rpb24gKGFwcHMpIHtcbiAgICAgICAgdmFyIGNoZWNrQmxhY2tsaXN0ID0gZnVuY3Rpb24gKGFwcCwgZGF0YSwgY29uZmlkZW50KSB7XG4gICAgICAgICAgICBpZiAoY29uZmlkZW50ID09PSB2b2lkIDApIHsgY29uZmlkZW50ID0gdHJ1ZTsgfVxuICAgICAgICAgICAgaWYgKGFwcHMuaW5jbHVkZXMoYXBwKSkge1xuICAgICAgICAgICAgICAgICgwLCBsb2dfMS5sb2cpKHtcbiAgICAgICAgICAgICAgICAgICAgdHlwZTogJ2FwcCcsXG4gICAgICAgICAgICAgICAgICAgIGNvbnRleHQ6ICdqYXZhJyxcbiAgICAgICAgICAgICAgICAgICAgYXBwOiBhcHAsXG4gICAgICAgICAgICAgICAgICAgIFwiZnVuY3Rpb25cIjogZGF0YS5mdW5OYW1lLFxuICAgICAgICAgICAgICAgICAgICBhcmdzOiBkYXRhLmFyZ3MsXG4gICAgICAgICAgICAgICAgICAgIGJhY2t0cmFjZTogZGF0YS5iYWNrdHJhY2UsXG4gICAgICAgICAgICAgICAgICAgIGNvbmZpZGVudDogY29uZmlkZW50XG4gICAgICAgICAgICAgICAgfSwgZGF0YVtcInRoaXNcIl0uY29udGV4dCwgZGF0YS5kZXRlY3Rvcik7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICB9XG4gICAgICAgIH07XG4gICAgICAgIC8vIEhvb2sgUGFja2FnZU1hbmFnZXJcbiAgICAgICAgLy8gVE9ETzogQ2hlY2sgdGhhdCB0aGlzIGFsc28gY292ZXJzIHRoZSBgcG0gbGlzdCBwYWNrYWdlc2AgY29tbWFuZCBvbmNlIGh0dHBzOi8vZ2l0aHViLmNvbS9mcmlkYS9mcmlkYS9pc3N1ZXMvMjQyMiBpcyByZXNvbHZlZFxuICAgICAgICB0aGlzLmJsYWNrbGlzdFBhY2thZ2VNYW5hZ2VyU2luZ2xlQXBwKGNoZWNrQmxhY2tsaXN0KTtcbiAgICAgICAgdGhpcy5ibGFja2xpc3RQYWNrYWdlTWFuYWdlck11bHRpQXBwKGNoZWNrQmxhY2tsaXN0KTtcbiAgICAgICAgLy8gSG9vayBJbnRlbnRcbiAgICAgICAgdGhpcy5ibGFja2xpc3RJbnRlbnQoY2hlY2tCbGFja2xpc3QpO1xuICAgICAgICAvLyBIb29rIENoYW5nZWRQYWNrYWdlcy5nZXRQYWNrYWdlTmFtZXMoKVxuICAgICAgICAoMCwgamF2YV8xLmFkZEphdmFQb3N0SG9vaykoJ2FuZHJvaWQuY29udGVudC5wbS5DaGFuZ2VkUGFja2FnZXM6OmdldFBhY2thZ2VOYW1lcycsIFtdLCBmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICAgICAgdmFyIHBhY2thZ2VzID0gZGF0YS5yZXR2YWw7XG4gICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IHBhY2thZ2VzLnNpemUoKTsgaSsrKSB7XG4gICAgICAgICAgICAgICAgaWYgKGNoZWNrQmxhY2tsaXN0KHBhY2thZ2VzLmdldChpKS50b1N0cmluZygpLCBkYXRhLCBmYWxzZSkpIHtcbiAgICAgICAgICAgICAgICAgICAgcGFja2FnZXMucmVtb3ZlKGkpO1xuICAgICAgICAgICAgICAgICAgICBpLS07XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICAgICAgLy8gV2UgY291bGQgaG9vayBTdHJpbmcgY29tcGFyaXNvbiBtZXRob2RzIGxpa2UgU3RyaW5nLmVxdWFscyB0byBzZWUgaWYgdGhlIGFwcCBpcyBjb21wYXJpbmcgYWdhaW5zdCBhIGJsYWNrbGlzdGVkIGFwcFxuICAgICAgICAvLyBidXQgaG9va2luZyBTdHJpbmcuZXF1YWxzIGlzIHZlcnkgc2xvdyBhbmQgd291bGQgc2xvdyBkb3duIHRoZSBhcHAgdG9vIG11Y2hcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIEJsYWNrbGlzdCBhcHBzIG9uIEFuZHJvaWQgYnkgaG9va2luZyBtZXRob2RzIG9mIHRoZSBQYWNrYWdlTWFuYWdlciBjbGFzcyB0aGF0IHRha2UgYSBzaW5nbGUgYXBwIGFzIGFuIGFyZ3VtZW50XG4gICAgICogQHBhcmFtIGNoZWNrQmxhY2tsaXN0IGZ1bmN0aW9uIHRoYXQgY2hlY2tzIGlmIGFuIGFwcCBpcyBibGFja2xpc3RlZFxuICAgICAqL1xuICAgIEFwcHNIb29rcy5wcm90b3R5cGUuYmxhY2tsaXN0UGFja2FnZU1hbmFnZXJTaW5nbGVBcHAgPSBmdW5jdGlvbiAoY2hlY2tCbGFja2xpc3QpIHtcbiAgICAgICAgdmFyIFBNID0gJ2FuZHJvaWQuYXBwLkFwcGxpY2F0aW9uUGFja2FnZU1hbmFnZXInO1xuICAgICAgICAvLyBTaWduYXR1cmUgKFN0cmluZyBwYWNrYWdlTmFtZSlcbiAgICAgICAgKDAsIGphdmFfMS5hZGRKYXZhUHJlSG9vaykoW1xuICAgICAgICAgICAgXCJcIi5jb25jYXQoUE0sIFwiOjpnZXRBcHBsaWNhdGlvbkJhbm5lclwiKSxcbiAgICAgICAgICAgIFwiXCIuY29uY2F0KFBNLCBcIjo6Z2V0QXBwbGljYXRpb25FbmFibGVkU2V0dGluZ1wiKSxcbiAgICAgICAgICAgIFwiXCIuY29uY2F0KFBNLCBcIjo6Z2V0QXBwbGljYXRpb25JY29uXCIpLFxuICAgICAgICAgICAgXCJcIi5jb25jYXQoUE0sIFwiOjpnZXRBcHBsaWNhdGlvbkxvZ29cIiksXG4gICAgICAgICAgICBcIlwiLmNvbmNhdChQTSwgXCI6OmdldEluc3RhbGxTb3VyY2VJbmZvXCIpLFxuICAgICAgICAgICAgXCJcIi5jb25jYXQoUE0sIFwiOjpnZXRJbnN0YWxsZXJQYWNrYWdlTmFtZVwiKSxcbiAgICAgICAgICAgIFwiXCIuY29uY2F0KFBNLCBcIjo6Z2V0TGF1bmNoSW50ZW50Rm9yUGFja2FnZVwiKSxcbiAgICAgICAgICAgIFwiXCIuY29uY2F0KFBNLCBcIjo6Z2V0TGF1bmNoSW50ZW50U2VuZGVyRm9yUGFja2FnZVwiKSxcbiAgICAgICAgICAgIFwiXCIuY29uY2F0KFBNLCBcIjo6Z2V0TGVhbmJhY2tMYXVuY2hJbnRlbnRGb3JQYWNrYWdlXCIpLFxuICAgICAgICAgICAgXCJcIi5jb25jYXQoUE0sIFwiOjpnZXRQYWNrYWdlR2lkc1wiKSxcbiAgICAgICAgICAgIFwiXCIuY29uY2F0KFBNLCBcIjo6Z2V0UmVzb3VyY2VzRm9yQXBwbGljYXRpb25cIiksXG4gICAgICAgICAgICBcIlwiLmNvbmNhdChQTSwgXCI6OmdldFRhcmdldFNka1ZlcnNpb25cIiksXG4gICAgICAgICAgICBcIlwiLmNvbmNhdChQTSwgXCI6OmlzUGFja2FnZVN1c3BlbmRlZFwiKVxuICAgICAgICBdLCBbJ3N0ciddLCBmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICAgICAgaWYgKGNoZWNrQmxhY2tsaXN0KGRhdGEuYXJnc1swXSwgZGF0YSkpIHtcbiAgICAgICAgICAgICAgICBkYXRhLmFyZ3NbMF0gPSAnZG9lc25vdGV4aXN0JztcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgICAgIC8vIFNpZ25hdHVyZSAoU3RyaW5nIHBhY2thZ2VOYW1lLCBpbnQgZmxhZ3MpXG4gICAgICAgICgwLCBqYXZhXzEuYWRkSmF2YVByZUhvb2spKFtcbiAgICAgICAgICAgIFwiXCIuY29uY2F0KFBNLCBcIjo6Z2V0QXBwbGljYXRpb25JbmZvXCIpLFxuICAgICAgICAgICAgXCJcIi5jb25jYXQoUE0sIFwiOjpnZXRNb2R1bGVJbmZvXCIpLFxuICAgICAgICAgICAgXCJcIi5jb25jYXQoUE0sIFwiOjpnZXRQYWNrYWdlR2lkc1wiKSxcbiAgICAgICAgICAgIFwiXCIuY29uY2F0KFBNLCBcIjo6Z2V0UGFja2FnZUluZm9cIiksXG4gICAgICAgICAgICBcIlwiLmNvbmNhdChQTSwgXCI6OmdldFBhY2thZ2VVaWRcIilcbiAgICAgICAgXSwgWydzdHInLCAnaW50J10sIGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgICAgICAgICBpZiAoY2hlY2tCbGFja2xpc3QoZGF0YS5hcmdzWzBdLCBkYXRhKSkge1xuICAgICAgICAgICAgICAgIGRhdGEuYXJnc1swXSA9ICdkb2Vzbm90ZXhpc3QnO1xuICAgICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICAgICAgLy8gU2lnbmF0dXJlIChTdHJpbmcgcGFja2FnZU5hbWUsIGludCByZXNvdXJjZUlkLCBBcHBsaWNhdGlvbkluZm8gYXBwSW5mbylcbiAgICAgICAgKDAsIGphdmFfMS5hZGRKYXZhUHJlSG9vaykoW1xuICAgICAgICAgICAgXCJcIi5jb25jYXQoUE0sIFwiOjpnZXREcmF3YWJsZVwiKSxcbiAgICAgICAgICAgIFwiXCIuY29uY2F0KFBNLCBcIjo6Z2V0VGV4dFwiKSxcbiAgICAgICAgICAgIFwiXCIuY29uY2F0KFBNLCBcIjo6Z2V0WG1sXCIpXG4gICAgICAgIF0sIFsnc3RyJywgJ2ludCcsICdhbmRyb2lkLmNvbnRlbnQucG0uQXBwbGljYXRpb25JbmZvJ10sIGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgICAgICAgICBpZiAoY2hlY2tCbGFja2xpc3QoZGF0YS5hcmdzWzBdLCBkYXRhKSkge1xuICAgICAgICAgICAgICAgIGRhdGEuYXJnc1swXSA9ICdkb2Vzbm90ZXhpc3QnO1xuICAgICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICAgICAgLy8gU2lnbmF0dXJlIChTdHJpbmcgcGFja2FnZU5hbWUsIFBhY2thZ2VNYW5hZ2VyLkFwcGxpY2F0aW9uSW5mb0ZsYWdzIGZsYWdzKVxuICAgICAgICAoMCwgamF2YV8xLmFkZEphdmFQcmVIb29rKShbXCJcIi5jb25jYXQoUE0sIFwiOjpnZXRBcHBsaWNhdGlvbkluZm9cIildLCBbJ3N0cicsIFwiXCIuY29uY2F0KFBNLCBcIi5BcHBsaWNhdGlvbkluZm9GbGFnc1wiKV0sIGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgICAgICAgICBpZiAoY2hlY2tCbGFja2xpc3QoZGF0YS5hcmdzWzBdLCBkYXRhKSkge1xuICAgICAgICAgICAgICAgIGRhdGEuYXJnc1swXSA9ICdkb2Vzbm90ZXhpc3QnO1xuICAgICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICAgICAgLy8gU2lnbmF0dXJlIChTdHJpbmcgcGFja2FnZU5hbWUsIFBhY2thZ2VNYW5hZ2VyLlBhY2thZ2VJbmZvRmxhZ3MgZmxhZ3MpXG4gICAgICAgICgwLCBqYXZhXzEuYWRkSmF2YVByZUhvb2spKFtcbiAgICAgICAgICAgIFwiXCIuY29uY2F0KFBNLCBcIjo6Z2V0UGFja2FnZUdpZHNcIiksXG4gICAgICAgICAgICBcIlwiLmNvbmNhdChQTSwgXCI6OmdldFBhY2thZ2VJbmZvXCIpLFxuICAgICAgICAgICAgXCJcIi5jb25jYXQoUE0sIFwiOjpnZXRQYWNrYWdlVWlkXCIpLFxuICAgICAgICBdLCBbJ3N0cicsIFwiXCIuY29uY2F0KFBNLCBcIi5QYWNrYWdlSW5mb0ZsYWdzXCIpXSwgZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAgICAgICAgIGlmIChjaGVja0JsYWNrbGlzdChkYXRhLmFyZ3NbMF0sIGRhdGEpKSB7XG4gICAgICAgICAgICAgICAgZGF0YS5hcmdzWzBdID0gJ2RvZXNub3RleGlzdCc7XG4gICAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgICAvLyBTaWduYXR1cmUgKFN0cmluZyBwcm9wZXJ0eU5hbWUsIFN0cmluZyBwYWNrYWdlTmFtZSlcbiAgICAgICAgKDAsIGphdmFfMS5hZGRKYXZhUHJlSG9vaykoW1xuICAgICAgICAgICAgXCJcIi5jb25jYXQoUE0sIFwiOjpjaGVja1Blcm1pc3Npb25cIiksXG4gICAgICAgICAgICBcIlwiLmNvbmNhdChQTSwgXCI6OmdldFByb3BlcnR5XCIpLFxuICAgICAgICBdLCBbJ3N0cicsICdzdHInXSwgZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAgICAgICAgIGlmIChjaGVja0JsYWNrbGlzdChkYXRhLmFyZ3NbMV0sIGRhdGEpKSB7XG4gICAgICAgICAgICAgICAgZGF0YS5hcmdzWzFdID0gJ2RvZXNub3RleGlzdCc7XG4gICAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogQmxhY2tsaXN0IGFwcHMgb24gQW5kcm9pZCBieSBob29raW5nIG1ldGhvZHMgb2YgdGhlIFBhY2thZ2VNYW5hZ2VyIGNsYXNzIHRoYXQgdGFrZSBhIGxpc3Qgb2YgYXBwcyBhcyBhbiBhcmd1bWVudFxuICAgICAqIEBwYXJhbSBjaGVja0JsYWNrbGlzdCBmdW5jdGlvbiB0aGF0IGNoZWNrcyBpZiBhbiBhcHAgaXMgYmxhY2tsaXN0ZWRcbiAgICAgKi9cbiAgICBBcHBzSG9va3MucHJvdG90eXBlLmJsYWNrbGlzdFBhY2thZ2VNYW5hZ2VyTXVsdGlBcHAgPSBmdW5jdGlvbiAoY2hlY2tCbGFja2xpc3QpIHtcbiAgICAgICAgdmFyIHBtID0gJ2FuZHJvaWQuYXBwLkFwcGxpY2F0aW9uUGFja2FnZU1hbmFnZXInO1xuICAgICAgICAvLyBIYW5kbGVyIGZvciBtZXRob2RzIHRoYXQgcmV0dXJuIExpc3Q8QXBwbGljYXRpb25JbmZvIHwgUGFja2FnZUluZm8+XG4gICAgICAgIHZhciBpbmZvSGFuZGxlciA9IGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgICAgICAgICB2YXIgYXBwcyA9IGRhdGEucmV0dmFsO1xuICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBhcHBzLnNpemUoKTsgaSsrKSB7XG4gICAgICAgICAgICAgICAgdmFyIGFwcCA9IEphdmEuY2FzdChhcHBzLmdldChpKSwgSmF2YS51c2UoYXBwcy5nZXQoaSkuZ2V0Q2xhc3MoKS5nZXROYW1lKCkpKTtcbiAgICAgICAgICAgICAgICBpZiAoY2hlY2tCbGFja2xpc3QoYXBwLnBhY2thZ2VOYW1lLnZhbHVlLCBkYXRhKSkge1xuICAgICAgICAgICAgICAgICAgICBhcHBzLnJlbW92ZShpKTtcbiAgICAgICAgICAgICAgICAgICAgaS0tO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfTtcbiAgICAgICAgLy8gU2lnbmF0dXJlIChpbnQgZmxhZ3MpID0+IExpc3Q8QXBwbGljYXRpb25JbmZvIHwgUGFja2FnZUluZm8+XG4gICAgICAgICgwLCBqYXZhXzEuYWRkSmF2YVBvc3RIb29rKShbXG4gICAgICAgICAgICBcIlwiLmNvbmNhdChwbSwgXCI6OmdldEluc3RhbGxlZEFwcGxpY2F0aW9uc1wiKSxcbiAgICAgICAgICAgIFwiXCIuY29uY2F0KHBtLCBcIjo6Z2V0SW5zdGFsbGVkUGFja2FnZXNcIilcbiAgICAgICAgXSwgWydpbnQnXSwgaW5mb0hhbmRsZXIpO1xuICAgICAgICAvLyBTaWduYXR1cmUgKFBhY2thZ2VNYW5hZ2VyLlBhY2thZ2VJbmZvRmxhZ3MgZmxhZ3MpID0+IExpc3Q8UGFja2FnZUluZm8+XG4gICAgICAgICgwLCBqYXZhXzEuYWRkSmF2YVBvc3RIb29rKShbXCJcIi5jb25jYXQocG0sIFwiOjpnZXRJbnN0YWxsZWRQYWNrYWdlc1wiKV0sIFtcIlwiLmNvbmNhdChwbSwgXCIuUGFja2FnZUluZm9GbGFnc1wiKV0sIGluZm9IYW5kbGVyKTtcbiAgICAgICAgLy8gU2lnbmF0dXJlIChTdHJpbmdbXSBwZXJtaXNzaW9ucywgaW50IGZsYWdzKSA9PiBMaXN0PFBhY2thZ2VJbmZvPlxuICAgICAgICAoMCwgamF2YV8xLmFkZEphdmFQb3N0SG9vaykoW1wiXCIuY29uY2F0KHBtLCBcIjo6Z2V0UGFja2FnZXNIb2xkaW5nUGVybWlzc2lvbnNcIildLCBbJ3N0cltdJywgJ2ludCddLCBpbmZvSGFuZGxlcik7XG4gICAgICAgIC8vIFNpZ25hdHVyZSAoU3RyaW5nW10gcGFja2FnZXMsIFBhY2thZ2VNYW5hZ2VyLlBhY2thZ2VJbmZvRmxhZ3MgZmxhZ3MpID0+IExpc3Q8UGFja2FnZUluZm8+XG4gICAgICAgICgwLCBqYXZhXzEuYWRkSmF2YVBvc3RIb29rKShbXCJcIi5jb25jYXQocG0sIFwiOjpnZXRQYWNrYWdlc0hvbGRpbmdQZXJtaXNzaW9uc1wiKV0sIFsnc3RyW10nLCBcIlwiLmNvbmNhdChwbSwgXCIuUGFja2FnZUluZm9GbGFnc1wiKV0sIGluZm9IYW5kbGVyKTtcbiAgICAgICAgLy8gU2lnbmF0dXJlIChpbnQgZmxhZ3MpID0+IExpc3Q8UGFja2FnZUluZm8+XG4gICAgICAgICgwLCBqYXZhXzEuYWRkSmF2YVBvc3RIb29rKShbXCJcIi5jb25jYXQocG0sIFwiOjpnZXRQcmVmZXJyZWRQYWNrYWdlc1wiKV0sIFsnaW50J10sIGluZm9IYW5kbGVyKTtcbiAgICAgICAgLy8gU2lnbmF0dXJlIChpbnQgZmxhZ3MpID0+IExpc3Q8TW9kdWxlSW5mbz5cbiAgICAgICAgKDAsIGphdmFfMS5hZGRKYXZhUG9zdEhvb2spKFtcIlwiLmNvbmNhdChwbSwgXCI6OmdldEluc3RhbGxlZE1vZHVsZXNcIildLCBbJ2ludCddLCBmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICAgICAgdmFyIGFwcHMgPSBkYXRhLnJldHZhbDtcbiAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYXBwcy5zaXplKCk7IGkrKykge1xuICAgICAgICAgICAgICAgIHZhciBhcHAgPSBKYXZhLmNhc3QoYXBwcy5nZXQoaSksIEphdmEudXNlKGFwcHMuZ2V0KGkpLmdldENsYXNzKCkuZ2V0TmFtZSgpKSk7XG4gICAgICAgICAgICAgICAgaWYgKGFwcCA9PSBudWxsKVxuICAgICAgICAgICAgICAgICAgICBjb250aW51ZTtcbiAgICAgICAgICAgICAgICBpZiAoY2hlY2tCbGFja2xpc3QoYXBwLmdldFBhY2thZ2VOYW1lKCksIGRhdGEpKSB7XG4gICAgICAgICAgICAgICAgICAgIGFwcHMucmVtb3ZlKGkpO1xuICAgICAgICAgICAgICAgICAgICBpLS07XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICAgICAgLy8gU2lnbmF0dXJlIChpbnQgdWlkKSA9PiBTdHJpbmdbXVxuICAgICAgICAoMCwgamF2YV8xLmFkZEphdmFQb3N0SG9vaykoW1wiXCIuY29uY2F0KHBtLCBcIjo6Z2V0UGFja2FnZXNGb3JVaWRcIildLCBbJ2ludCddLCBmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICAgICAgdmFyIGFwcHMgPSBkYXRhLnJldHZhbDtcbiAgICAgICAgICAgIHZhciBuZXdBcHBzID0gW107XG4gICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGFwcHMubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgICAgICBpZiAoIWNoZWNrQmxhY2tsaXN0KGFwcHNbaV0sIGRhdGEpKSB7XG4gICAgICAgICAgICAgICAgICAgIG5ld0FwcHMucHVzaChhcHBzW2ldKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBkYXRhLnJldHZhbCA9IG5ld0FwcHM7XG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogQmxhY2tsaXN0IGFwcHMgb24gQW5kcm9pZCBieSBob29raW5nIG1ldGhvZHMgb2YgdGhlIEludGVudCBjbGFzc1xuICAgICAqIEBwYXJhbSBjaGVja0JsYWNrbGlzdCBmdW5jdGlvbiB0aGF0IGNoZWNrcyBpZiBhbiBhcHAgaXMgYmxhY2tsaXN0ZWRcbiAgICAgKi9cbiAgICBBcHBzSG9va3MucHJvdG90eXBlLmJsYWNrbGlzdEludGVudCA9IGZ1bmN0aW9uIChjaGVja0JsYWNrbGlzdCkge1xuICAgICAgICB2YXIgaW50ZW50ID0gJ2FuZHJvaWQuY29udGVudC5JbnRlbnQnO1xuICAgICAgICAoMCwgamF2YV8xLmFkZEphdmFQcmVIb29rKShcIlwiLmNvbmNhdChpbnRlbnQsIFwiOjpzZXRQYWNrYWdlXCIpLCBbJ3N0ciddLCBmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICAgICAgaWYgKGNoZWNrQmxhY2tsaXN0KGRhdGEuYXJnc1swXSwgZGF0YSkpIHtcbiAgICAgICAgICAgICAgICBkYXRhLmFyZ3NbMF0gPSAnZG9lc25vdGV4aXN0JztcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgICAgICgwLCBqYXZhXzEuYWRkSmF2YVByZUhvb2spKFwiXCIuY29uY2F0KGludGVudCwgXCI6OnNldENsYXNzTmFtZVwiKSwgWydzdHInLCAnc3RyJ10sIGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgICAgICAgICBpZiAoY2hlY2tCbGFja2xpc3QoZGF0YS5hcmdzWzBdLCBkYXRhKSkge1xuICAgICAgICAgICAgICAgIGRhdGEuYXJnc1swXSA9ICdkb2Vzbm90ZXhpc3QnO1xuICAgICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICAgICAgKDAsIGphdmFfMS5hZGRKYXZhUHJlSG9vaykoXCJcIi5jb25jYXQoaW50ZW50LCBcIjo6c2V0Q29tcG9uZW50XCIpLCBbJ2FuZHJvaWQuY29udGVudC5Db21wb25lbnROYW1lJ10sIGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgICAgICAgICBpZiAoZGF0YS5hcmdzWzBdID09IG51bGwpXG4gICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgaWYgKGNoZWNrQmxhY2tsaXN0KGRhdGEuYXJnc1swXS5nZXRQYWNrYWdlTmFtZSgpLCBkYXRhKSkge1xuICAgICAgICAgICAgICAgIGRhdGEuYXJnc1swXS5zZXRQYWNrYWdlTmFtZSgnZG9lc25vdGV4aXN0Jyk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgcmV0dXJuIEFwcHNIb29rcztcbn0oKSk7XG5leHBvcnRzLkFwcHNIb29rcyA9IEFwcHNIb29rcztcbiIsIlwidXNlIHN0cmljdFwiO1xuZXhwb3J0cy5fX2VzTW9kdWxlID0gdHJ1ZTtcbmV4cG9ydHMuRmlsZUhvb2tzID0gZXhwb3J0cy5GaWxlUGF0dGVybiA9IHZvaWQgMDtcbnZhciBuYXRpdmVfMSA9IHJlcXVpcmUoXCIuL25hdGl2ZVwiKTtcbnZhciBsb2dfMSA9IHJlcXVpcmUoXCIuLi9pbmMvbG9nXCIpO1xudmFyIHV0aWxfMSA9IHJlcXVpcmUoXCIuLi9pbmMvdXRpbFwiKTtcbi8qKlxuICogQ2xhc3MgdXNlZCB0byBtYXRjaCBmaWxlIHBhdGhzIGFnYWluc3QgYSBibGFja2xpc3RcbiAqIE1hdGNoaW5nIGNhbiBiZSBwZXJmb3JtZWQgYnkgZmlsZW5hbWUgb3Igc3Vic3RyaW5nXG4gKi9cbnZhciBGaWxlUGF0dGVybiA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uICgpIHtcbiAgICAvKipcbiAgICAgKiBDb25zdHJ1Y3QgYSBmaWxlIHBhdHRlcm4gdGhhdCBjYW4gYmUgdXNlZCBmb3IgYmxhY2tsaXN0aW5nIGZpbGVzXG4gICAgICogQHBhcmFtIHBhdGggcGF0aCB0byBtYXRjaFxuICAgICAqIEBwYXJhbSBtYXRjaGluZyBtYXRjaGluZyBtZXRob2RcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBGaWxlUGF0dGVybihwYXRoLCBtYXRjaGluZykge1xuICAgICAgICB0aGlzLnBhdGggPSBwYXRoLnRvTG93ZXJDYXNlKCk7XG4gICAgICAgIHRoaXMubWF0Y2hpbmcgPSBtYXRjaGluZztcbiAgICB9XG4gICAgLyoqXG4gICAgICogQ2hlY2sgaWYgYW4gYWJzb2x1dGUgcGF0aCBtYXRjaGVzIHRoaXMgcGF0dGVyblxuICAgICAqIEBwYXJhbSBwYXRoIGFic29sdXRlIHBhdGggdG8gY2hlY2tcbiAgICAgKiBAcmV0dXJucyB0cnVlIGlmIHBhdGggbWF0Y2hlcyB0aGlzIHBhdHRlcm4sIGZhbHNlIG90aGVyd2lzZVxuICAgICAqL1xuICAgIEZpbGVQYXR0ZXJuLnByb3RvdHlwZS5tYXRjaGVzID0gZnVuY3Rpb24gKHBhdGgpIHtcbiAgICAgICAgaWYgKHBhdGggPT09IG51bGwgfHwgcGF0aCA9PT0gdW5kZWZpbmVkKVxuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICBwYXRoID0gcGF0aC50b0xvd2VyQ2FzZSgpO1xuICAgICAgICAvLyBJZ25vcmUgZmlsZXMgb2YgdGhlIGN1cnJlbnQgYXBwbGljYXRpb25cbiAgICAgICAgaWYgKHBhdGguaW5jbHVkZXMoZ2xvYmFsLmNvbnRleHQuaW5mby5wYWNrYWdlKSlcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgaWYgKGdsb2JhbC5jb250ZXh0LmluZm8uZXhlY3V0YWJsZSAmJiBwYXRoLmluY2x1ZGVzKGdsb2JhbC5jb250ZXh0LmluZm8uZXhlY3V0YWJsZSArICcuYXBwJykpXG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIC8vIElnbm9yZSBmcmlkYSBpbnRlcm5hbCBmaWxlcyB0aGF0IGFyZSBhY2Nlc3NlZCBkdXJpbmcgbm9ybWFsIG9wZXJhdGlvblxuICAgICAgICAvLyBUT0RPOiBTZWUgaWYgdGhlcmUgaXMgYSB3YXkgdG8gc3RpbGwgZGV0ZWN0IHdoZW4gdGhlc2UgZmlsZXMgYXJlIGFjY2Vzc2VkIGJ5IFxuICAgICAgICAvLyB0aGUgYXBwIGluc3RlYWQgb2YgZnJpZGEgaXRzZWxmXG4gICAgICAgIGlmIChwYXRoLnN0YXJ0c1dpdGgoJy9kYXRhL2xvY2FsL3RtcC9yZS5mcmlkYS5zZXJ2ZXIvbGluamVjdG9yLScpIHx8XG4gICAgICAgICAgICBwYXRoLnN0YXJ0c1dpdGgoJy9kYXRhL2xvY2FsL3RtcC9yZS5mcmlkYS5zZXJ2ZXIvZnJpZGEtJykpXG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIHN3aXRjaCAodGhpcy5tYXRjaGluZykge1xuICAgICAgICAgICAgY2FzZSAnY29udGFpbnMnOlxuICAgICAgICAgICAgICAgIHJldHVybiBwYXRoLmluY2x1ZGVzKHRoaXMucGF0aCk7XG4gICAgICAgICAgICBjYXNlICdmaWxlbmFtZSc6XG4gICAgICAgICAgICAgICAgaWYgKHRoaXMucGF0aC5pbmNsdWRlcygnLycpKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBwYXRoID09IHRoaXMucGF0aDtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBwYXRoLnNwbGl0KCcvJykucG9wKCkgPT0gdGhpcy5wYXRoO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNhc2UgJ3N0YXJ0c1dpdGgnOlxuICAgICAgICAgICAgICAgIHJldHVybiBwYXRoLnN0YXJ0c1dpdGgodGhpcy5wYXRoKTtcbiAgICAgICAgICAgIGNhc2UgJ2VuZHNXaXRoJzpcbiAgICAgICAgICAgICAgICByZXR1cm4gcGF0aC5lbmRzV2l0aCh0aGlzLnBhdGgpO1xuICAgICAgICB9XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBDb25zdHJ1Y3QgYSBsaXN0IG9mIGZpbGUgcGF0dGVybnMgZnJvbSBhIGxpc3Qgb2Ygc3RyaW5nc1xuICAgICAqIEEgKiBhdCB0aGUgc3RhcnQgb3IgZW5kIG9mIGEgc3RyaW5nIGlzIGNvbnNpZGVyZWQgYSB3aWxkY2FyZFxuICAgICAqIEBwYXJhbSBsaXN0IGxpc3Qgb2Ygc3RyaW5nc1xuICAgICAqIEByZXR1cm5zIGxpc3Qgb2YgZmlsZSBwYXR0ZXJuc1xuICAgICAqL1xuICAgIEZpbGVQYXR0ZXJuLmZyb20gPSBmdW5jdGlvbiAobGlzdCkge1xuICAgICAgICByZXR1cm4gbGlzdC5tYXAoZnVuY3Rpb24gKHBhdGgpIHtcbiAgICAgICAgICAgIHZhciBzdGFydHNXaXRoV2lsZGNhcmQgPSBwYXRoLnN0YXJ0c1dpdGgoJyonKTtcbiAgICAgICAgICAgIHZhciBlbmRzV2l0aFdpbGRjYXJkID0gcGF0aC5lbmRzV2l0aCgnKicpO1xuICAgICAgICAgICAgdmFyIG1hdGNoaW5nO1xuICAgICAgICAgICAgaWYgKHN0YXJ0c1dpdGhXaWxkY2FyZCAmJiBlbmRzV2l0aFdpbGRjYXJkKSB7XG4gICAgICAgICAgICAgICAgbWF0Y2hpbmcgPSAnY29udGFpbnMnO1xuICAgICAgICAgICAgICAgIHBhdGggPSBwYXRoLnN1YnN0cmluZygxLCBwYXRoLmxlbmd0aCAtIDEpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZWxzZSBpZiAoc3RhcnRzV2l0aFdpbGRjYXJkKSB7XG4gICAgICAgICAgICAgICAgbWF0Y2hpbmcgPSAnZW5kc1dpdGgnO1xuICAgICAgICAgICAgICAgIHBhdGggPSBwYXRoLnN1YnN0cmluZygxKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2UgaWYgKGVuZHNXaXRoV2lsZGNhcmQpIHtcbiAgICAgICAgICAgICAgICBtYXRjaGluZyA9ICdzdGFydHNXaXRoJztcbiAgICAgICAgICAgICAgICBwYXRoID0gcGF0aC5zdWJzdHJpbmcoMCwgcGF0aC5sZW5ndGggLSAxKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgIG1hdGNoaW5nID0gJ2ZpbGVuYW1lJztcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBuZXcgRmlsZVBhdHRlcm4ocGF0aCwgbWF0Y2hpbmcpO1xuICAgICAgICB9KTtcbiAgICB9O1xuICAgIHJldHVybiBGaWxlUGF0dGVybjtcbn0oKSk7XG5leHBvcnRzLkZpbGVQYXR0ZXJuID0gRmlsZVBhdHRlcm47XG4vKipcbiAqIFNpbmdsZXRvbiBjbGFzcyB3cmFwcGVyIHVzZWQgdG8gZWFzaWx5IGFkZCBob29rcyB0byBmaWxlIG9wZXJhdGlvbnNcbiAqL1xudmFyIEZpbGVIb29rcyA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uICgpIHtcbiAgICBmdW5jdGlvbiBGaWxlSG9va3MoKSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIHRoaXMuZmlsZURlc2NyaXB0b3JzID0ge307XG4gICAgICAgIHRoaXMuZmlsZUhhbmRsZXIgPSBmdW5jdGlvbiAobGlzdCwgY2FsbGJhY2spIHtcbiAgICAgICAgICAgIHJldHVybiBmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICAgICAgICAgIGlmIChkYXRhLmFyZ3MubGVuZ3RoIDwgMSlcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIHZhciBwYXRoO1xuICAgICAgICAgICAgICAgIGlmICh0eXBlb2YgZGF0YS5hcmdzWzBdID09ICdzdHJpbmcnKSB7XG4gICAgICAgICAgICAgICAgICAgIC8vIEFyZ3M6IHBhdGhcbiAgICAgICAgICAgICAgICAgICAgcGF0aCA9IGRhdGEuYXJnc1swXTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZiAoZGF0YS5hcmdzLmxlbmd0aCA+PSAyICYmIHR5cGVvZiBkYXRhLmFyZ3NbMF0gPT0gJ251bWJlcicgJiYgdHlwZW9mIGRhdGEuYXJnc1sxXSA9PSAnc3RyaW5nJykge1xuICAgICAgICAgICAgICAgICAgICAvLyBBcmdzOiBmZCwgcGF0aFxuICAgICAgICAgICAgICAgICAgICBwYXRoID0gZGF0YS5hcmdzWzFdO1xuICAgICAgICAgICAgICAgICAgICBpZiAoZGF0YS5hcmdzWzBdICYmIF90aGlzLmZpbGVEZXNjcmlwdG9yc1tkYXRhLmFyZ3NbMF1dKVxuICAgICAgICAgICAgICAgICAgICAgICAgcGF0aCA9IF90aGlzLmZpbGVEZXNjcmlwdG9yc1tkYXRhLmFyZ3NbMF1dICsgJy8nICsgcGF0aDtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZiAodHlwZW9mIGRhdGEuYXJnc1swXSA9PSAnbnVtYmVyJykge1xuICAgICAgICAgICAgICAgICAgICAvLyBBcmdzOiBmZFxuICAgICAgICAgICAgICAgICAgICBwYXRoID0gX3RoaXMuZmlsZURlc2NyaXB0b3JzW2RhdGEuYXJnc1swXV07XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmIChsaXN0LnNvbWUoZnVuY3Rpb24gKGl0ZW0pIHsgcmV0dXJuIGl0ZW0ubWF0Y2hlcyhwYXRoKTsgfSkpIHtcbiAgICAgICAgICAgICAgICAgICAgbG9nRmlsZShkYXRhLCBwYXRoKTtcbiAgICAgICAgICAgICAgICAgICAgY2FsbGJhY2soZGF0YSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfTtcbiAgICAgICAgfTtcbiAgICAgICAgLy8gQWRkIGhvb2tzIHNvIHdlIGNhbiBhc3NvY2lhdGUgZmlsZSBkZXNjcmlwdG9ycyB3aXRoIGZpbGUgcGF0aHNcbiAgICAgICAgKDAsIG5hdGl2ZV8xLmFkZFBvc3RIb29rKShbJ29wZW4nLCAnb3Blbl9kcHJvdGVjdGVkX25wJywgJ29wZW5fZXh0ZW5kZWQnLCAnb3Blbl9ub2NhbmNlbCcsICdndWFyZGVkX29wZW5fbnAnLCAnZ3VhcmRlZF9vcGVuX2Rwcm90ZWN0ZWRfbnAnLCAnY3JlYXQnXSwgWydzdHInXSwgZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAgICAgICAgIGlmIChkYXRhLnJldHZhbC50b0ludDMyKCkgPCAwKVxuICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgIF90aGlzLmZpbGVEZXNjcmlwdG9yc1tkYXRhLnJldHZhbC50b0ludDMyKCldID0gZGF0YS5hcmdzWzBdO1xuICAgICAgICB9KTtcbiAgICAgICAgKDAsIG5hdGl2ZV8xLmFkZFBvc3RIb29rKShbJ2Nsb3NlJywgJ2FuZHJvaWRfZmRzYW5fY2xvc2Vfd2l0aF90YWcnLCAnc3lzX2Nsb3NlJywgJ3N5c19jbG9zZV9ub2NhbmNlbCcsICdndWFyZGVkX2Nsb3NlX25wJ10sIFsnaW50J10sIGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgICAgICAgICBpZiAoZGF0YS5yZXR2YWwudG9JbnQzMigpICE9IDApXG4gICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgZGVsZXRlIF90aGlzLmZpbGVEZXNjcmlwdG9yc1tkYXRhLmFyZ3NbMF1dO1xuICAgICAgICB9KTtcbiAgICAgICAgKDAsIG5hdGl2ZV8xLmFkZFBvc3RIb29rKShbJ29wZW5hdCcsICdvcGVuYXRfbm9jYW5jZWwnXSwgWydpbnQnLCAnc3RyJ10sIGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgICAgICAgICBpZiAoZGF0YS5yZXR2YWwudG9JbnQzMigpIDwgMClcbiAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICBfdGhpcy5maWxlRGVzY3JpcHRvcnNbZGF0YS5yZXR2YWwudG9JbnQzMigpXSA9IF90aGlzLmZpbGVEZXNjcmlwdG9yc1tkYXRhLmFyZ3NbMF1dICsgJy8nICsgZGF0YS5hcmdzWzFdO1xuICAgICAgICB9KTtcbiAgICB9XG4gICAgRmlsZUhvb2tzLmdldEluc3RhbmNlID0gZnVuY3Rpb24gKCkge1xuICAgICAgICBpZiAoIUZpbGVIb29rcy5pbnN0YW5jZSkge1xuICAgICAgICAgICAgRmlsZUhvb2tzLmluc3RhbmNlID0gbmV3IEZpbGVIb29rcygpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBGaWxlSG9va3MuaW5zdGFuY2U7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBBZGRzIGhvb2tzIHRvIGZpbGUgb3BlcmF0aW9ucyByZWxhdGVkIHRvIHRoZSBsaXN0ZWQgZmlsZXMuIENhbiBhbHNvIGJsYWNrbGlzdCBmaWxlcyBzbyB0aGV5IGFyZSBub3QgdmlzaWJsZSB0byB0aGUgYXBwXG4gICAgICogQHBhcmFtIGxpc3QgbGlzdCBvZiBmaWxlIHBhdGhzXG4gICAgICogQHBhcmFtIGJsYWNrbGlzdCBpZiB0cnVlLCB0aGUgbGlzdCBpcyB0cmVhdGVkIGFzIGEgYmxhY2tsaXN0LCBvdGhlcndpc2UgdGhlIGZ1bmN0aW9uIHdpbGwgb25seSBsb2cgYWNjZXNzIHRvIG1hdGNoaW5nIGZpbGVzXG4gICAgICovXG4gICAgRmlsZUhvb2tzLnByb3RvdHlwZS5hY2Nlc3NGaWxlSG9vayA9IGZ1bmN0aW9uIChsaXN0LCBibGFja2xpc3QpIHtcbiAgICAgICAgaWYgKGJsYWNrbGlzdCA9PT0gdm9pZCAwKSB7IGJsYWNrbGlzdCA9IGZhbHNlOyB9XG4gICAgICAgIC8vIEFyZ3M6IHBhdGhcbiAgICAgICAgdmFyIGZpbGVIb29rID0gdGhpcy5maWxlSGFuZGxlcihsaXN0LCBmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICAgICAgaWYgKGJsYWNrbGlzdCkge1xuICAgICAgICAgICAgICAgIGRhdGEuYXJnc1swXSA9IFwiL2RvZXNub3RleGlzdFwiO1xuICAgICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICAgICAgLy8gQXJnczogZmQsIHBhdGhcbiAgICAgICAgdmFyIGZpbGVhdEhvb2sgPSB0aGlzLmZpbGVIYW5kbGVyKGxpc3QsIGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgICAgICAgICBpZiAoYmxhY2tsaXN0KSB7XG4gICAgICAgICAgICAgICAgZGF0YS5hcmdzWzFdID0gXCIvZG9lc25vdGV4aXN0XCI7XG4gICAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgICAvLyBBcmdzOiBmZFxuICAgICAgICB2YXIgZmZpbGVIb29rID0gdGhpcy5maWxlSGFuZGxlcihsaXN0LCBmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICAgICAgLy8gTm8gbmVlZCB0byBjaGVjayBmb3IgYmxhY2tsaXN0LCBzaW5jZSB0aGUgYXBwIHdvdWxkIGJlIHVuYWJsZSB0byBjb25zdHJ1Y3QgYSBmaWxlIGRlc2NyaXB0b3IgXG4gICAgICAgICAgICAvLyB0byB0aGVzZSBmaWxlcyBzaW5jZSB3ZSBob29rIG9wZW4gYW5kIG9wZW5hdFxuICAgICAgICB9KTtcbiAgICAgICAgdmFyIG9wZW5TeXNjYWxscyA9IFsnb3BlbicsICdvcGVuX2Rwcm90ZWN0ZWRfbnAnLCAnb3Blbl9leHRlbmRlZCcsICdvcGVuX25vY2FuY2VsJywgJ2d1YXJkZWRfb3Blbl9ucCcsICdndWFyZGVkX29wZW5fZHByb3RlY3RlZF9ucCcsICdjcmVhdCcsICdhY2Nlc3MnLCAnYWNjZXNzX2V4dGVuZGVkJ107XG4gICAgICAgICgwLCBuYXRpdmVfMS5hZGRQcmVIb29rKShvcGVuU3lzY2FsbHMsIFsnc3RyJ10sIGZpbGVIb29rKTtcbiAgICAgICAgdmFyIG9wZW5hdFN5c2NhbGxzID0gWydvcGVuYXQnLCAnb3BlbmF0X25vY2FuY2VsJywgJ2ZhY2Nlc3NhdCddO1xuICAgICAgICAoMCwgbmF0aXZlXzEuYWRkUHJlSG9vaykob3BlbmF0U3lzY2FsbHMsIFsnaW50JywgJ3N0ciddLCBmaWxlYXRIb29rKTtcbiAgICAgICAgdmFyIHN0YXRTeXNjYWxscyA9IFsnbHN0YXQnLCAnc3RhdCcsICdzdGF0ZnMnLCAnc3RhdHZmcyddO1xuICAgICAgICAoMCwgbmF0aXZlXzEuYWRkUHJlSG9vaykoc3RhdFN5c2NhbGxzLCBbJ3N0cicsICdwdHInXSwgZmlsZUhvb2spO1xuICAgICAgICB2YXIgZnN0YXRTeXNjYWxscyA9IFsnZnN0YXQnLCAnc3lzX2ZzdGF0JywgJ2ZzdGF0ZnMnLCAnZnN0YXR2ZnMnXTtcbiAgICAgICAgKDAsIG5hdGl2ZV8xLmFkZFByZUhvb2spKGZzdGF0U3lzY2FsbHMsIFsnaW50JywgJ3B0ciddLCBmZmlsZUhvb2spO1xuICAgICAgICAoMCwgbmF0aXZlXzEuYWRkUHJlSG9vaykoJ2ZzdGF0YXQnLCBbJ2ludCcsICdzdHInLCAncHRyJywgJ2ludCddLCBmaWxlYXRIb29rKTtcbiAgICAgICAgKDAsIG5hdGl2ZV8xLmFkZFByZUhvb2spKCdwYXRoY29uZicsIFsnc3RyJywgJ2ludCddLCBmaWxlSG9vayk7XG4gICAgICAgICgwLCBuYXRpdmVfMS5hZGRQcmVIb29rKShbJ2ZwYXRoY29uZicsICdzeXNfZnBhdGhjb25mJ10sIFsnaW50JywgJ2ludCddLCBmZmlsZUhvb2spO1xuICAgICAgICAoMCwgbmF0aXZlXzEuYWRkUHJlSG9vaykoJ2dldGF0dHJsaXN0JywgWydzdHInLCAncHRyJywgJ3B0cicsICdpbnQnXSwgZmlsZUhvb2spO1xuICAgICAgICAoMCwgbmF0aXZlXzEuYWRkUHJlSG9vaykoJ2ZnZXRhdHRybGlzdCcsIFsnaW50JywgJ3B0cicsICdwdHInLCAnaW50J10sIGZmaWxlSG9vayk7XG4gICAgICAgICgwLCBuYXRpdmVfMS5hZGRQcmVIb29rKSgnZ2V0YXR0cmxpc3RhdCcsIFsnaW50JywgJ3N0cicsICdwdHInLCAncHRyJywgJ2ludCddLCBmaWxlYXRIb29rKTtcbiAgICAgICAgKDAsIG5hdGl2ZV8xLmFkZFByZUhvb2spKCdyZWFkbGluaycsIFsnc3RyJ10sIGZpbGVIb29rKTtcbiAgICAgICAgKDAsIG5hdGl2ZV8xLmFkZFByZUhvb2spKCdyZWFkbGlua2F0JywgWydpbnQnLCAnc3RyJ10sIGZpbGVhdEhvb2spO1xuICAgICAgICB2YXIgcmVhZGxpbmtIb29rID0gZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAgICAgICAgIHZhciBsaW5rUGF0aEluZGV4ID0gMTtcbiAgICAgICAgICAgIGlmICh0eXBlb2YgZGF0YS5hcmdzWzBdICE9ICdzdHJpbmcnKSB7XG4gICAgICAgICAgICAgICAgbGlua1BhdGhJbmRleCA9IDI7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAobGlzdC5zb21lKGZ1bmN0aW9uIChpdGVtKSB7IHJldHVybiBpdGVtLm1hdGNoZXMoZGF0YS5hcmdzW2xpbmtQYXRoSW5kZXhdKTsgfSkpIHtcbiAgICAgICAgICAgICAgICBsb2dGaWxlKGRhdGEsIGRhdGEuYXJnc1tsaW5rUGF0aEluZGV4XSk7XG4gICAgICAgICAgICAgICAgaWYgKGJsYWNrbGlzdCkge1xuICAgICAgICAgICAgICAgICAgICBkYXRhLmFyZ3NbbGlua1BhdGhJbmRleF0gPSAnL2Rldi9udWxsJztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH07XG4gICAgICAgICgwLCBuYXRpdmVfMS5hZGRQb3N0SG9vaykoJ3JlYWRsaW5rJywgWydzdHInLCAnc3RyJ10sIHJlYWRsaW5rSG9vayk7XG4gICAgICAgICgwLCBuYXRpdmVfMS5hZGRQcmVIb29rKSgncmVhZGxpbmthdCcsIFsnaW50JywgJ3N0cicsICdzdHInXSwgcmVhZGxpbmtIb29rKTtcbiAgICAgICAgLy8gVE9ETzogQmxhY2tsaXN0IGluZGl2aWR1YWwgZGlyZWN0b3J5IGVudHJpZXNcbiAgICAgICAgKDAsIG5hdGl2ZV8xLmFkZFByZUhvb2spKCdnZXRhdHRybGlzdGJ1bGsnLCBbJ2ludCcsICdwdHInLCAncHRyJywgJ2ludCcsICdpbnQnXSwgZmZpbGVIb29rKTtcbiAgICAgICAgKDAsIG5hdGl2ZV8xLmFkZFByZUhvb2spKCdnZXRkaXJlbnRyaWVzYXR0cicsIFsnaW50JywgJ3B0cicsICdwdHInLCAnaW50JywgJ2xvbmcnLCAnbG9uZycsICdsb25nJywgJ2ludCddLCBmZmlsZUhvb2spO1xuICAgICAgICAoMCwgbmF0aXZlXzEuYWRkUHJlSG9vaykoJ2dldGRpcmVudHJpZXMnLCBbJ2ludCcsICdwdHInLCAnaW50JywgJ3B0ciddLCBmZmlsZUhvb2spO1xuICAgICAgICAvLyBIb29rIGV4ZWN1dGluZyBmaWxlc1xuICAgICAgICB2YXIgZXhlYyA9IFsnZXhlY3ZlJywgJ2V4ZWN2JywgJ2V4ZWN2cCcsICdleGVjdnBlJ107XG4gICAgICAgICgwLCBuYXRpdmVfMS5hZGRQcmVIb29rKShleGVjLCBbJ3N0cicsICdwdHInXSwgZmlsZUhvb2spO1xuICAgICAgICAoMCwgbmF0aXZlXzEuYWRkUHJlSG9vaykoJ3N5c3RlbScsIFsnc3RyJ10sIGZpbGVIb29rKTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIFZpcnR1YWxseSBjaGFuZ2UgcGVybWlzc2lvbnMgb2YgZmlsZXMgbWF0Y2hpbmcgdGhlIGxpc3QgdG8gcmVhZC1vbmx5XG4gICAgICogQHBhcmFtIGxpc3QgbGlzdCBvZiBmaWxlIHBhdGhzXG4gICAgICovXG4gICAgRmlsZUhvb2tzLnByb3RvdHlwZS5yb1Blcm1pc3Npb25zRmlsZUhvb2sgPSBmdW5jdGlvbiAobGlzdCkge1xuICAgICAgICB2YXIgc3RhdCA9ICgwLCB1dGlsXzEuc3lzY2FsbCkoJ3N0YXQnLCAnaW50JywgWydwb2ludGVyJywgJ3BvaW50ZXInXSk7XG4gICAgICAgIGZ1bmN0aW9uIHNldFBlcm1pc3Npb25zKHN0YXRTdHJ1Y3QpIHtcbiAgICAgICAgICAgIC8vIFNldCBmaWxlIHBlcm1pc3Npb25zIHRvIHJlYWQtb25seSBpbiBzdF9tb2RlXG4gICAgICAgICAgICAvLyB1bnNpZ25lZCBsb25nK3Vuc2lnbmVkIGxvbmcgPSA4KzggPSAxNlxuICAgICAgICAgICAgdmFyIHBlcm1pc3Npb25zID0gc3RhdFN0cnVjdC5hZGQoMTYpLnJlYWRVMzIoKTtcbiAgICAgICAgICAgIC8vIENsZWFyIHdyaXRlIHBlcm1pc3Npb25zXG4gICAgICAgICAgICBwZXJtaXNzaW9ucyA9IChwZXJtaXNzaW9ucyAmIH4xNDYpID4+PiAwO1xuICAgICAgICAgICAgc3RhdFN0cnVjdC5hZGQoMTYpLndyaXRlVTMyKHBlcm1pc3Npb25zKTtcbiAgICAgICAgfVxuICAgICAgICB2YXIgc2V0UGVybWlzc2lvbnNIb29rID0gdGhpcy5maWxlSGFuZGxlcihsaXN0LCBmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICAgICAgdmFyIHN0YXRTdHJ1Y3Q7XG4gICAgICAgICAgICBpZiAodHlwZW9mIGRhdGEuYXJnc1sxXSA9PSAnbnVtYmVyJykge1xuICAgICAgICAgICAgICAgIC8vIEFyZ3M6IGZkLCBzdGF0XG4gICAgICAgICAgICAgICAgc3RhdFN0cnVjdCA9IGRhdGEuYXJnc1sxXTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2UgaWYgKHR5cGVvZiBkYXRhLmFyZ3NbMl0gPT0gJ251bWJlcicpIHtcbiAgICAgICAgICAgICAgICAvLyBBcmdzOiBmZCwgcGF0aCwgc3RhdFxuICAgICAgICAgICAgICAgIHN0YXRTdHJ1Y3QgPSBkYXRhLmFyZ3NbMl07XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBzZXRQZXJtaXNzaW9ucyhzdGF0U3RydWN0KTtcbiAgICAgICAgfSk7XG4gICAgICAgICgwLCBuYXRpdmVfMS5hZGRQb3N0SG9vaykoWydzdGF0JywgJ3N0YXRfZXh0ZW5kZWQnXSwgWydzdHInLCAncHRyJ10sIHNldFBlcm1pc3Npb25zSG9vayk7XG4gICAgICAgICgwLCBuYXRpdmVfMS5hZGRQb3N0SG9vaykoWydsc3RhdCcsICdsc3RhdF9leHRlbmRlZCddLCBbJ3N0cicsICdwdHInXSwgdGhpcy5maWxlSGFuZGxlcihsaXN0LCBmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICAgICAgLy8gVXNlIHN0YXQgc28gd2UgZG9uJ3QgcmV0dXJuIGEgc3ltbGlua1xuICAgICAgICAgICAgc3RhdChNZW1vcnkuYWxsb2NVdGY4U3RyaW5nKGRhdGEuYXJnc1swXSksIGRhdGEuYXJnc1sxXSk7XG4gICAgICAgICAgICBzZXRQZXJtaXNzaW9ucyhkYXRhLmFyZ3NbMV0pO1xuICAgICAgICB9KSk7XG4gICAgICAgICgwLCBuYXRpdmVfMS5hZGRQb3N0SG9vaykoWydmc3RhdCcsICdzeXNfZnN0YXRfZXh0ZW5kZWQnLCAnc3lzX2ZzdGF0J10sIFsnaW50JywgJ3B0ciddLCBzZXRQZXJtaXNzaW9uc0hvb2spO1xuICAgICAgICAoMCwgbmF0aXZlXzEuYWRkUHJlSG9vaykoWydmc3RhdGF0J10sIFsnaW50JywgJ3N0cicsICdwdHInLCAnaW50J10sIHRoaXMuZmlsZUhhbmRsZXIobGlzdCwgZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAgICAgICAgIC8vIFVuc2V0IEFUX1NZTUxJTktfTk9GT0xMT1dcbiAgICAgICAgICAgIGRhdGEuYXJnc1szXSAmPSB+MHgxMDA7XG4gICAgICAgIH0pKTtcbiAgICAgICAgKDAsIG5hdGl2ZV8xLmFkZFBvc3RIb29rKShbJ2ZzdGF0YXQnXSwgWydpbnQnLCAnc3RyJywgJ3B0cicsICdpbnQnXSwgc2V0UGVybWlzc2lvbnNIb29rKTtcbiAgICAgICAgdmFyIHNldEFjY2Vzc2libGVIb29rID0gdGhpcy5maWxlSGFuZGxlcihsaXN0LCBmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICAgICAgdmFyIG1vZGU7XG4gICAgICAgICAgICBpZiAodHlwZW9mIGRhdGEuYXJnc1sxXSA9PSAnbnVtYmVyJykge1xuICAgICAgICAgICAgICAgIC8vIEFyZ3M6IGZkLCBtb2RlXG4gICAgICAgICAgICAgICAgbW9kZSA9IGRhdGEuYXJnc1sxXTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2UgaWYgKHR5cGVvZiBkYXRhLmFyZ3NbMl0gPT0gJ251bWJlcicpIHtcbiAgICAgICAgICAgICAgICAvLyBBcmdzOiBmZCwgcGF0aCwgbW9kZVxuICAgICAgICAgICAgICAgIG1vZGUgPSBkYXRhLmFyZ3NbMl07XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAobW9kZSAmIDE0Nikge1xuICAgICAgICAgICAgICAgIGRhdGEucmV0dmFsLnJlcGxhY2UoLTEpO1xuICAgICAgICAgICAgICAgIGRhdGEuY29udGV4dC5lcnJubyA9IDEzOyAvLyBFQUNDRVNcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgICAgICgwLCBuYXRpdmVfMS5hZGRQb3N0SG9vaykoWydhY2Nlc3MnLCAnYWNjZXNzX2V4dGVuZGVkJ10sIFsnc3RyJywgJ2ludCddLCBzZXRBY2Nlc3NpYmxlSG9vayk7XG4gICAgICAgICgwLCBuYXRpdmVfMS5hZGRQb3N0SG9vaykoJ2ZhY2Nlc3NhdCcsIFsnaW50JywgJ3N0cicsICdpbnQnLCAnaW50J10sIHNldEFjY2Vzc2libGVIb29rKTtcbiAgICAgICAgKDAsIG5hdGl2ZV8xLmFkZFByZUhvb2spKCdyZWFkbGluaycsIFsnc3RyJ10sIHRoaXMuZmlsZUhhbmRsZXIobGlzdCwgZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAgICAgICAgIGRhdGEuYXJnc1swXSA9IFwiL1wiOyAvLyBNYWtlIHN1cmUgRUlOVkFMIGlzIHJldHVybmVkIChub3QgYSBzeW1saW5rKVxuICAgICAgICB9KSk7XG4gICAgICAgICgwLCBuYXRpdmVfMS5hZGRQcmVIb29rKSgncmVhZGxpbmthdCcsIFsnaW50JywgJ3N0ciddLCB0aGlzLmZpbGVIYW5kbGVyKGxpc3QsIGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgICAgICAgICBkYXRhLmFyZ3NbMV0gPSBcIi9cIjsgLy8gTWFrZSBzdXJlIEVJTlZBTCBpcyByZXR1cm5lZCAobm90IGEgc3ltbGluaylcbiAgICAgICAgfSkpO1xuICAgICAgICB2YXIgZXBlcm1Ib29rID0gdGhpcy5maWxlSGFuZGxlcihsaXN0LCBmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICAgICAgZGF0YS5yZXR2YWwucmVwbGFjZSgtMSk7XG4gICAgICAgICAgICBkYXRhLmNvbnRleHQuZXJybm8gPSAxOyAvLyBFUEVSTVxuICAgICAgICB9KTtcbiAgICAgICAgdmFyIHdyaXRlU3lzY2FsbHMgPSBbJ3dyaXRlJywgJ3dyaXRlX25vY2FuY2VsJywgJ3dyaXRldicsICd3cml0ZXZfbm9jYW5jZWwnLCAncHdyaXRlJywgJ3B3cml0ZV9ub2NhbmNlbCcsICdwd3JpdGV2JywgJ3B3cml0ZXYyJywgJ3N5c19wd3JpdGV2JywgJ3N5c19wd3JpdGV2X25vY2FuY2VsJ107XG4gICAgICAgICgwLCBuYXRpdmVfMS5hZGRQcmVIb29rKSh3cml0ZVN5c2NhbGxzLCBbJ2ludCcsICdwdHInLCAndWludCddLCB0aGlzLmZpbGVIYW5kbGVyKGxpc3QsIGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgICAgICAgICBkYXRhLmFyZ3NbMl0gPSAwO1xuICAgICAgICB9KSk7XG4gICAgICAgICgwLCBuYXRpdmVfMS5hZGRQb3N0SG9vaykod3JpdGVTeXNjYWxscywgWydpbnQnLCAncHRyJywgJ3VpbnQnXSwgZXBlcm1Ib29rKTtcbiAgICAgICAgdmFyIGd1YXJkZWRXcml0ZVN5c2NhbGxzID0gWydndWFyZGVkX3dyaXRlX25wJywgJ2d1YXJkZWRfcHdyaXRlX25wJywgJ2d1YXJkZWRfd3JpdGV2X25wJ107XG4gICAgICAgICgwLCBuYXRpdmVfMS5hZGRQcmVIb29rKShndWFyZGVkV3JpdGVTeXNjYWxscywgWydpbnQnLCAncHRyJywgJ3B0cicsICd1aW50J10sIHRoaXMuZmlsZUhhbmRsZXIobGlzdCwgZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAgICAgICAgIGRhdGEuYXJnc1szXSA9IDA7XG4gICAgICAgIH0pKTtcbiAgICAgICAgKDAsIG5hdGl2ZV8xLmFkZFBvc3RIb29rKShndWFyZGVkV3JpdGVTeXNjYWxscywgWydpbnQnLCAncHRyJywgJ3B0cicsICd1aW50J10sIGVwZXJtSG9vayk7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBWaXJ0dWFsbHkgcmVwbGFjZSBhIChyZWFkb25seSkgZmlsZSB3aXRoIG5ldyBjb250ZXh0IGJ5IGhvb2tpbmcgYWxsIGZpbGUgb3BlcmF0aW9uc1xuICAgICAqIEBwYXJhbSBwYXRoIHNvbWUgcGFyZW50IGRpcmVjdG9yeSBvZiBmaWxlIHRvIHJlcGxhY2VcbiAgICAgKiBAcGFyYW0gZmlsZW5hbWUgbmFtZSBvZiBmaWxlIHRvIHJlcGxhY2VcbiAgICAgKiBAcGFyYW0gY2FsbGJhY2sgY2FsbGJhY2sgdG8gZ2VuZXJhdGUgbmV3IGZpbGUgY29udGVudHNcbiAgICAgKi9cbiAgICBGaWxlSG9va3MucHJvdG90eXBlLnJlcGxhY2VGaWxlSG9vayA9IGZ1bmN0aW9uIChwYXRoLCBmaWxlbmFtZSwgY2FsbGJhY2ssIGNvbmZpZGVudCkge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICBpZiAoY29uZmlkZW50ID09PSB2b2lkIDApIHsgY29uZmlkZW50ID0gdHJ1ZTsgfVxuICAgICAgICAvLyBDcmVhdGUgYSB0ZW1wb3JhcnkgZmlsZSB0byByZXBsYWNlIGEgZmlsZVxuICAgICAgICB2YXIgdG1wRGlyID0gbnVsbDtcbiAgICAgICAgaWYgKFByb2Nlc3MucGxhdGZvcm0gPT0gJ2RhcndpbicpIHtcbiAgICAgICAgICAgIGlmIChPYmpDLmF2YWlsYWJsZSkge1xuICAgICAgICAgICAgICAgIC8vIE5TVGVtcG9yYXJ5RGlyZWN0b3J5KClcbiAgICAgICAgICAgICAgICB2YXIgTlNUZW1wb3JhcnlEaXJlY3RvcnkgPSBuZXcgTmF0aXZlRnVuY3Rpb24oTW9kdWxlLmZpbmRFeHBvcnRCeU5hbWUobnVsbCwgJ05TVGVtcG9yYXJ5RGlyZWN0b3J5JyksICdwb2ludGVyJywgW10pO1xuICAgICAgICAgICAgICAgIHRtcERpciA9IChuZXcgT2JqQy5PYmplY3QoTlNUZW1wb3JhcnlEaXJlY3RvcnkoKSkpLnRvU3RyaW5nKCk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAoMCwgbG9nXzEuZXJyb3IpKFwiQ2Fubm90IHJlcGxhY2UgZmlsZSBvbiBpT1Mgd2l0aG91dCBPYmplY3RpdmUtQyBydW50aW1lXCIpO1xuICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIC8vIEFuZHJvaWRcbiAgICAgICAgICAgIHZhciBwYWNrYWdlSWQgPSBnbG9iYWwuY29udGV4dC5pbmZvLnBhY2thZ2U7XG4gICAgICAgICAgICB0bXBEaXIgPSBcIi9kYXRhL2RhdGEvXCIgKyBwYWNrYWdlSWQ7XG4gICAgICAgIH1cbiAgICAgICAgdmFyIG9wZW4gPSAoMCwgdXRpbF8xLnN5c2NhbGwpKCdvcGVuJywgJ2ludCcsIFsncG9pbnRlcicsICdpbnQnXSk7XG4gICAgICAgIHZhciBjbG9zZSA9ICgwLCB1dGlsXzEuc3lzY2FsbCkoJ2Nsb3NlJywgJ2ludCcsIFsnaW50J10pO1xuICAgICAgICB2YXIgcmVwbGFjZUZpbGVIYW5kbGVyID0gZnVuY3Rpb24gKG9wZW5QYXRoLCBmbGFncywgZGF0YSkge1xuICAgICAgICAgICAgaWYgKG9wZW5QYXRoICE9IG51bGwgJiYgb3BlblBhdGguc3RhcnRzV2l0aChwYXRoKSAmJiBvcGVuUGF0aC5lbmRzV2l0aChmaWxlbmFtZSkpIHtcbiAgICAgICAgICAgICAgICB2YXIgbmV3RmlsZSA9IGNhbGxiYWNrKG9wZW5QYXRoKTtcbiAgICAgICAgICAgICAgICBpZiAobmV3RmlsZSAhPSBudWxsKSB7XG4gICAgICAgICAgICAgICAgICAgIGxvZ0ZpbGUoZGF0YSwgb3BlblBhdGgsIGNvbmZpZGVudCk7XG4gICAgICAgICAgICAgICAgICAgIC8vIFdyaXRlIG5ld0ZpbGUgdG8gdGVtcG9yYXJ5IGZpbGVcbiAgICAgICAgICAgICAgICAgICAgdmFyIHRtcEZpbGUgPSB0bXBEaXIgKyAnLycgKyBvcGVuUGF0aC5yZXBsYWNlKC9cXC8vZywgJ18nKSArICdfJyArIChuZXcgRGF0ZSgpKS5nZXRUaW1lKCkgKyAnLnRtcCc7XG4gICAgICAgICAgICAgICAgICAgIHZhciBzdWNjZXNzID0gKDAsIHV0aWxfMS53cml0ZUZpbGUpKHRtcEZpbGUsIG5ld0ZpbGUpO1xuICAgICAgICAgICAgICAgICAgICBpZiAoIXN1Y2Nlc3MpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICgwLCBsb2dfMS5lcnJvcikoXCJGYWlsZWQgdG8gd3JpdGUgdGVtcG9yYXJ5IGZpbGUgXCIgKyB0bXBGaWxlICsgXCIgZm9yIFwiICsgb3BlblBhdGggKyBcIiByZXBsYWNlbWVudFwiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAvLyBSZXBsYWNlIGZpbGUgZGVzY3JpcHRvclxuICAgICAgICAgICAgICAgICAgICB2YXIgdG1wRmlsZVBhdGggPSBNZW1vcnkuYWxsb2NVdGY4U3RyaW5nKHRtcEZpbGUpO1xuICAgICAgICAgICAgICAgICAgICB2YXIgZmQgPSBvcGVuKHRtcEZpbGVQYXRoLCBmbGFncyk7XG4gICAgICAgICAgICAgICAgICAgIGlmIChmZCA9PSAtMSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgKDAsIGxvZ18xLmVycm9yKShcIkZhaWxlZCB0byBvcGVuIHRlbXBvcmFyeSBmaWxlIGZvciBcIiArIG9wZW5QYXRoICsgXCIgcmVwbGFjZW1lbnRcIik7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgX3RoaXMuZmlsZURlc2NyaXB0b3JzW2ZkXSA9IG9wZW5QYXRoO1xuICAgICAgICAgICAgICAgICAgICBjbG9zZShkYXRhLnJldHZhbC50b0ludDMyKCkpO1xuICAgICAgICAgICAgICAgICAgICBkYXRhLnJldHZhbC5yZXBsYWNlKGZkKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH07XG4gICAgICAgICgwLCBuYXRpdmVfMS5hZGRQb3N0SG9vaykoWydvcGVuJywgJ29wZW5fZHByb3RlY3RlZF9ucCcsICdvcGVuX2V4dGVuZGVkJywgJ29wZW5fbm9jYW5jZWwnLCAnZ3VhcmRlZF9vcGVuX25wJywgJ2d1YXJkZWRfb3Blbl9kcHJvdGVjdGVkX25wJywgJ2NyZWF0J10sIFsnc3RyJywgJ2ludCddLCBmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICAgICAgdmFyIG9wZW5QYXRoID0gZGF0YS5hcmdzWzBdO1xuICAgICAgICAgICAgcmVwbGFjZUZpbGVIYW5kbGVyKG9wZW5QYXRoLCBkYXRhLmFyZ3NbMV0sIGRhdGEpO1xuICAgICAgICB9KTtcbiAgICAgICAgKDAsIG5hdGl2ZV8xLmFkZFBvc3RIb29rKShbJ29wZW5hdCcsICdvcGVuYXRfbm9jYW5jZWwnXSwgWydpbnQnLCAnc3RyJywgJ2ludCddLCBmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICAgICAgdmFyIG9wZW5QYXRoID0gZGF0YS5hcmdzWzFdO1xuICAgICAgICAgICAgaWYgKGRhdGEuYXJnc1swXSAmJiBfdGhpcy5maWxlRGVzY3JpcHRvcnNbZGF0YS5hcmdzWzBdXSlcbiAgICAgICAgICAgICAgICBvcGVuUGF0aCA9IF90aGlzLmZpbGVEZXNjcmlwdG9yc1tkYXRhLmFyZ3NbMF1dICsgJy8nICsgb3BlblBhdGg7XG4gICAgICAgICAgICByZXBsYWNlRmlsZUhhbmRsZXIob3BlblBhdGgsIGRhdGEuYXJnc1syXSwgZGF0YSk7XG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgcmV0dXJuIEZpbGVIb29rcztcbn0oKSk7XG5leHBvcnRzLkZpbGVIb29rcyA9IEZpbGVIb29rcztcbmZ1bmN0aW9uIGxvZ0ZpbGUoZGF0YSwgcGF0aCwgY29uZmlkZW50KSB7XG4gICAgaWYgKGNvbmZpZGVudCA9PT0gdm9pZCAwKSB7IGNvbmZpZGVudCA9IHRydWU7IH1cbiAgICAoMCwgbG9nXzEubG9nKSh7XG4gICAgICAgIHR5cGU6ICdmaWxlJyxcbiAgICAgICAgY29udGV4dDogJ25hdGl2ZScsXG4gICAgICAgIFwiZnVuY3Rpb25cIjogZGF0YS5zeXNjYWxsLFxuICAgICAgICBhcmdzOiBkYXRhLmFyZ3MsXG4gICAgICAgIGNvbmZpZGVudDogY29uZmlkZW50LFxuICAgICAgICBmaWxlOiBwYXRoXG4gICAgfSwgZGF0YS5jb250ZXh0LmNvbnRleHQsIGRhdGEuZGV0ZWN0b3IpO1xufVxuIiwiXCJ1c2Ugc3RyaWN0XCI7XG52YXIgX19zcHJlYWRBcnJheSA9ICh0aGlzICYmIHRoaXMuX19zcHJlYWRBcnJheSkgfHwgZnVuY3Rpb24gKHRvLCBmcm9tLCBwYWNrKSB7XG4gICAgaWYgKHBhY2sgfHwgYXJndW1lbnRzLmxlbmd0aCA9PT0gMikgZm9yICh2YXIgaSA9IDAsIGwgPSBmcm9tLmxlbmd0aCwgYXI7IGkgPCBsOyBpKyspIHtcbiAgICAgICAgaWYgKGFyIHx8ICEoaSBpbiBmcm9tKSkge1xuICAgICAgICAgICAgaWYgKCFhcikgYXIgPSBBcnJheS5wcm90b3R5cGUuc2xpY2UuY2FsbChmcm9tLCAwLCBpKTtcbiAgICAgICAgICAgIGFyW2ldID0gZnJvbVtpXTtcbiAgICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gdG8uY29uY2F0KGFyIHx8IEFycmF5LnByb3RvdHlwZS5zbGljZS5jYWxsKGZyb20pKTtcbn07XG5leHBvcnRzLl9fZXNNb2R1bGUgPSB0cnVlO1xuZXhwb3J0cy5hZGRKYXZhUmVwbGFjZUhvb2sgPSBleHBvcnRzLmFkZEphdmFQb3N0SG9vayA9IGV4cG9ydHMuYWRkSmF2YVByZUhvb2sgPSB2b2lkIDA7XG52YXIgbG9nXzEgPSByZXF1aXJlKFwiLi4vaW5jL2xvZ1wiKTtcbnZhciBhcHBsaWVkSG9va3MgPSBbXTtcbi8qKlxuICogSG9vayBhIEphdmEgZnVuY3Rpb24gYmVmb3JlIGNhbGxpbmcgaXRzIG9yaWdpbmFsIGltcGxlbWVudGF0aW9uLCBhbGxvd2luZyBmb3IgdGhlIG1vZGlmaWNhdGlvbiBvZiBhcmd1bWVudHNcbiAqIEBwYXJhbSBmdW4gZnVuY3Rpb24gdG8gaG9va1xuICogQHBhcmFtIGFyZ1R5cGVzIHR5cGVzIG9mIHRoZSBhcmd1bWVudHMgb2YgdGhlIGZ1bmN0aW9uIHRvIGhvb2suIFVzZWQgdG8gZmluZCB0aGUgY29ycmVjdCBvdmVybG9hZCBvZiB0aGUgZnVuY3Rpb24uIElmIG51bGwsIHRoZSBmaXJzdCBvdmVybG9hZCBpcyB1c2VkXG4gKiBAcGFyYW0gaGFuZGxlciBjYWxsYmFjayBmdW5jdGlvbiB0byBjYWxsIGJlZm9yZSB0aGUgb3JpZ2luYWwgZnVuY3Rpb25cbiAqIEBwYXJhbSBpbml0SmF2YSB3aGV0aGVyIHRvIGluaXRpYWxpemUgSmF2YSBjb250ZXh0IGJlZm9yZSBob29raW5nLiBTZXQgdG8gZmFsc2UgaWYgeW91IGFyZSBhbHJlYWR5IGluIGEgSmF2YS5wZXJmb3JtKCkgYmxvY2tcbiAqIEBwYXJhbSBkZXRlY3RvciBkZXRlY3RvciB0aGF0IGNhbGxlZCB0aGlzIGZ1bmN0aW9uXG4gKi9cbmZ1bmN0aW9uIGFkZEphdmFQcmVIb29rKGZ1biwgYXJnVHlwZXMsIGhhbmRsZXIsIGluaXRKYXZhLCBkZXRlY3Rvcikge1xuICAgIGlmIChhcmdUeXBlcyA9PT0gdm9pZCAwKSB7IGFyZ1R5cGVzID0gbnVsbDsgfVxuICAgIGlmIChpbml0SmF2YSA9PT0gdm9pZCAwKSB7IGluaXRKYXZhID0gdHJ1ZTsgfVxuICAgIGlmIChkZXRlY3RvciA9PT0gdm9pZCAwKSB7IGRldGVjdG9yID0gbnVsbDsgfVxuICAgIGFkZEhvb2soZnVuLCAncHJlJywgYXJnVHlwZXMsIGhhbmRsZXIsIGluaXRKYXZhLCBkZXRlY3Rvcik7XG59XG5leHBvcnRzLmFkZEphdmFQcmVIb29rID0gYWRkSmF2YVByZUhvb2s7XG4vKipcbiAqIEhvb2sgYSBKYXZhIGZ1bmN0aW9uIGFmdGVyIGNhbGxpbmcgaXRzIG9yaWdpbmFsIGltcGxlbWVudGF0aW9uLCBhbGxvd2luZyBmb3IgdGhlIG1vZGlmaWNhdGlvbiBvZiB0aGUgcmV0dXJuIHZhbHVlXG4gKiBAcGFyYW0gZnVuIGZ1bmN0aW9uIHRvIGhvb2tcbiAqIEBwYXJhbSBhcmdUeXBlcyB0eXBlcyBvZiB0aGUgYXJndW1lbnRzIG9mIHRoZSBmdW5jdGlvbiB0byBob29rLiBVc2VkIHRvIGZpbmQgdGhlIGNvcnJlY3Qgb3ZlcmxvYWQgb2YgdGhlIGZ1bmN0aW9uLiBJZiBudWxsLCB0aGUgZmlyc3Qgb3ZlcmxvYWQgaXMgdXNlZFxuICogQHBhcmFtIGhhbmRsZXIgY2FsbGJhY2sgZnVuY3Rpb24gdG8gY2FsbCBhZnRlciB0aGUgb3JpZ2luYWwgZnVuY3Rpb25cbiAqIEBwYXJhbSBpbml0SmF2YSB3aGV0aGVyIHRvIGluaXRpYWxpemUgSmF2YSBjb250ZXh0IGJlZm9yZSBob29raW5nLiBTZXQgdG8gZmFsc2UgaWYgeW91IGFyZSBhbHJlYWR5IGluIGEgSmF2YS5wZXJmb3JtKCkgYmxvY2tcbiAqIEBwYXJhbSBkZXRlY3RvciBkZXRlY3RvciB0aGF0IGNhbGxlZCB0aGlzIGZ1bmN0aW9uXG4gKi9cbmZ1bmN0aW9uIGFkZEphdmFQb3N0SG9vayhmdW4sIGFyZ1R5cGVzLCBoYW5kbGVyLCBpbml0SmF2YSwgZGV0ZWN0b3IpIHtcbiAgICBpZiAoYXJnVHlwZXMgPT09IHZvaWQgMCkgeyBhcmdUeXBlcyA9IG51bGw7IH1cbiAgICBpZiAoaW5pdEphdmEgPT09IHZvaWQgMCkgeyBpbml0SmF2YSA9IHRydWU7IH1cbiAgICBpZiAoZGV0ZWN0b3IgPT09IHZvaWQgMCkgeyBkZXRlY3RvciA9IG51bGw7IH1cbiAgICBhZGRIb29rKGZ1biwgJ3Bvc3QnLCBhcmdUeXBlcywgaGFuZGxlciwgaW5pdEphdmEsIGRldGVjdG9yKTtcbn1cbmV4cG9ydHMuYWRkSmF2YVBvc3RIb29rID0gYWRkSmF2YVBvc3RIb29rO1xuLyoqXG4gKiBIb29rIGEgSmF2YSBmdW5jdGlvbiBhbmQgcmVwbGFjZSBpdHMgb3JpZ2luYWwgaW1wbGVtZW50YXRpb25cbiAqIEBwYXJhbSBmdW4gZnVuY3Rpb24gdG8gaG9va1xuICogQHBhcmFtIGFyZ1R5cGVzIHR5cGVzIG9mIHRoZSBhcmd1bWVudHMgb2YgdGhlIGZ1bmN0aW9uIHRvIGhvb2suIFVzZWQgdG8gZmluZCB0aGUgY29ycmVjdCBvdmVybG9hZCBvZiB0aGUgZnVuY3Rpb24uIElmIG51bGwsIHRoZSBmaXJzdCBvdmVybG9hZCBpcyB1c2VkXG4gKiBAcGFyYW0gaGFuZGxlciBjYWxsYmFjayBmdW5jdGlvbiB0byBjYWxsIGluc3RlYWQgb2YgdGhlIG9yaWdpbmFsIGZ1bmN0aW9uXG4gKiBAcGFyYW0gaW5pdEphdmEgd2hldGhlciB0byBpbml0aWFsaXplIEphdmEgY29udGV4dCBiZWZvcmUgaG9va2luZy4gU2V0IHRvIGZhbHNlIGlmIHlvdSBhcmUgYWxyZWFkeSBpbiBhIEphdmEucGVyZm9ybSgpIGJsb2NrXG4gKiBAcGFyYW0gZGV0ZWN0b3IgZGV0ZWN0b3IgdGhhdCBjYWxsZWQgdGhpcyBmdW5jdGlvblxuICovXG5mdW5jdGlvbiBhZGRKYXZhUmVwbGFjZUhvb2soZnVuLCBhcmdUeXBlcywgaGFuZGxlciwgaW5pdEphdmEsIGRldGVjdG9yKSB7XG4gICAgaWYgKGFyZ1R5cGVzID09PSB2b2lkIDApIHsgYXJnVHlwZXMgPSBudWxsOyB9XG4gICAgaWYgKGluaXRKYXZhID09PSB2b2lkIDApIHsgaW5pdEphdmEgPSB0cnVlOyB9XG4gICAgaWYgKGRldGVjdG9yID09PSB2b2lkIDApIHsgZGV0ZWN0b3IgPSBudWxsOyB9XG4gICAgYWRkSG9vayhmdW4sICdyZXBsYWNlJywgYXJnVHlwZXMsIGhhbmRsZXIsIGluaXRKYXZhLCBkZXRlY3Rvcik7XG59XG5leHBvcnRzLmFkZEphdmFSZXBsYWNlSG9vayA9IGFkZEphdmFSZXBsYWNlSG9vaztcbi8qKlxuICogSG9vayBhIEphdmEgZnVuY3Rpb25cbiAqIEBwYXJhbSBmdW4gZnVuY3Rpb24gdG8gaG9va1xuICogQHBhcmFtIHR5cGUgdHlwZSBvZiBob29rIHRvIGFkZFxuICogQHBhcmFtIGFyZ1R5cGVzIHR5cGVzIG9mIHRoZSBhcmd1bWVudHMgb2YgdGhlIGZ1bmN0aW9uIHRvIGhvb2suIFVzZWQgdG8gZmluZCB0aGUgY29ycmVjdCBvdmVybG9hZCBvZiB0aGUgZnVuY3Rpb24uIElmIG51bGwsIHRoZSBmaXJzdCBvdmVybG9hZCBpcyB1c2VkXG4gKiBAcGFyYW0gaGFuZGxlciBjYWxsYmFjayBmdW5jdGlvbiB0byBjYWxsIHdoZW4gaG9va2VkIGZ1bmN0aW9uIGlzIGNhbGxlZFxuICogQHBhcmFtIGluaXRKYXZhIHdoZXRoZXIgdG8gaW5pdGlhbGl6ZSBKYXZhIGNvbnRleHQgYmVmb3JlIGhvb2tpbmcuIFNldCB0byBmYWxzZSBpZiB5b3UgYXJlIGFscmVhZHkgaW4gYSBKYXZhLnBlcmZvcm0oKSBibG9ja1xuICogQHBhcmFtIGRldGVjdG9yIGRldGVjdG9yIHRoYXQgY2FsbGVkIHRoaXMgZnVuY3Rpb25cbiAqL1xuZnVuY3Rpb24gYWRkSG9vayhmdW4sIHR5cGUsIGFyZ1R5cGVzLCBoYW5kbGVyLCBpbml0SmF2YSwgZGV0ZWN0b3IpIHtcbiAgICBpZiAoaW5pdEphdmEgPT09IHZvaWQgMCkgeyBpbml0SmF2YSA9IHRydWU7IH1cbiAgICBpZiAoZGV0ZWN0b3IgPT09IHZvaWQgMCkgeyBkZXRlY3RvciA9IG51bGw7IH1cbiAgICBpZiAoZnVuID09ICdhbmRyb2lkLnByb3ZpZGVyLlNldHRpbmdzJFNlY3VyZTo6Z2V0U3RyaW5nJykge1xuICAgICAgICBbJ1NlY3VyZScsICdHbG9iYWwnXS5mb3JFYWNoKGZ1bmN0aW9uIChjbHMpIHtcbiAgICAgICAgICAgIFsnU3RyaW5nJywgJ0ludCcsICdMb25nJywgJ0Zsb2F0J10uZm9yRWFjaChmdW5jdGlvbiAodmFyVHlwZSkge1xuICAgICAgICAgICAgICAgIGlmICh2YXJUeXBlICE9PSAnU3RyaW5nJyB8fCBjbHMgPT09ICdHbG9iYWwnKSB7XG4gICAgICAgICAgICAgICAgICAgIGFkZEhvb2soXCJhbmRyb2lkLnByb3ZpZGVyLlNldHRpbmdzJFwiLmNvbmNhdChjbHMsIFwiOjpnZXRcIikuY29uY2F0KHZhclR5cGUpLCB0eXBlLCBhcmdUeXBlcywgaGFuZGxlcik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICh2YXJUeXBlICE9PSAnU3RyaW5nJykge1xuICAgICAgICAgICAgICAgICAgICBhZGRIb29rKFwiYW5kcm9pZC5wcm92aWRlci5TZXR0aW5ncyRcIi5jb25jYXQoY2xzLCBcIjo6Z2V0XCIpLmNvbmNhdCh2YXJUeXBlKSwgdHlwZSwgX19zcHJlYWRBcnJheShfX3NwcmVhZEFycmF5KFtdLCBhcmdUeXBlcywgdHJ1ZSksIFt2YXJUeXBlLnRvTG93ZXJDYXNlKCldLCBmYWxzZSksIGhhbmRsZXIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9KTtcbiAgICB9XG4gICAgaWYgKGZ1biBpbnN0YW5jZW9mIEFycmF5KSB7XG4gICAgICAgIC8vIEFkZCBob29rIGZvciBldmVyeSBzeXNjYWxsIGluIHRoZSBhcnJheVxuICAgICAgICBmdW4uZm9yRWFjaChmdW5jdGlvbiAoZikge1xuICAgICAgICAgICAgYWRkSG9vayhmLCB0eXBlLCBhcmdUeXBlcywgaGFuZGxlcik7XG4gICAgICAgIH0pO1xuICAgICAgICByZXR1cm47XG4gICAgfVxuICAgIGlmICh0eXBlb2YgZnVuICE9PSAnc3RyaW5nJykge1xuICAgICAgICAvLyBBc3N1bWUgSmF2YSBhbHJlYWR5IGluaXRpYWxpemVkIGFuZCB3ZSBhcmUgaW4gYSBKYXZhLnBlcmZvcm0oKSBibG9ja1xuICAgICAgICBpbml0SmF2YSA9IGZhbHNlO1xuICAgIH1cbiAgICBpZiAoaW5pdEphdmEgJiYgIUphdmEuYXZhaWxhYmxlKSB7XG4gICAgICAgIHJldHVybjtcbiAgICB9XG4gICAgLy8gUmVwbGFjZSBhcmdUeXBlICdzdHInIHdpdGggJ2phdmEubGFuZy5TdHJpbmcnICBhbmQgJ1tdJyB3aXRoICdbTC4uLjsnXG4gICAgaWYgKGFyZ1R5cGVzKSB7XG4gICAgICAgIGFyZ1R5cGVzID0gYXJnVHlwZXMubWFwKGZ1bmN0aW9uIChhcmdUeXBlKSB7XG4gICAgICAgICAgICBpZiAoYXJnVHlwZSA9PT0gJ3N0cicpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gJ2phdmEubGFuZy5TdHJpbmcnO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZWxzZSBpZiAoYXJnVHlwZSA9PT0gJ3N0cltdJykge1xuICAgICAgICAgICAgICAgIHJldHVybiAnW0xqYXZhLmxhbmcuU3RyaW5nOyc7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlIGlmIChhcmdUeXBlLmVuZHNXaXRoKCdbXScpKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIFwiW0xcIi5jb25jYXQoYXJnVHlwZS5zbGljZSgwLCAtMiksIFwiO1wiKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgIHJldHVybiBhcmdUeXBlO1xuICAgICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICB9XG4gICAgaWYgKGluaXRKYXZhICYmICFkZXRlY3Rvcikge1xuICAgICAgICBkZXRlY3RvciA9ICgwLCBsb2dfMS5nZXREZXRlY3RvcikoKTtcbiAgICB9XG4gICAgdmFyIG92ZXJ3cml0ZUZ1bmN0aW9uID0gZnVuY3Rpb24gKCkge1xuICAgICAgICB2YXIgamF2YUZ1bjtcbiAgICAgICAgdmFyIGZ1bk5hbWUgPSBudWxsO1xuICAgICAgICBpZiAodHlwZW9mIGZ1biA9PT0gJ3N0cmluZycpIHtcbiAgICAgICAgICAgIHZhciBjbHMgPSBmdW4uc3BsaXQoJzo6JylbMF07XG4gICAgICAgICAgICB2YXIgbmFtZV8xID0gZnVuLnNwbGl0KCc6OicpWzFdO1xuICAgICAgICAgICAgdmFyIGphdmFDbHMgPSB2b2lkIDA7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIGphdmFDbHMgPSBKYXZhLnVzZShjbHMpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgY2F0Y2ggKGUpIHtcbiAgICAgICAgICAgICAgICAoMCwgbG9nXzEuZGVidWcpKFwiWyFdIFVuYWJsZSB0byBmaW5kIGNsYXNzIFwiLmNvbmNhdChjbHMsIFwiIGluIEphdmFcIikpO1xuICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGphdmFGdW4gPSBqYXZhQ2xzW25hbWVfMV07XG4gICAgICAgICAgICBpZiAoIWphdmFGdW4pIHtcbiAgICAgICAgICAgICAgICAoMCwgbG9nXzEuZGVidWcpKFwiWyFdIFVuYWJsZSB0byBmaW5kIGZ1bmN0aW9uIFwiLmNvbmNhdChmdW4sIFwiIGluIEphdmFcIikpO1xuICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGZ1bk5hbWUgPSBmdW4ucmVwbGFjZSgnJCcsICcuJyk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICBqYXZhRnVuID0gZnVuO1xuICAgICAgICB9XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICBpZiAoYXJnVHlwZXMgIT09IG51bGwpIHtcbiAgICAgICAgICAgICAgICBqYXZhRnVuID0gamF2YUZ1bi5vdmVybG9hZC5hcHBseShqYXZhRnVuLCBhcmdUeXBlcyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAoIWphdmFGdW4pIHtcbiAgICAgICAgICAgICAgICAoMCwgbG9nXzEuZGVidWcpKFwiWyFdIFVuYWJsZSB0byBmaW5kIG92ZXJsb2FkIG9mIGZ1bmN0aW9uIFwiLmNvbmNhdChmdW4sIFwiIGluIEphdmFcIikpO1xuICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICBjYXRjaCAoZSkge1xuICAgICAgICAgICAgKDAsIGxvZ18xLmRlYnVnKShcIlshXSBVbmFibGUgdG8gZmluZCBmdW5jdGlvbiBcIi5jb25jYXQoZnVuLCBcIiB3aXRoIGFyZ1R5cGVzIFwiKS5jb25jYXQoYXJnVHlwZXMsIFwiIGluIEphdmFcIikpO1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG4gICAgICAgIHZhciBpc0hvb2tlZCA9IGFwcGxpZWRIb29rcy5maW5kKGZ1bmN0aW9uIChob29rKSB7IHJldHVybiBob29rLmphdmFGdW4gPT09IGphdmFGdW47IH0pO1xuICAgICAgICBhcHBsaWVkSG9va3MucHVzaCh7IGphdmFGdW46IGphdmFGdW4sIHR5cGU6IHR5cGUsIGhhbmRsZXI6IGhhbmRsZXIsIGRldGVjdG9yOiBkZXRlY3RvciB9KTtcbiAgICAgICAgaWYgKCFpc0hvb2tlZCkge1xuICAgICAgICAgICAgamF2YUZ1bi5pbXBsZW1lbnRhdGlvbiA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICAgICAgICAgIHZhciBhcmdzID0gW107XG4gICAgICAgICAgICAgICAgZm9yICh2YXIgX2kgPSAwOyBfaSA8IGFyZ3VtZW50cy5sZW5ndGg7IF9pKyspIHtcbiAgICAgICAgICAgICAgICAgICAgYXJnc1tfaV0gPSBhcmd1bWVudHNbX2ldO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB2YXIgdHJhY2UgPSBKYXZhLnVzZSgnamF2YS5sYW5nLkV4Y2VwdGlvbicpLiRuZXcoKS5nZXRTdGFja1RyYWNlKCk7XG4gICAgICAgICAgICAgICAgaWYgKCFmdW5OYW1lKSB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBtZXRob2QgPSB0cmFjZVswXTtcbiAgICAgICAgICAgICAgICAgICAgZnVuTmFtZSA9IG1ldGhvZC5nZXRDbGFzc05hbWUoKS5yZXBsYWNlKCckJywgJy4nKSArIFwiOjpcIiArIG1ldGhvZC5nZXRNZXRob2ROYW1lKCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHZhciBiYWNrdHJhY2UgPSB0cmFjZS5tYXAoZnVuY3Rpb24gKGUpIHsgcmV0dXJuIGUudG9TdHJpbmcoKS50cmltKCk7IH0pO1xuICAgICAgICAgICAgICAgIHZhciBob29rcyA9IGFwcGxpZWRIb29rcy5maWx0ZXIoZnVuY3Rpb24gKGhvb2spIHsgcmV0dXJuIGhvb2suamF2YUZ1biA9PT0gamF2YUZ1bjsgfSk7XG4gICAgICAgICAgICAgICAgdmFyIHJlcGxhY2VkID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgdmFyIHJldHZhbDtcbiAgICAgICAgICAgICAgICBob29rcy5mb3JFYWNoKGZ1bmN0aW9uIChob29rKSB7XG4gICAgICAgICAgICAgICAgICAgIGlmIChob29rLnR5cGUgPT09ICdyZXBsYWNlJykge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGRhdGEgPSB7IGZ1bjogamF2YUZ1biwgZnVuTmFtZTogZnVuTmFtZSwgYXJnczogYXJncywgXCJ0aGlzXCI6IF90aGlzLCBkZXRlY3RvcjogaG9vay5kZXRlY3RvciwgYmFja3RyYWNlOiBiYWNrdHJhY2UgfTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHZhbCA9IGhvb2suaGFuZGxlcihkYXRhKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJlcGxhY2VkID0gdHJ1ZTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgIGlmIChyZXBsYWNlZCkge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gcmV0dmFsO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBob29rcy5mb3JFYWNoKGZ1bmN0aW9uIChob29rKSB7XG4gICAgICAgICAgICAgICAgICAgIGlmIChob29rLnR5cGUgPT09ICdwcmUnKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgZGF0YSA9IHsgZnVuOiBqYXZhRnVuLCBmdW5OYW1lOiBmdW5OYW1lLCBhcmdzOiBhcmdzLCBcInRoaXNcIjogX3RoaXMsIGRldGVjdG9yOiBob29rLmRldGVjdG9yLCBiYWNrdHJhY2U6IGJhY2t0cmFjZSB9O1xuICAgICAgICAgICAgICAgICAgICAgICAgaG9vay5oYW5kbGVyKGRhdGEpO1xuICAgICAgICAgICAgICAgICAgICAgICAgLy8gQ29udmVydCBhbnkgc3RyaW5nIGFyZ3MgdG8gSmF2YS5sYW5nLlN0cmluZ1xuICAgICAgICAgICAgICAgICAgICAgICAgYXJncy5tYXAoZnVuY3Rpb24gKGFyZykgeyByZXR1cm4gYXJnIGluc3RhbmNlb2YgU3RyaW5nID8gSmF2YS51c2UoJ2phdmEubGFuZy5TdHJpbmcnKS4kbmV3KGFyZykgOiBhcmc7IH0pO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgcmV0dmFsID0gamF2YUZ1bi5jYWxsLmFwcGx5KGphdmFGdW4sIF9fc3ByZWFkQXJyYXkoW3RoaXNdLCBhcmdzLCBmYWxzZSkpO1xuICAgICAgICAgICAgICAgIHZhciBvcmlnaW5hbFJldHZhbCA9IHJldHZhbDtcbiAgICAgICAgICAgICAgICBob29rcy5mb3JFYWNoKGZ1bmN0aW9uIChob29rKSB7XG4gICAgICAgICAgICAgICAgICAgIGlmIChob29rLnR5cGUgPT09ICdwb3N0Jykge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGRhdGEgPSB7IGZ1bjogamF2YUZ1biwgZnVuTmFtZTogZnVuTmFtZSwgYXJnczogYXJncywgXCJ0aGlzXCI6IF90aGlzLCByZXR2YWw6IHJldHZhbCwgZGV0ZWN0b3I6IGhvb2suZGV0ZWN0b3IsIGJhY2t0cmFjZTogYmFja3RyYWNlIH07XG4gICAgICAgICAgICAgICAgICAgICAgICBob29rLmhhbmRsZXIoZGF0YSk7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAoZGF0YS5yZXR2YWwgIT09IG9yaWdpbmFsUmV0dmFsKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dmFsID0gZGF0YS5yZXR2YWw7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICByZXR1cm4gcmV0dmFsO1xuICAgICAgICAgICAgfTtcbiAgICAgICAgfVxuICAgIH07XG4gICAgaWYgKGluaXRKYXZhKSB7XG4gICAgICAgIEphdmEucGVyZm9ybShvdmVyd3JpdGVGdW5jdGlvbik7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICBvdmVyd3JpdGVGdW5jdGlvbigpO1xuICAgIH1cbn1cbiIsIlwidXNlIHN0cmljdFwiO1xudmFyIF9fc3ByZWFkQXJyYXkgPSAodGhpcyAmJiB0aGlzLl9fc3ByZWFkQXJyYXkpIHx8IGZ1bmN0aW9uICh0bywgZnJvbSwgcGFjaykge1xuICAgIGlmIChwYWNrIHx8IGFyZ3VtZW50cy5sZW5ndGggPT09IDIpIGZvciAodmFyIGkgPSAwLCBsID0gZnJvbS5sZW5ndGgsIGFyOyBpIDwgbDsgaSsrKSB7XG4gICAgICAgIGlmIChhciB8fCAhKGkgaW4gZnJvbSkpIHtcbiAgICAgICAgICAgIGlmICghYXIpIGFyID0gQXJyYXkucHJvdG90eXBlLnNsaWNlLmNhbGwoZnJvbSwgMCwgaSk7XG4gICAgICAgICAgICBhcltpXSA9IGZyb21baV07XG4gICAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIHRvLmNvbmNhdChhciB8fCBBcnJheS5wcm90b3R5cGUuc2xpY2UuY2FsbChmcm9tKSk7XG59O1xuZXhwb3J0cy5fX2VzTW9kdWxlID0gdHJ1ZTtcbmV4cG9ydHMuY29udmVydEFyZ3MgPSBleHBvcnRzLmdldEFwcGxpZWRIb29rcyA9IGV4cG9ydHMuYWRkUG9zdEhvb2sgPSBleHBvcnRzLmFkZFByZUhvb2sgPSB2b2lkIDA7XG52YXIgbG9nXzEgPSByZXF1aXJlKFwiLi4vaW5jL2xvZ1wiKTtcbnZhciBhcHBsaWVkSG9va3MgPSB7fTtcbi8qKlxuICogQWRkIGEgbmV3IGhvb2sgdG8gdGhlIGdpdmVuIHN5c2NhbGwocykgd2l0aCBhIGhhbmRsZXIgdGhhdCBpcyBjYWxsZWQgYmVmb3JlIHRoZSBzeXNjYWxsIGlzIGV4ZWN1dGVkIChvbkVudGVyKVxuICogQHBhcmFtIHN5c2NhbGxzIHN5c2NhbGwgb3IgbGlzdCBvZiBzeXNjYWxscyB0byBpbnRlcmNlcHRcbiAqIEBwYXJhbSBhcmdUeXBlcyBsaXN0IG9mIHR5cGVzIHRoZSBhcmd1bWVudHMgc2hvdWxkIGJlIGNvbnZlcnRlZCB0b1xuICogQHBhcmFtIGhhbmRsZXIgaGFuZGxlciB0byBjYWxsIHdoZW4gdGhlIHN5c2NhbGwgaXMgaW50ZXJjZXB0ZWRcbiAqIEBwYXJhbSBtb2QgbW9kdWxlIHRvIHNlYXJjaCBmb3IgdGhlIHN5c2NhbGwgaW4gKGRlZmF1bHRzIHRvIG51bGwgb24gbWFjT1MsIGxpYmMuc28gb24gQW5kcm9pZClcbiAqL1xuZnVuY3Rpb24gYWRkUHJlSG9vayhzeXNjYWxscywgYXJnVHlwZXMsIGhhbmRsZXIsIG1vZCkge1xuICAgIGlmIChhcmdUeXBlcyA9PT0gdm9pZCAwKSB7IGFyZ1R5cGVzID0gbnVsbDsgfVxuICAgIGlmIChtb2QgPT09IHZvaWQgMCkgeyBtb2QgPSBudWxsOyB9XG4gICAgYWRkSG9vayhzeXNjYWxscywgJ3ByZScsIGFyZ1R5cGVzLCBoYW5kbGVyLCBtb2QpO1xufVxuZXhwb3J0cy5hZGRQcmVIb29rID0gYWRkUHJlSG9vaztcbi8qKlxuICogQWRkIGEgbmV3IGhvb2sgdG8gdGhlIGdpdmVuIHN5c2NhbGwocykgd2l0aCBhIGhhbmRsZXIgdGhhdCBpcyBjYWxsZWQgYWZ0ZXIgdGhlIHN5c2NhbGwgaGFzIHJldHVybmVkIChvbkxlYXZlKVxuICogQHBhcmFtIHN5c2NhbGxzIHN5c2NhbGwgb3IgbGlzdCBvZiBzeXNjYWxscyB0byBpbnRlcmNlcHRcbiAqIEBwYXJhbSBhcmdUeXBlcyBsaXN0IG9mIHR5cGVzIHRoZSBhcmd1bWVudHMgc2hvdWxkIGJlIGNvbnZlcnRlZCB0b1xuICogQHBhcmFtIGhhbmRsZXIgaGFuZGxlciB0byBjYWxsIHdoZW4gdGhlIHN5c2NhbGwgaGFzIHJldHVybmVkXG4gKiBAcGFyYW0gbW9kIG1vZHVsZSB0byBzZWFyY2ggZm9yIHRoZSBzeXNjYWxsIGluIChkZWZhdWx0cyB0byBudWxsIG9uIG1hY09TLCBsaWJjLnNvIG9uIEFuZHJvaWQpXG4gKi9cbmZ1bmN0aW9uIGFkZFBvc3RIb29rKHN5c2NhbGxzLCBhcmdUeXBlcywgaGFuZGxlciwgbW9kKSB7XG4gICAgaWYgKGFyZ1R5cGVzID09PSB2b2lkIDApIHsgYXJnVHlwZXMgPSBudWxsOyB9XG4gICAgaWYgKG1vZCA9PT0gdm9pZCAwKSB7IG1vZCA9IG51bGw7IH1cbiAgICBhZGRIb29rKHN5c2NhbGxzLCAncG9zdCcsIGFyZ1R5cGVzLCBoYW5kbGVyLCBtb2QpO1xufVxuZXhwb3J0cy5hZGRQb3N0SG9vayA9IGFkZFBvc3RIb29rO1xuLyoqXG4gKiBBZGQgYSBuZXcgaG9vayB0byB0aGUgZ2l2ZW4gc3lzY2FsbChzKVxuICogQHBhcmFtIHN5c2NhbGwgc3lzY2FsbCBvciBsaXN0IG9mIHN5c2NhbGxzIHRvIGludGVyY2VwdFxuICogQHBhcmFtIHR5cGUgY2FsbCBoYW5kbGVyIGVpdGhlciBvbiBvbkVudGVyIChwcmUpIG9yIG9uTGVhdmUgKHBvc3QpXG4gKiBAcGFyYW0gYXJnVHlwZXMgbGlzdCBvZiB0eXBlcyB0aGUgYXJndW1lbnRzIHNob3VsZCBiZSBjb252ZXJ0ZWQgdG9cbiAqIEBwYXJhbSBoYW5kbGVyIGhhbmRsZXIgdG8gY2FsbCB3aGVuIHRoZSBzeXNjYWxsIGlzIGludGVyY2VwdGVkXG4gKiBAcGFyYW0gbW9kIG1vZHVsZSB0byBzZWFyY2ggZm9yIHRoZSBzeXNjYWxsIGluIChkZWZhdWx0cyB0byBudWxsIG9uIG1hY09TLCBsaWJjLnNvIG9uIEFuZHJvaWQpXG4gKi9cbmZ1bmN0aW9uIGFkZEhvb2soc3lzY2FsbCwgdHlwZSwgYXJnVHlwZXMsIGhhbmRsZXIsIG1vZCkge1xuICAgIGlmIChtb2QgPT09IHZvaWQgMCkgeyBtb2QgPSBudWxsOyB9XG4gICAgaWYgKHN5c2NhbGwgaW5zdGFuY2VvZiBBcnJheSkge1xuICAgICAgICAvLyBBZGQgaG9vayBmb3IgZXZlcnkgc3lzY2FsbCBpbiB0aGUgYXJyYXlcbiAgICAgICAgc3lzY2FsbC5mb3JFYWNoKGZ1bmN0aW9uIChzKSB7XG4gICAgICAgICAgICBhZGRIb29rKHMsIHR5cGUsIGFyZ1R5cGVzLCBoYW5kbGVyKTtcbiAgICAgICAgfSk7XG4gICAgICAgIHJldHVybjtcbiAgICB9XG4gICAgLy8gQWxzbyBhZGQgYSBob29rIGZvciB0aGUgNjQgYml0IHZlcnNpb24gb2YgdGhlIHN5c2NhbGxcbiAgICBpZiAoIXN5c2NhbGwuZW5kc1dpdGgoJzY0JykpXG4gICAgICAgIGFkZEhvb2soc3lzY2FsbCArICc2NCcsIHR5cGUsIGFyZ1R5cGVzLCBoYW5kbGVyKTtcbiAgICBpZiAobW9kID09PSBudWxsKSB7XG4gICAgICAgIC8vIE9uIGlPUywgdGhlIHN5c2NhbGxzIGFyZSBzcHJlYWQgb3ZlciBtdWx0aXBsZSBtb2R1bGVzIHNvIHdlIGxldCBGcmlkYSBmaW5kIHRoZSBjb3JyZWN0IG1vZHVsZVxuICAgICAgICBtb2QgPSBQcm9jZXNzLnBsYXRmb3JtID09PSAnZGFyd2luJyA/IG51bGwgOiAnbGliYy5zbyc7XG4gICAgfVxuICAgIHZhciBzeXNjYWxsUG9pbnRlciA9IE1vZHVsZS5maW5kRXhwb3J0QnlOYW1lKG1vZCwgc3lzY2FsbCk7XG4gICAgaWYgKHN5c2NhbGxQb2ludGVyID09PSBudWxsKSB7XG4gICAgICAgIGlmICghc3lzY2FsbC5lbmRzV2l0aCgnNjQnKSkge1xuICAgICAgICAgICAgdmFyIGFuZHJvaWRPbmx5U3lzY2FsbHMgPSBbJ2FuZHJvaWRfZmRzYW5fY2xvc2Vfd2l0aF90YWcnLCAnYW5kcm9pZF9mZHNhbl9zZXRfb3duZXJfdGFnJywgJ3JlYWRkaXI2NF9yJywgJ2V4ZWN2cGUnXTtcbiAgICAgICAgICAgIGlmIChQcm9jZXNzLnBsYXRmb3JtID09ICdkYXJ3aW4nICYmIGFuZHJvaWRPbmx5U3lzY2FsbHMuaW5kZXhPZihzeXNjYWxsKSA+PSAwKVxuICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICgwLCBsb2dfMS5kZWJ1ZykoXCJbIV0gVW5hYmxlIHRvIGZpbmQgc3lzY2FsbFwiLCBzeXNjYWxsKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm47XG4gICAgfVxuICAgIHZhciBkZXRlY3RvciA9ICgwLCBsb2dfMS5nZXREZXRlY3RvcikoKTtcbiAgICBpZiAoYXBwbGllZEhvb2tzW3N5c2NhbGxdID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgLy8gV2Ugb25seSBhcHBseSBvbmUgaG9vayB0byBhIHN5c2NhbGwgYmVjYXVzZSB3ZSBnZXQgdW5kZWZpbmVkIGJlaGF2aW91ciB3aGVuIHdlIGF0dGFjaCBtdWx0aXBsZSB0aW1lc1xuICAgICAgICBhcHBsaWVkSG9va3Nbc3lzY2FsbF0gPSBbXTtcbiAgICAgICAgYXBwbGllZEhvb2tzW3N5c2NhbGxdLnB1c2goeyBzeXNjYWxsOiBzeXNjYWxsLCB0eXBlOiB0eXBlLCBhcmdUeXBlczogYXJnVHlwZXMsIGhhbmRsZXI6IGhhbmRsZXIsIGRldGVjdG9yOiBkZXRlY3RvciwgYXJnczogbnVsbCB9KTtcbiAgICAgICAgSW50ZXJjZXB0b3IuYXR0YWNoKHN5c2NhbGxQb2ludGVyLCB7XG4gICAgICAgICAgICBvbkVudGVyOiBmdW5jdGlvbiAoYXJncykge1xuICAgICAgICAgICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgICAgICAgICAgdmFyIGhvb2tzID0gYXBwbGllZEhvb2tzW3N5c2NhbGxdO1xuICAgICAgICAgICAgICAgIGhvb2tzLmZvckVhY2goZnVuY3Rpb24gKGhvb2spIHtcbiAgICAgICAgICAgICAgICAgICAgLy8gU2F2ZSBhcmd1bWVudHMgZm9yIHBvc3QgaG9va1xuICAgICAgICAgICAgICAgICAgICBob29rLmFyZ3MgPSBjb252ZXJ0QXJncyhhcmdzLCBob29rLmFyZ1R5cGVzLCBzeXNjYWxsKTtcbiAgICAgICAgICAgICAgICAgICAgaWYgKGhvb2sudHlwZSA9PT0gJ3ByZScpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBob29rQXJncyA9IF9fc3ByZWFkQXJyYXkoW10sIGhvb2suYXJncywgdHJ1ZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgZGF0YSA9IHsgYXJnczogaG9vay5hcmdzLCBzeXNjYWxsOiBzeXNjYWxsLCBjb250ZXh0OiBfdGhpcywgZGV0ZWN0b3I6IGhvb2suZGV0ZWN0b3IgfTtcbiAgICAgICAgICAgICAgICAgICAgICAgIGhvb2suaGFuZGxlcihkYXRhKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIC8vIFJlcGxhY2UgYXJndW1lbnRzIGlmIHRoZXkgd2VyZSBjaGFuZ2VkXG4gICAgICAgICAgICAgICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGhvb2tBcmdzLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGhvb2tBcmdzW2ldICE9PSBob29rLmFyZ3NbaV0pIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gSWYgc3RyaW5nLCB1c2UgTWVtb3J5LmFsbG9jVXRmOFN0cmluZ1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAodHlwZW9mIGhvb2suYXJnc1tpXSA9PT0gJ3N0cmluZycpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFyZ3NbaV0gPSBNZW1vcnkuYWxsb2NVdGY4U3RyaW5nKGhvb2suYXJnc1tpXSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZSBpZiAodHlwZW9mIGhvb2suYXJnc1tpXSA9PT0gJ251bWJlcicpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChob29rLmFyZ1R5cGVzW2ldID09PSAndWludCcgfHwgaG9vay5hcmdUeXBlc1tpXSA9PT0gJ2ludCcpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhcmdzW2ldID0gcHRyKGhvb2suYXJnc1tpXSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlIGlmIChob29rLmFyZ1R5cGVzW2ldID09PSAnbG9uZycpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhcmdzW2ldLndyaXRlTG9uZyhob29rLmFyZ3NbaV0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYXJnc1tpXSA9IGhvb2suYXJnc1tpXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIG9uTGVhdmU6IGZ1bmN0aW9uIChyZXR2YWwpIHtcbiAgICAgICAgICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICAgICAgICAgIHZhciBob29rcyA9IGFwcGxpZWRIb29rc1tzeXNjYWxsXTtcbiAgICAgICAgICAgICAgICBob29rcy5mb3JFYWNoKGZ1bmN0aW9uIChob29rKSB7XG4gICAgICAgICAgICAgICAgICAgIGlmIChob29rLnR5cGUgIT09ICdwb3N0JylcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgdmFyIGRhdGEgPSB7IGFyZ3M6IGhvb2suYXJncywgcmV0dmFsOiByZXR2YWwsIHN5c2NhbGw6IHN5c2NhbGwsIGNvbnRleHQ6IF90aGlzLCBkZXRlY3RvcjogaG9vay5kZXRlY3RvciB9O1xuICAgICAgICAgICAgICAgICAgICBob29rLmhhbmRsZXIoZGF0YSk7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgYXBwbGllZEhvb2tzW3N5c2NhbGxdLnB1c2goeyBzeXNjYWxsOiBzeXNjYWxsLCB0eXBlOiB0eXBlLCBhcmdUeXBlczogYXJnVHlwZXMsIGhhbmRsZXI6IGhhbmRsZXIsIGRldGVjdG9yOiBkZXRlY3RvciwgYXJnczogbnVsbCB9KTtcbiAgICB9XG59XG4vKipcbiAqIEdldCBhIGxpc3Qgb2YgYWxsIHRoZSBob29rZWQgbmF0aXZlIGZ1bmN0aW9uc1xuICogQHJldHVybnMgbGlzdCBvZiBhbGwgdGhlIGhvb2tlZCBuYXRpdmUgZnVuY3Rpb25zIGFzIGEgZGljdGlvbmFyeSBtYXBwaW5nIHRoZSBzeXNjYWxsIG5hbWUgdG8gdGhlIGhvb2tcbiAqL1xuZnVuY3Rpb24gZ2V0QXBwbGllZEhvb2tzKCkge1xuICAgIHJldHVybiBhcHBsaWVkSG9va3M7XG59XG5leHBvcnRzLmdldEFwcGxpZWRIb29rcyA9IGdldEFwcGxpZWRIb29rcztcbi8qKlxuICogQ29udmVydCBhcmd1bWVudHMgZnJvbSBOYXRpdmVQb2ludGVycyB0byB0aGUgZ2l2ZW4gdHlwZXNcbiAqIEBwYXJhbSBhcmdzIGFyZ3VtZW50cyBhcyBhIGxpc3Qgb2YgTmF0aXZlUG9pbnRlcnNcbiAqIEBwYXJhbSBhcmdUeXBlcyB0eXBlcyB0aGUgYXJndW1lbnRzIG5lZWQgdG8gYmUgY29udmVydGVkIHRvLCBpbmRleGVzIGNvcnJlc3BvbmQgd2l0aCBlbGVtZW50cyBpbiBhcmdzXG4gKiBAcGFyYW0gc3lzY2FsbCB0aGUgc3lzY2FsbCBmb3Igd2hpY2ggdGhlIGFyZ3VtZW50cyBhcmUgY29udmVydGVkXG4gKiBAcmV0dXJucyBsaXN0IG9mIGNvbnZlcnRlZCBhcmd1bWVudHNcbiAqL1xuZnVuY3Rpb24gY29udmVydEFyZ3MoYXJncywgYXJnVHlwZXMsIHN5c2NhbGwpIHtcbiAgICBpZiAoYXJnVHlwZXMgPT09IG51bGwpXG4gICAgICAgIHJldHVybiBhcmdzO1xuICAgIHZhciBjb252ZXJ0ZWRBcmdzID0gW107XG4gICAgLy8gQ29udmVydCBhcmd1bWVudCB0eXBlc1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYXJnVHlwZXMubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIHN3aXRjaCAoYXJnVHlwZXNbaV0pIHtcbiAgICAgICAgICAgICAgICBjYXNlICdzdHInOlxuICAgICAgICAgICAgICAgICAgICBjb252ZXJ0ZWRBcmdzLnB1c2goYXJnc1tpXS5yZWFkQ1N0cmluZygpKTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgY2FzZSAndWludCc6XG4gICAgICAgICAgICAgICAgICAgIGNvbnZlcnRlZEFyZ3MucHVzaChhcmdzW2ldLnRvVUludDMyKCkpO1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBjYXNlICdpbnQnOlxuICAgICAgICAgICAgICAgICAgICBjb252ZXJ0ZWRBcmdzLnB1c2goYXJnc1tpXS50b0ludDMyKCkpO1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBjYXNlICdsb25nJzpcbiAgICAgICAgICAgICAgICAgICAgY29udmVydGVkQXJncy5wdXNoKGFyZ3NbaV0ucmVhZExvbmcoKSk7XG4gICAgICAgICAgICAgICAgY2FzZSAncHRyJzpcbiAgICAgICAgICAgICAgICAgICAgY29udmVydGVkQXJncy5wdXNoKGFyZ3NbaV0pO1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBjYXNlICdzdHJbXSc6XG4gICAgICAgICAgICAgICAgICAgIGNvbnZlcnRlZEFyZ3MucHVzaChbXSk7XG4gICAgICAgICAgICAgICAgICAgIHZhciBhcnJheUkgPSAwO1xuICAgICAgICAgICAgICAgICAgICB3aGlsZSAoIWFyZ3NbaV0uYWRkKGFycmF5SSkucmVhZFBvaW50ZXIoKS5pc051bGwoKSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgY29udmVydGVkQXJnc1tpXS5wdXNoKGFyZ3NbaV0uYWRkKGFycmF5SSkucmVhZFBvaW50ZXIoKS5yZWFkQ1N0cmluZygpKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIGFycmF5SSArPSBQcm9jZXNzLnBvaW50ZXJTaXplO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgKDAsIGxvZ18xLmRlYnVnKShcImFyZ1R5cGVcIiwgYXJnVHlwZXNbaV0sIFwiaXMgbm90IGltcGxlbWVudGVkXCIpO1xuICAgICAgICAgICAgICAgICAgICBjb252ZXJ0ZWRBcmdzLnB1c2gobnVsbCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2ggKGUpIHtcbiAgICAgICAgICAgIGNvbnZlcnRlZEFyZ3MucHVzaChudWxsKTtcbiAgICAgICAgICAgIGlmIChlLnRvU3RyaW5nKCkuaW5kZXhPZihcImFjY2VzcyB2aW9sYXRpb25cIikgIT0gLTEpXG4gICAgICAgICAgICAgICAgY29udGludWU7XG4gICAgICAgICAgICAoMCwgbG9nXzEuZGVidWcpKFwiRmFpbGVkIHRvIGNvbnZlcnQgYXJndW1lbnRcIiwgaSwgXCJvZiBzeXNjYWxsXCIsIHN5c2NhbGwsIFwiOlwiLCBlKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gY29udmVydGVkQXJncztcbn1cbmV4cG9ydHMuY29udmVydEFyZ3MgPSBjb252ZXJ0QXJncztcbiIsIlwidXNlIHN0cmljdFwiO1xuZXhwb3J0cy5fX2VzTW9kdWxlID0gdHJ1ZTtcbmV4cG9ydHMuYWRkT2JqQ1Bvc3RIb29rID0gZXhwb3J0cy5hZGRPYmpDUHJlSG9vayA9IHZvaWQgMDtcbnZhciBsb2dfMSA9IHJlcXVpcmUoXCIuLi9pbmMvbG9nXCIpO1xudmFyIGFwcGxpZWRIb29rcyA9IFtdO1xuLyoqXG4gKiBIb29rIGFuIE9iamVjdGl2ZS1DIGZ1bmN0aW9uIGJlZm9yZSBjYWxsaW5nIGl0cyBvcmlnaW5hbCBpbXBsZW1lbnRhdGlvbiwgYWxsb3dpbmcgZm9yIHRoZSBtb2RpZmljYXRpb24gb2YgYXJndW1lbnRzXG4gKiBAcGFyYW0gZnVuIGZ1bmN0aW9uIHRvIGhvb2tcbiAqIEBwYXJhbSBhcmdDb3VudCBudW1iZXIgb2YgYXJndW1lbnRzIHRoZSBmdW5jdGlvbiB0YWtlc1xuICogQHBhcmFtIGhhbmRsZXIgY2FsbGJhY2sgZnVuY3Rpb24gdG8gY2FsbCBiZWZvcmUgdGhlIG9yaWdpbmFsIGZ1bmN0aW9uXG4gKiBAcGFyYW0gZGV0ZWN0b3IgZGV0ZWN0b3IgdGhhdCBjYWxsZWQgdGhpcyBmdW5jdGlvblxuICovXG5mdW5jdGlvbiBhZGRPYmpDUHJlSG9vayhmdW4sIGFyZ0NvdW50LCBoYW5kbGVyLCBkZXRlY3Rvcikge1xuICAgIGlmIChkZXRlY3RvciA9PT0gdm9pZCAwKSB7IGRldGVjdG9yID0gbnVsbDsgfVxuICAgIGFkZEhvb2soZnVuLCBhcmdDb3VudCwgJ3ByZScsIGhhbmRsZXIsIGRldGVjdG9yKTtcbn1cbmV4cG9ydHMuYWRkT2JqQ1ByZUhvb2sgPSBhZGRPYmpDUHJlSG9vaztcbi8qKlxuICogSG9vayBhbiBPYmplY3RpdmUtQyBmdW5jdGlvbiBhZnRlciBjYWxsaW5nIGl0cyBvcmlnaW5hbCBpbXBsZW1lbnRhdGlvbiwgYWxsb3dpbmcgZm9yIHRoZSBtb2RpZmljYXRpb24gb2YgdGhlIHJldHVybiB2YWx1ZVxuICogQHBhcmFtIGZ1biBmdW5jdGlvbiB0byBob29rXG4gKiBAcGFyYW0gYXJnQ291bnQgbnVtYmVyIG9mIGFyZ3VtZW50cyB0aGUgZnVuY3Rpb24gdGFrZXNcbiAqIEBwYXJhbSBoYW5kbGVyIGNhbGxiYWNrIGZ1bmN0aW9uIHRvIGNhbGwgYWZ0ZXIgdGhlIG9yaWdpbmFsIGZ1bmN0aW9uXG4gKiBAcGFyYW0gZGV0ZWN0b3IgZGV0ZWN0b3IgdGhhdCBjYWxsZWQgdGhpcyBmdW5jdGlvblxuICovXG5mdW5jdGlvbiBhZGRPYmpDUG9zdEhvb2soZnVuLCBhcmdDb3VudCwgaGFuZGxlciwgZGV0ZWN0b3IpIHtcbiAgICBpZiAoZGV0ZWN0b3IgPT09IHZvaWQgMCkgeyBkZXRlY3RvciA9IG51bGw7IH1cbiAgICBhZGRIb29rKGZ1biwgYXJnQ291bnQsICdwb3N0JywgaGFuZGxlciwgZGV0ZWN0b3IpO1xufVxuZXhwb3J0cy5hZGRPYmpDUG9zdEhvb2sgPSBhZGRPYmpDUG9zdEhvb2s7XG4vKipcbiAqIEhvb2sgYW4gT2JqZWN0aXZlLUMgZnVuY3Rpb24gYW5kIHJlcGxhY2UgaXRzIG9yaWdpbmFsIGltcGxlbWVudGF0aW9uXG4gKiBAcGFyYW0gZnVuIGZ1bmN0aW9uIHRvIGhvb2tcbiAqIEBwYXJhbSBhcmdDb3VudCBudW1iZXIgb2YgYXJndW1lbnRzIHRoZSBmdW5jdGlvbiB0YWtlc1xuICogQHBhcmFtIGhhbmRsZXIgY2FsbGJhY2sgZnVuY3Rpb24gdG8gY2FsbCBpbnN0ZWFkIG9mIHRoZSBvcmlnaW5hbCBmdW5jdGlvblxuICogQHBhcmFtIGRldGVjdG9yIGRldGVjdG9yIHRoYXQgY2FsbGVkIHRoaXMgZnVuY3Rpb25cbiAqL1xuZnVuY3Rpb24gYWRkSG9vayhmdW4sIGFyZ0NvdW50LCB0eXBlLCBoYW5kbGVyLCBkZXRlY3Rvcikge1xuICAgIGlmIChkZXRlY3RvciA9PT0gdm9pZCAwKSB7IGRldGVjdG9yID0gbnVsbDsgfVxuICAgIC8vIFRPRE86IERvZXMgdGhpcyB3b3JrIHByb3Blcmx5IGlmIHRoZSBzYW1lIGZ1bmN0aW9uIGlzIGhvb2tlZCBtdWx0aXBsZSB0aW1lcz9cbiAgICBpZiAoZnVuIGluc3RhbmNlb2YgQXJyYXkpIHtcbiAgICAgICAgLy8gQWRkIGhvb2sgZm9yIGV2ZXJ5IHN5c2NhbGwgaW4gdGhlIGFycmF5XG4gICAgICAgIGZ1bi5mb3JFYWNoKGZ1bmN0aW9uIChmKSB7XG4gICAgICAgICAgICBhZGRIb29rKGYsIGFyZ0NvdW50LCB0eXBlLCBoYW5kbGVyKTtcbiAgICAgICAgfSk7XG4gICAgICAgIHJldHVybjtcbiAgICB9XG4gICAgaWYgKCFPYmpDLmF2YWlsYWJsZSkge1xuICAgICAgICByZXR1cm47XG4gICAgfVxuICAgIGlmIChkZXRlY3RvciA9PSBudWxsKSB7XG4gICAgICAgIGRldGVjdG9yID0gKDAsIGxvZ18xLmdldERldGVjdG9yKSgpO1xuICAgIH1cbiAgICB2YXIgb2JqY0Z1bjtcbiAgICB2YXIgZnVuTmFtZSA9IG51bGw7XG4gICAgaWYgKHR5cGVvZiBmdW4gPT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHZhciBtb2RpZmllciA9IGZ1bi5zdWJzdHJpbmcoMCwgMSk7XG4gICAgICAgIHZhciBpZGVudGlmaWVyID0gZnVuLnN1YnN0cmluZygxKS5yZXBsYWNlKCdbJywgJycpLnJlcGxhY2UoJ10nLCAnJykuc3BsaXQoJyAnKTtcbiAgICAgICAgdmFyIGNscyA9IGlkZW50aWZpZXJbMF07XG4gICAgICAgIHZhciBuYW1lXzEgPSBpZGVudGlmaWVyWzFdO1xuICAgICAgICB2YXIgb2JqY0NscyA9IE9iakMuY2xhc3Nlc1tjbHNdO1xuICAgICAgICBpZiAob2JqY0NscyA9PT0gdW5kZWZpbmVkICYmIGNscyA9PSAnTlNBcHBsaWNhdGlvbicpIHtcbiAgICAgICAgICAgIGNscyA9ICdVSUFwcGxpY2F0aW9uJztcbiAgICAgICAgICAgIG9iamNDbHMgPSBPYmpDLmNsYXNzZXNbY2xzXTtcbiAgICAgICAgfVxuICAgICAgICBpZiAob2JqY0NscyA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICAoMCwgbG9nXzEuZGVidWcpKFwiWyFdIFVuYWJsZSB0byBmaW5kIGNsYXNzIFwiLmNvbmNhdChjbHMsIFwiIGluIE9iamVjdGl2ZS1DXCIpKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuICAgICAgICBvYmpjRnVuID0gb2JqY0Nsc1ttb2RpZmllciArICcgJyArIG5hbWVfMV07XG4gICAgICAgIGlmIChvYmpjRnVuID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgICgwLCBsb2dfMS5kZWJ1ZykoXCJbIV0gVW5hYmxlIHRvIGZpbmQgZnVuY3Rpb24gXCIuY29uY2F0KGZ1biwgXCIgaW4gT2JqZWN0aXZlLUNcIikpO1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICBvYmpjRnVuID0gZnVuO1xuICAgIH1cbiAgICB2YXIgaXNIb29rZWQgPSBhcHBsaWVkSG9va3MuZmluZChmdW5jdGlvbiAoaCkgeyByZXR1cm4gaC5vYmpjRnVuID09PSBvYmpjRnVuOyB9KTtcbiAgICBhcHBsaWVkSG9va3MucHVzaCh7IG9iamNGdW46IG9iamNGdW4sIHR5cGU6IHR5cGUsIGhhbmRsZXI6IGhhbmRsZXIsIGRldGVjdG9yOiBkZXRlY3RvciB9KTtcbiAgICBpZiAoIWlzSG9va2VkKSB7XG4gICAgICAgIHZhciBzZWxmXzE7XG4gICAgICAgIHZhciBzZWxlY3Rvcl8xO1xuICAgICAgICB2YXIgZnVuQXJnc18xO1xuICAgICAgICBJbnRlcmNlcHRvci5hdHRhY2gob2JqY0Z1bi5pbXBsZW1lbnRhdGlvbiwge1xuICAgICAgICAgICAgb25FbnRlcjogZnVuY3Rpb24gKGFyZ3MpIHtcbiAgICAgICAgICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICAgICAgICAgIHNlbGZfMSA9IG5ldyBPYmpDLk9iamVjdChhcmdzWzBdKTtcbiAgICAgICAgICAgICAgICBzZWxlY3Rvcl8xID0gT2JqQy5zZWxlY3RvckFzU3RyaW5nKGFyZ3NbMV0pO1xuICAgICAgICAgICAgICAgIGZ1bkFyZ3NfMSA9IFtdO1xuICAgICAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYXJnQ291bnQ7IGkrKykge1xuICAgICAgICAgICAgICAgICAgICBmdW5BcmdzXzEucHVzaChhcmdzW2kgKyAyXSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghZnVuTmFtZSkge1xuICAgICAgICAgICAgICAgICAgICB2YXIgbWV0aG9kID0gc2VsZl8xLiRtZXRob2RzLmZpbmQoZnVuY3Rpb24gKG0pIHsgcmV0dXJuIG0uZW5kc1dpdGgoJyAnICsgc2VsZWN0b3JfMSk7IH0pO1xuICAgICAgICAgICAgICAgICAgICBmdW5OYW1lID0gbWV0aG9kLnN1YnN0cmluZygwLCAxKSArICdbJyArIHNlbGZfMS4kY2xhc3NOYW1lICsgJyAnICsgbWV0aG9kLnN1YnN0cmluZygyKSArICddJztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgdmFyIGhvb2tzID0gYXBwbGllZEhvb2tzLmZpbHRlcihmdW5jdGlvbiAoaCkgeyByZXR1cm4gaC5vYmpjRnVuID09PSBvYmpjRnVuOyB9KTtcbiAgICAgICAgICAgICAgICBob29rcy5mb3JFYWNoKGZ1bmN0aW9uIChob29rKSB7XG4gICAgICAgICAgICAgICAgICAgIGlmIChob29rLnR5cGUgPT09ICdwcmUnKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgZGF0YSA9IHsgZnVuOiBvYmpjRnVuLCBmdW5OYW1lOiBmdW5OYW1lLCBhcmdzOiBmdW5BcmdzXzEsIHNlbGY6IHNlbGZfMSwgXCJ0aGlzXCI6IF90aGlzLCBkZXRlY3RvcjogaG9vay5kZXRlY3RvciB9O1xuICAgICAgICAgICAgICAgICAgICAgICAgaG9vay5oYW5kbGVyKGRhdGEpO1xuICAgICAgICAgICAgICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBhcmdDb3VudDsgaSsrKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgYXJnc1tpICsgMl0gPSBmdW5BcmdzXzFbaV07XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBvbkxlYXZlOiBmdW5jdGlvbiAocmV0dmFsKSB7XG4gICAgICAgICAgICAgICAgdmFyIF90aGlzID0gdGhpcztcbiAgICAgICAgICAgICAgICB2YXIgaG9va3MgPSBhcHBsaWVkSG9va3MuZmlsdGVyKGZ1bmN0aW9uIChoKSB7IHJldHVybiBoLm9iamNGdW4gPT09IG9iamNGdW47IH0pO1xuICAgICAgICAgICAgICAgIGhvb2tzLmZvckVhY2goZnVuY3Rpb24gKGhvb2spIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKGhvb2sudHlwZSA9PT0gJ3Bvc3QnKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgZGF0YSA9IHsgZnVuOiBvYmpjRnVuLCBmdW5OYW1lOiBmdW5OYW1lLCBhcmdzOiBmdW5BcmdzXzEsIHNlbGY6IHNlbGZfMSwgXCJ0aGlzXCI6IF90aGlzLCByZXR2YWw6IHJldHZhbCwgZGV0ZWN0b3I6IGhvb2suZGV0ZWN0b3IgfTtcbiAgICAgICAgICAgICAgICAgICAgICAgIGhvb2suaGFuZGxlcihkYXRhKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICB9XG59XG4iLCJcInVzZSBzdHJpY3RcIjtcbnZhciBfX2Fzc2lnbiA9ICh0aGlzICYmIHRoaXMuX19hc3NpZ24pIHx8IGZ1bmN0aW9uICgpIHtcbiAgICBfX2Fzc2lnbiA9IE9iamVjdC5hc3NpZ24gfHwgZnVuY3Rpb24odCkge1xuICAgICAgICBmb3IgKHZhciBzLCBpID0gMSwgbiA9IGFyZ3VtZW50cy5sZW5ndGg7IGkgPCBuOyBpKyspIHtcbiAgICAgICAgICAgIHMgPSBhcmd1bWVudHNbaV07XG4gICAgICAgICAgICBmb3IgKHZhciBwIGluIHMpIGlmIChPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwocywgcCkpXG4gICAgICAgICAgICAgICAgdFtwXSA9IHNbcF07XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHQ7XG4gICAgfTtcbiAgICByZXR1cm4gX19hc3NpZ24uYXBwbHkodGhpcywgYXJndW1lbnRzKTtcbn07XG5leHBvcnRzLl9fZXNNb2R1bGUgPSB0cnVlO1xuZXhwb3J0cy5hZGRPcGVuUG9ydEhvb2sgPSB2b2lkIDA7XG52YXIgbG9nXzEgPSByZXF1aXJlKFwiLi4vaW5jL2xvZ1wiKTtcbnZhciBuYXRpdmVfMSA9IHJlcXVpcmUoXCIuL25hdGl2ZVwiKTtcbi8qKlxuICogV2lsbCBwcmV0ZW5kIHRoYXQgdGhlIGdpdmVuIHBvcnQgaXMgdW51c2VkIGV2ZW4gaWYgaXQgbWlnaHQgYmUgb3BlbiwgYW5kIGxvZyBjaGVja3MgZm9yIHRoaXNcbiAqIEBwYXJhbSBwb3J0XG4gKi9cbmZ1bmN0aW9uIGFkZE9wZW5Qb3J0SG9vayhwb3J0KSB7XG4gICAgdmFyIG9wZW5Qb3J0SGFuZGxlciA9IGZ1bmN0aW9uIChkYXRhLCBzb2NrYWRkcikge1xuICAgICAgICBpZiAoc29ja2FkZHIuaXNOdWxsKCkpXG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIHZhciBudG9ocyA9IG5ldyBOYXRpdmVGdW5jdGlvbihNb2R1bGUuZmluZEV4cG9ydEJ5TmFtZShudWxsLCAnbnRvaHMnKSwgJ3VpbnQnLCBbJ3VpbnQnXSk7XG4gICAgICAgIHZhciBudG9obCA9IG5ldyBOYXRpdmVGdW5jdGlvbihNb2R1bGUuZmluZEV4cG9ydEJ5TmFtZShudWxsLCAnbnRvaGwnKSwgJ3VpbnQnLCBbJ3VpbnQnXSk7XG4gICAgICAgIHZhciBzb2NrRmFtaWx5ID0gc29ja2FkZHIucmVhZFNob3J0KCk7XG4gICAgICAgIHZhciBzb2NrUG9ydCA9IG50b2hzKHNvY2thZGRyLmFkZCgyKS5yZWFkVVNob3J0KCkpO1xuICAgICAgICB2YXIgc29ja0FkZHIgPSBudG9obChzb2NrYWRkci5hZGQoNCkucmVhZFUzMigpKTtcbiAgICAgICAgaWYgKHNvY2tGYW1pbHkgPT0gMiAmJiBzb2NrUG9ydCA9PSBwb3J0ICYmIChzb2NrQWRkciA9PSAwIHx8IHNvY2tBZGRyID09IDB4N2YwMDAwMDEpKSB7XG4gICAgICAgICAgICAoMCwgbG9nXzEubG9nRnVuY3Rpb24pKF9fYXNzaWduKF9fYXNzaWduKHt9LCBkYXRhKSwgeyBhcmdzOiBbXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGZhbWlseTogc29ja0ZhbWlseSxcbiAgICAgICAgICAgICAgICAgICAgICAgIHBvcnQ6IHNvY2tQb3J0LFxuICAgICAgICAgICAgICAgICAgICAgICAgYWRkcjogc29ja0FkZHJcbiAgICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICBdIH0pKTtcbiAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9O1xuICAgIC8vIFNpZ25hdHVyZTogaW50IHNvY2tmZCwgc3RydWN0IHNvY2thZGRyICphZGRyLCBzb2NrbGVuX3QgYWRkcmxlblxuICAgIHZhciBzb2NrRnVuY3Rpb25zMSA9IFsnY29ubmVjdCcsICdiaW5kJywgJ2FjY2VwdCcsICdnZXRwZWVybmFtZScsICdnZXRzb2NrbmFtZSddO1xuICAgICgwLCBuYXRpdmVfMS5hZGRQcmVIb29rKShzb2NrRnVuY3Rpb25zMSwgWydpbnQnLCAncHRyJywgJ3B0ciddLCBmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICB2YXIgc29ja2FkZHIgPSBkYXRhLmFyZ3NbMV07XG4gICAgICAgIGlmIChvcGVuUG9ydEhhbmRsZXIoZGF0YSwgc29ja2FkZHIpKSB7XG4gICAgICAgICAgICAvLyBBc3NpZ24gcmFuZG9tIHBvcnRcbiAgICAgICAgICAgIHNvY2thZGRyLmFkZCgyKS53cml0ZVVTaG9ydCgwKTtcbiAgICAgICAgfVxuICAgIH0pO1xuICAgICgwLCBuYXRpdmVfMS5hZGRQb3N0SG9vaykoc29ja0Z1bmN0aW9uczEsIFsnaW50JywgJ3B0cicsICdwdHInXSwgZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAgICAgdmFyIHNvY2thZGRyID0gZGF0YS5hcmdzWzFdO1xuICAgICAgICBpZiAob3BlblBvcnRIYW5kbGVyKGRhdGEsIHNvY2thZGRyKSkge1xuICAgICAgICAgICAgLy8gUmVzdG9yZSBwb3J0XG4gICAgICAgICAgICBzb2NrYWRkci5hZGQoMikud3JpdGVVU2hvcnQocG9ydCk7XG4gICAgICAgIH1cbiAgICB9KTtcbiAgICAvLyBTaWduYXR1cmU6IGludCBzb2NrZmQsIHZvaWQgKmJ1Ziwgc2l6ZV90IGxlbiwgaW50IGZsYWdzLCBzdHJ1Y3Qgc29ja2FkZHIgKmFkZHIsIHNvY2tsZW5fdCAqYWRkcmxlblxuICAgIHZhciBzb2NrRnVuY3Rpb25zMiA9IFsncmVjdmZyb20nLCAnc2VuZHRvJ107XG4gICAgKDAsIG5hdGl2ZV8xLmFkZFByZUhvb2spKHNvY2tGdW5jdGlvbnMyLCBbJ2ludCcsICdwdHInLCAnaW50JywgJ2ludCcsICdwdHInLCAncHRyJ10sIGZ1bmN0aW9uIChkYXRhKSB7XG4gICAgICAgIHZhciBzb2NrYWRkciA9IGRhdGEuYXJnc1s0XTtcbiAgICAgICAgaWYgKG9wZW5Qb3J0SGFuZGxlcihkYXRhLCBzb2NrYWRkcikpIHtcbiAgICAgICAgICAgIC8vIEFzc2lnbiByYW5kb20gcG9ydFxuICAgICAgICAgICAgc29ja2FkZHIuYWRkKDIpLndyaXRlVVNob3J0KDApO1xuICAgICAgICB9XG4gICAgfSk7XG4gICAgKDAsIG5hdGl2ZV8xLmFkZFBvc3RIb29rKShzb2NrRnVuY3Rpb25zMiwgWydpbnQnLCAncHRyJywgJ2ludCcsICdpbnQnLCAncHRyJywgJ3B0ciddLCBmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICB2YXIgc29ja2FkZHIgPSBkYXRhLmFyZ3NbNF07XG4gICAgICAgIGlmIChvcGVuUG9ydEhhbmRsZXIoZGF0YSwgc29ja2FkZHIpKSB7XG4gICAgICAgICAgICAvLyBSZXN0b3JlIHBvcnRcbiAgICAgICAgICAgIHNvY2thZGRyLmFkZCgyKS53cml0ZVVTaG9ydChwb3J0KTtcbiAgICAgICAgfVxuICAgIH0pO1xufVxuZXhwb3J0cy5hZGRPcGVuUG9ydEhvb2sgPSBhZGRPcGVuUG9ydEhvb2s7XG4iLCJcInVzZSBzdHJpY3RcIjtcbmV4cG9ydHMuX19lc01vZHVsZSA9IHRydWU7XG52YXIgbG9nXzEgPSByZXF1aXJlKFwiLi9sb2dcIik7XG52YXIgdXRpbF8xID0gcmVxdWlyZShcIi4vdXRpbFwiKTtcbi8qXG5UaGlzIGZpbGUgaXMgYSBtb2RpZmllZCB2ZXJzaW9uIG9mIGZyaWRhLWlvcy1kdW1wIGJ5IEFsb25lTW9ua2V5OlxuaHR0cHM6Ly9naXRodWIuY29tL0Fsb25lTW9ua2V5L2ZyaWRhLWlvcy1kdW1wL2Jsb2IvbWFzdGVyL2R1bXAuanNcbkNoYW5nZXM6XG4tIERlY3J5cHQgbW9kdWxlIGluIG1lbW9yeSBhbmQgc2VuZCB0byBweXRob24gd2l0aCBGcmlkYSBtZXNzYWdlIGluc3RlYWQgb2Ygd3JpdGluZyB0byBmaWxlIGFuZCBjb3B5aW5nIHdpdGggU0NQXG4tIFJlbW92ZSB1bnVzZWQgY29kZVxuLSBSZXBsYWNlIGNvbnNvbGUubG9nIHdpdGggZGVidWcvd2FybiBmdW5jdGlvblxuLSBBZGQgZXJyb3IgaGFuZGxpbmcgdG8gbGlicmFyeSBsb2FkaW5nXG4qL1xuTW9kdWxlLmVuc3VyZUluaXRpYWxpemVkKCdGb3VuZGF0aW9uJyk7XG52YXIgT19SRE9OTFkgPSAwO1xudmFyIFNFRUtfU0VUID0gMDtcbnZhciBTRUVLX0VORCA9IDI7XG5mdW5jdGlvbiBhbGxvY1N0cihzdHIpIHtcbiAgICByZXR1cm4gTWVtb3J5LmFsbG9jVXRmOFN0cmluZyhzdHIpO1xufVxuZnVuY3Rpb24gZ2V0VTMyKGFkZHIpIHtcbiAgICBpZiAodHlwZW9mIGFkZHIgPT0gXCJudW1iZXJcIikge1xuICAgICAgICBhZGRyID0gcHRyKGFkZHIpO1xuICAgIH1cbiAgICAvL0B0cy1pZ25vcmVcbiAgICByZXR1cm4gTWVtb3J5LnJlYWRVMzIoYWRkcik7XG59XG5mdW5jdGlvbiBwdXRVNjQoYWRkciwgbikge1xuICAgIGlmICh0eXBlb2YgYWRkciA9PSBcIm51bWJlclwiKSB7XG4gICAgICAgIGFkZHIgPSBwdHIoYWRkcik7XG4gICAgfVxuICAgIC8vQHRzLWlnbm9yZVxuICAgIHJldHVybiBNZW1vcnkud3JpdGVVNjQoYWRkciwgbik7XG59XG5mdW5jdGlvbiBtYWxsb2Moc2l6ZSkge1xuICAgIHJldHVybiBNZW1vcnkuYWxsb2Moc2l6ZSk7XG59XG5mdW5jdGlvbiBnZXRFeHBvcnRGdW5jdGlvbih0eXBlLCBuYW1lLCByZXQsIGFyZ3MpIHtcbiAgICB2YXIgbnB0cjtcbiAgICBucHRyID0gTW9kdWxlLmZpbmRFeHBvcnRCeU5hbWUobnVsbCwgbmFtZSk7XG4gICAgaWYgKG5wdHIgPT09IG51bGwpIHtcbiAgICAgICAgKDAsIGxvZ18xLndhcm4pKFwiY2Fubm90IGZpbmQgXCIgKyBuYW1lKTtcbiAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICBpZiAodHlwZSA9PT0gXCJmXCIpIHtcbiAgICAgICAgICAgIHZhciBmdW5jbGV0ID0gbmV3IE5hdGl2ZUZ1bmN0aW9uKG5wdHIsIHJldCwgYXJncyk7XG4gICAgICAgICAgICBpZiAodHlwZW9mIGZ1bmNsZXQgPT09IFwidW5kZWZpbmVkXCIpIHtcbiAgICAgICAgICAgICAgICAoMCwgbG9nXzEud2FybikoXCJwYXJzZSBlcnJvciBcIiArIG5hbWUpO1xuICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIGZ1bmNsZXQ7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAodHlwZSA9PT0gXCJkXCIpIHtcbiAgICAgICAgICAgIC8vQHRzLWlnbm9yZVxuICAgICAgICAgICAgdmFyIGRhdGFsZXQgPSBNZW1vcnkucmVhZFBvaW50ZXIobnB0cik7XG4gICAgICAgICAgICBpZiAodHlwZW9mIGRhdGFsZXQgPT09IFwidW5kZWZpbmVkXCIpIHtcbiAgICAgICAgICAgICAgICAoMCwgbG9nXzEud2FybikoXCJwYXJzZSBlcnJvciBcIiArIG5hbWUpO1xuICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIGRhdGFsZXQ7XG4gICAgICAgIH1cbiAgICB9XG59XG52YXIgd3JhcHBlcl9vcGVuID0gZ2V0RXhwb3J0RnVuY3Rpb24oXCJmXCIsIFwib3BlblwiLCBcImludFwiLCBbXCJwb2ludGVyXCIsIFwiaW50XCIsIFwiaW50XCJdKTtcbnZhciByZWFkID0gZ2V0RXhwb3J0RnVuY3Rpb24oXCJmXCIsIFwicmVhZFwiLCBcImludFwiLCBbXCJpbnRcIiwgXCJwb2ludGVyXCIsIFwiaW50XCJdKTtcbnZhciBsc2VlayA9IGdldEV4cG9ydEZ1bmN0aW9uKFwiZlwiLCBcImxzZWVrXCIsIFwiaW50NjRcIiwgW1wiaW50XCIsIFwiaW50NjRcIiwgXCJpbnRcIl0pO1xudmFyIGNsb3NlID0gZ2V0RXhwb3J0RnVuY3Rpb24oXCJmXCIsIFwiY2xvc2VcIiwgXCJpbnRcIiwgW1wiaW50XCJdKTtcbnZhciBkbG9wZW4gPSBnZXRFeHBvcnRGdW5jdGlvbihcImZcIiwgXCJkbG9wZW5cIiwgXCJwb2ludGVyXCIsIFtcInBvaW50ZXJcIiwgXCJpbnRcIl0pO1xuZnVuY3Rpb24gb3BlbihwYXRobmFtZSwgZmxhZ3MsIG1vZGUpIHtcbiAgICBpZiAodHlwZW9mIHBhdGhuYW1lID09IFwic3RyaW5nXCIpIHtcbiAgICAgICAgcGF0aG5hbWUgPSBhbGxvY1N0cihwYXRobmFtZSk7XG4gICAgfVxuICAgIHJldHVybiB3cmFwcGVyX29wZW4ocGF0aG5hbWUsIGZsYWdzLCBtb2RlKTtcbn1cbnZhciBtb2R1bGVzID0gbnVsbDtcbmZ1bmN0aW9uIGdldEFsbEFwcE1vZHVsZXMoKSB7XG4gICAgbW9kdWxlcyA9IG5ldyBBcnJheSgpO1xuICAgIHZhciB0bXBtb2RzID0gUHJvY2Vzcy5lbnVtZXJhdGVNb2R1bGVzKCk7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCB0bXBtb2RzLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgIGlmICh0bXBtb2RzW2ldLnBhdGguaW5kZXhPZihcIi5hcHBcIikgIT0gLTEpIHtcbiAgICAgICAgICAgIG1vZHVsZXMucHVzaCh0bXBtb2RzW2ldKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gbW9kdWxlcztcbn1cbnZhciBGQVRfTUFHSUMgPSAweGNhZmViYWJlO1xudmFyIEZBVF9DSUdBTSA9IDB4YmViYWZlY2E7XG52YXIgTUhfTUFHSUMgPSAweGZlZWRmYWNlO1xudmFyIE1IX0NJR0FNID0gMHhjZWZhZWRmZTtcbnZhciBNSF9NQUdJQ182NCA9IDB4ZmVlZGZhY2Y7XG52YXIgTUhfQ0lHQU1fNjQgPSAweGNmZmFlZGZlO1xudmFyIExDX0VOQ1JZUFRJT05fSU5GTyA9IDB4MjE7XG52YXIgTENfRU5DUllQVElPTl9JTkZPXzY0ID0gMHgyQztcbmZ1bmN0aW9uIHBhZChzdHIsIG4pIHtcbiAgICByZXR1cm4gQXJyYXkobiAtIHN0ci5sZW5ndGggKyAxKS5qb2luKFwiMFwiKSArIHN0cjtcbn1cbmZ1bmN0aW9uIHN3YXAzMih2YWx1ZSkge1xuICAgIHZhbHVlID0gcGFkKHZhbHVlLnRvU3RyaW5nKDE2KSwgOCk7XG4gICAgdmFyIHJlc3VsdCA9IFwiXCI7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCB2YWx1ZS5sZW5ndGg7IGkgPSBpICsgMikge1xuICAgICAgICByZXN1bHQgKz0gdmFsdWUuY2hhckF0KHZhbHVlLmxlbmd0aCAtIGkgLSAyKTtcbiAgICAgICAgcmVzdWx0ICs9IHZhbHVlLmNoYXJBdCh2YWx1ZS5sZW5ndGggLSBpIC0gMSk7XG4gICAgfVxuICAgIHJldHVybiBwYXJzZUludChyZXN1bHQsIDE2KTtcbn1cbmZ1bmN0aW9uIGR1bXBNb2R1bGUobmFtZSkge1xuICAgIGlmIChtb2R1bGVzID09IG51bGwpIHtcbiAgICAgICAgbW9kdWxlcyA9IGdldEFsbEFwcE1vZHVsZXMoKTtcbiAgICB9XG4gICAgdmFyIHRhcmdldG1vZCA9IG51bGw7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBtb2R1bGVzLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgIGlmIChtb2R1bGVzW2ldLnBhdGguaW5kZXhPZihuYW1lKSAhPSAtMSkge1xuICAgICAgICAgICAgdGFyZ2V0bW9kID0gbW9kdWxlc1tpXTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgfVxuICAgIGlmICh0YXJnZXRtb2QgPT0gbnVsbCkge1xuICAgICAgICAoMCwgbG9nXzEud2FybikoXCJDYW5ub3QgZmluZCBtb2R1bGVcIik7XG4gICAgICAgIHJldHVybjtcbiAgICB9XG4gICAgdmFyIG1vZGJhc2UgPSB0YXJnZXRtb2QuYmFzZTtcbiAgICB2YXIgbW9kcGF0aCA9IHRhcmdldG1vZC5wYXRoO1xuICAgIHZhciBmb2xkbW9kdWxlID0gb3Blbihtb2RwYXRoLCBPX1JET05MWSwgMCk7XG4gICAgaWYgKGZvbGRtb2R1bGUgPT0gLTEpIHtcbiAgICAgICAgKDAsIGxvZ18xLndhcm4pKFwiQ2Fubm90IG9wZW4gZmlsZVwiICsgZm9sZG1vZHVsZSk7XG4gICAgICAgIHJldHVybjtcbiAgICB9XG4gICAgdmFyIHNpemVfb2ZfbWFjaF9oZWFkZXIgPSAwO1xuICAgIHZhciBtYWdpYyA9IGdldFUzMihtb2RiYXNlKTtcbiAgICB2YXIgY3VyX2NwdV90eXBlID0gZ2V0VTMyKG1vZGJhc2UuYWRkKDQpKTtcbiAgICB2YXIgY3VyX2NwdV9zdWJ0eXBlID0gZ2V0VTMyKG1vZGJhc2UuYWRkKDgpKTtcbiAgICBpZiAobWFnaWMgPT0gTUhfTUFHSUMgfHwgbWFnaWMgPT0gTUhfQ0lHQU0pIHtcbiAgICAgICAgc2l6ZV9vZl9tYWNoX2hlYWRlciA9IDI4O1xuICAgIH1cbiAgICBlbHNlIGlmIChtYWdpYyA9PSBNSF9NQUdJQ182NCB8fCBtYWdpYyA9PSBNSF9DSUdBTV82NCkge1xuICAgICAgICBzaXplX29mX21hY2hfaGVhZGVyID0gMzI7XG4gICAgfVxuICAgIHZhciBCVUZTSVpFID0gNDA5NjtcbiAgICB2YXIgYnVmZmVyID0gbWFsbG9jKEJVRlNJWkUpO1xuICAgIHJlYWQoZm9sZG1vZHVsZSwgYnVmZmVyLCBCVUZTSVpFKTtcbiAgICB2YXIgZmlsZW9mZnNldCA9IDA7XG4gICAgdmFyIGZpbGVzaXplID0gMDtcbiAgICB2YXIgZm1vZHVsZV9vZmZzZXQgPSAwO1xuICAgIG1hZ2ljID0gZ2V0VTMyKGJ1ZmZlcik7XG4gICAgaWYgKG1hZ2ljID09IEZBVF9DSUdBTSB8fCBtYWdpYyA9PSBGQVRfTUFHSUMpIHtcbiAgICAgICAgdmFyIG9mZiA9IDQ7XG4gICAgICAgIHZhciBhcmNocyA9IHN3YXAzMihnZXRVMzIoYnVmZmVyLmFkZChvZmYpKSk7XG4gICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYXJjaHM7IGkrKykge1xuICAgICAgICAgICAgdmFyIGNwdXR5cGUgPSBzd2FwMzIoZ2V0VTMyKGJ1ZmZlci5hZGQob2ZmICsgNCkpKTtcbiAgICAgICAgICAgIHZhciBjcHVzdWJ0eXBlID0gc3dhcDMyKGdldFUzMihidWZmZXIuYWRkKG9mZiArIDgpKSk7XG4gICAgICAgICAgICBpZiAoY3VyX2NwdV90eXBlID09IGNwdXR5cGUgJiYgY3VyX2NwdV9zdWJ0eXBlID09IGNwdXN1YnR5cGUpIHtcbiAgICAgICAgICAgICAgICBmaWxlb2Zmc2V0ID0gc3dhcDMyKGdldFUzMihidWZmZXIuYWRkKG9mZiArIDEyKSkpO1xuICAgICAgICAgICAgICAgIGZpbGVzaXplID0gc3dhcDMyKGdldFUzMihidWZmZXIuYWRkKG9mZiArIDE2KSkpO1xuICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgb2ZmICs9IDIwO1xuICAgICAgICB9XG4gICAgICAgIHZhciBmbW9kdWxlID0gbWFsbG9jKGZpbGVzaXplKTtcbiAgICAgICAgaWYgKGZpbGVvZmZzZXQgPT0gMCB8fCBmaWxlc2l6ZSA9PSAwKVxuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICBsc2Vlayhmb2xkbW9kdWxlLCBmaWxlb2Zmc2V0LCBTRUVLX1NFVCk7XG4gICAgICAgIC8vQHRzLWlnbm9yZVxuICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IHBhcnNlSW50KGZpbGVzaXplIC8gQlVGU0laRSk7IGkrKykge1xuICAgICAgICAgICAgcmVhZChmb2xkbW9kdWxlLCBidWZmZXIsIEJVRlNJWkUpO1xuICAgICAgICAgICAgTWVtb3J5LmNvcHkoZm1vZHVsZS5hZGQoZm1vZHVsZV9vZmZzZXQpLCBidWZmZXIsIEJVRlNJWkUpO1xuICAgICAgICAgICAgZm1vZHVsZV9vZmZzZXQgKz0gQlVGU0laRTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoZmlsZXNpemUgJSBCVUZTSVpFKSB7XG4gICAgICAgICAgICByZWFkKGZvbGRtb2R1bGUsIGJ1ZmZlciwgZmlsZXNpemUgJSBCVUZTSVpFKTtcbiAgICAgICAgICAgIE1lbW9yeS5jb3B5KGZtb2R1bGUuYWRkKGZtb2R1bGVfb2Zmc2V0KSwgYnVmZmVyLCBmaWxlc2l6ZSAlIEJVRlNJWkUpO1xuICAgICAgICAgICAgZm1vZHVsZV9vZmZzZXQgKz0gZmlsZXNpemUgJSBCVUZTSVpFO1xuICAgICAgICB9XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICBmaWxlc2l6ZSA9IHBhcnNlSW50KGxzZWVrKGZvbGRtb2R1bGUsIDAsIFNFRUtfRU5EKSk7XG4gICAgICAgIHZhciBmbW9kdWxlID0gbWFsbG9jKGZpbGVzaXplKTtcbiAgICAgICAgdmFyIHJlYWRMZW4gPSAwO1xuICAgICAgICBsc2Vlayhmb2xkbW9kdWxlLCAwLCBTRUVLX1NFVCk7XG4gICAgICAgIHdoaWxlIChyZWFkTGVuID0gcmVhZChmb2xkbW9kdWxlLCBidWZmZXIsIEJVRlNJWkUpKSB7XG4gICAgICAgICAgICBNZW1vcnkuY29weShmbW9kdWxlLmFkZChmbW9kdWxlX29mZnNldCksIGJ1ZmZlciwgcmVhZExlbik7XG4gICAgICAgICAgICBmbW9kdWxlX29mZnNldCArPSByZWFkTGVuO1xuICAgICAgICB9XG4gICAgfVxuICAgIHZhciBuY21kcyA9IGdldFUzMihtb2RiYXNlLmFkZCgxNikpO1xuICAgIHZhciBvZmYgPSBzaXplX29mX21hY2hfaGVhZGVyO1xuICAgIHZhciBvZmZzZXRfY3J5cHRpZCA9IC0xO1xuICAgIHZhciBjcnlwdF9vZmYgPSAwO1xuICAgIHZhciBjcnlwdF9zaXplID0gMDtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IG5jbWRzOyBpKyspIHtcbiAgICAgICAgdmFyIGNtZCA9IGdldFUzMihtb2RiYXNlLmFkZChvZmYpKTtcbiAgICAgICAgdmFyIGNtZHNpemUgPSBnZXRVMzIobW9kYmFzZS5hZGQob2ZmICsgNCkpO1xuICAgICAgICBpZiAoY21kID09IExDX0VOQ1JZUFRJT05fSU5GTyB8fCBjbWQgPT0gTENfRU5DUllQVElPTl9JTkZPXzY0KSB7XG4gICAgICAgICAgICBvZmZzZXRfY3J5cHRpZCA9IG9mZiArIDE2O1xuICAgICAgICAgICAgY3J5cHRfb2ZmID0gZ2V0VTMyKG1vZGJhc2UuYWRkKG9mZiArIDgpKTtcbiAgICAgICAgICAgIGNyeXB0X3NpemUgPSBnZXRVMzIobW9kYmFzZS5hZGQob2ZmICsgMTIpKTtcbiAgICAgICAgfVxuICAgICAgICBvZmYgKz0gY21kc2l6ZTtcbiAgICB9XG4gICAgaWYgKG9mZnNldF9jcnlwdGlkICE9IC0xKSB7XG4gICAgICAgIHZhciB0cGJ1ZiA9IG1hbGxvYyg4KTtcbiAgICAgICAgcHV0VTY0KHRwYnVmLCAwKTtcbiAgICAgICAgZm1vZHVsZV9vZmZzZXQgPSBvZmZzZXRfY3J5cHRpZDtcbiAgICAgICAgTWVtb3J5LmNvcHkoZm1vZHVsZS5hZGQoZm1vZHVsZV9vZmZzZXQpLCB0cGJ1ZiwgNCk7XG4gICAgICAgIGZtb2R1bGVfb2Zmc2V0ID0gY3J5cHRfb2ZmO1xuICAgICAgICBNZW1vcnkuY29weShmbW9kdWxlLmFkZChmbW9kdWxlX29mZnNldCksIG1vZGJhc2UuYWRkKGNyeXB0X29mZiksIGNyeXB0X3NpemUpO1xuICAgIH1cbiAgICBjbG9zZShmb2xkbW9kdWxlKTtcbiAgICAvLyBTZW5kIG1heCA2NCBNaUIgYXQgYSB0aW1lXG4gICAgdmFyIG1heFNpemUgPSAweDQwMDAwMDA7XG4gICAgZm9yICh2YXIgb2Zmc2V0ID0gMDsgb2Zmc2V0IDwgZmlsZXNpemU7IG9mZnNldCArPSBtYXhTaXplKSB7XG4gICAgICAgIHZhciByZWFkTGVuZ3RoID0gTWF0aC5taW4obWF4U2l6ZSwgZmlsZXNpemUgLSBvZmZzZXQpO1xuICAgICAgICBzZW5kKHsgdHlwZTogJ2R1bXAnLCBjb21wbGV0ZTogZmFsc2UsIG1vZHVsZTogdGFyZ2V0bW9kLm5hbWUsIHBhdGg6IG1vZHBhdGgsIG9mZnNldDogb2Zmc2V0IH0sIGZtb2R1bGUuYWRkKG9mZnNldCkucmVhZEJ5dGVBcnJheShyZWFkTGVuZ3RoKSk7XG4gICAgfVxufVxuZnVuY3Rpb24gbG9hZEFsbER5bmFtaWNMaWJyYXJ5KGFwcF9wYXRoKSB7XG4gICAgdmFyIGRlZmF1bHRNYW5hZ2VyID0gT2JqQy5jbGFzc2VzLk5TRmlsZU1hbmFnZXIuZGVmYXVsdE1hbmFnZXIoKTtcbiAgICB2YXIgZXJyb3JQdHIgPSBNZW1vcnkuYWxsb2MoUHJvY2Vzcy5wb2ludGVyU2l6ZSk7XG4gICAgLy9AdHMtaWdub3JlXG4gICAgTWVtb3J5LndyaXRlUG9pbnRlcihlcnJvclB0ciwgTlVMTCk7XG4gICAgdmFyIGZpbGVuYW1lcyA9IGRlZmF1bHRNYW5hZ2VyLmNvbnRlbnRzT2ZEaXJlY3RvcnlBdFBhdGhfZXJyb3JfKGFwcF9wYXRoLCBlcnJvclB0cik7XG4gICAgZm9yICh2YXIgaSA9IDAsIGwgPSBmaWxlbmFtZXMuY291bnQoKTsgaSA8IGw7IGkrKykge1xuICAgICAgICB2YXIgZmlsZV9uYW1lID0gZmlsZW5hbWVzLm9iamVjdEF0SW5kZXhfKGkpO1xuICAgICAgICB2YXIgZmlsZV9wYXRoID0gYXBwX3BhdGguc3RyaW5nQnlBcHBlbmRpbmdQYXRoQ29tcG9uZW50XyhmaWxlX25hbWUpO1xuICAgICAgICBpZiAoZmlsZV9uYW1lLmhhc1N1ZmZpeF8oXCIuZnJhbWV3b3JrXCIpKSB7XG4gICAgICAgICAgICB2YXIgYnVuZGxlID0gT2JqQy5jbGFzc2VzLk5TQnVuZGxlLmJ1bmRsZVdpdGhQYXRoXyhmaWxlX3BhdGgpO1xuICAgICAgICAgICAgaWYgKGJ1bmRsZS5pc0xvYWRlZCgpKSB7XG4gICAgICAgICAgICAgICAgKDAsIGxvZ18xLmRlYnVnKShmaWxlX25hbWUgKyBcIiBoYXMgYmVlbiBsb2FkZWQuIFwiKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgIGlmIChidW5kbGUubG9hZCgpKSB7XG4gICAgICAgICAgICAgICAgICAgICgwLCBsb2dfMS5kZWJ1ZykoXCJMb2FkIFwiICsgZmlsZV9uYW1lICsgXCIgc3VjY2Vzcy4gXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgKDAsIGxvZ18xLndhcm4pKFwiTG9hZCBcIiArIGZpbGVfbmFtZSArIFwiIGZhaWxlZC4gXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmIChmaWxlX25hbWUuaGFzU3VmZml4XyhcIi5idW5kbGVcIikgfHxcbiAgICAgICAgICAgIGZpbGVfbmFtZS5oYXNTdWZmaXhfKFwiLm1vbWRcIikgfHxcbiAgICAgICAgICAgIGZpbGVfbmFtZS5oYXNTdWZmaXhfKFwiLnN0cmluZ3NcIikgfHxcbiAgICAgICAgICAgIGZpbGVfbmFtZS5oYXNTdWZmaXhfKFwiLmFwcGV4XCIpIHx8XG4gICAgICAgICAgICBmaWxlX25hbWUuaGFzU3VmZml4XyhcIi5hcHBcIikgfHxcbiAgICAgICAgICAgIGZpbGVfbmFtZS5oYXNTdWZmaXhfKFwiLmxwcm9qXCIpIHx8XG4gICAgICAgICAgICBmaWxlX25hbWUuaGFzU3VmZml4XyhcIi5zdG9yeWJvYXJkY1wiKSkge1xuICAgICAgICAgICAgY29udGludWU7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICB2YXIgaXNEaXJQdHIgPSBNZW1vcnkuYWxsb2MoUHJvY2Vzcy5wb2ludGVyU2l6ZSk7XG4gICAgICAgICAgICAvL0B0cy1pZ25vcmVcbiAgICAgICAgICAgIE1lbW9yeS53cml0ZVBvaW50ZXIoaXNEaXJQdHIsIE5VTEwpO1xuICAgICAgICAgICAgZGVmYXVsdE1hbmFnZXIuZmlsZUV4aXN0c0F0UGF0aF9pc0RpcmVjdG9yeV8oZmlsZV9wYXRoLCBpc0RpclB0cik7XG4gICAgICAgICAgICAvL0B0cy1pZ25vcmVcbiAgICAgICAgICAgIGlmIChNZW1vcnkucmVhZFBvaW50ZXIoaXNEaXJQdHIpID09IDEpIHtcbiAgICAgICAgICAgICAgICBsb2FkQWxsRHluYW1pY0xpYnJhcnkoZmlsZV9wYXRoKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgIGlmIChmaWxlX25hbWUuaGFzU3VmZml4XyhcIi5keWxpYlwiKSkge1xuICAgICAgICAgICAgICAgICAgICB2YXIgaXNfbG9hZGVkID0gMDtcbiAgICAgICAgICAgICAgICAgICAgZm9yICh2YXIgaiA9IDA7IGogPCBtb2R1bGVzLmxlbmd0aDsgaisrKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAobW9kdWxlc1tqXS5wYXRoLmluZGV4T2YoZmlsZV9uYW1lKSAhPSAtMSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlzX2xvYWRlZCA9IDE7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgKDAsIGxvZ18xLmRlYnVnKShmaWxlX25hbWUgKyBcIiBoYXMgYmVlbiBkbG9wZW4uXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGlmICghaXNfbG9hZGVkKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBBZGRlZCBlcnJvciBoYW5kbGluZyB2aWEgdHJ5IGNhdGNoIHRvIHByZXZlbnQgcHJvZ3JhbSBmcm9tIGNyYXNoaW5nXG4gICAgICAgICAgICAgICAgICAgICAgICAvLyB3aGVuIGEgbGlicmFyeSBjYW5ub3QgYmUgbG9hZGVkLlxuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGZpbGVfcGF0aF9wdHIgPSBhbGxvY1N0cihmaWxlX3BhdGguVVRGOFN0cmluZygpKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGRsb3BlbihmaWxlX3BhdGhfcHRyLCA5KSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAoMCwgbG9nXzEuZGVidWcpKFwiZGxvcGVuIFwiICsgZmlsZV9uYW1lICsgXCIgc3VjY2Vzcy4gXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKDAsIGxvZ18xLndhcm4pKFwiZGxvcGVuIFwiICsgZmlsZV9uYW1lICsgXCIgZmFpbGVkLiBcIik7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgY2F0Y2ggKGUpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAoMCwgbG9nXzEud2FybikoXCJkbG9wZW4gXCIgKyBmaWxlX25hbWUgKyBcIiBmYWlsZWQ6IFwiICsgZS5tZXNzYWdlKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbn1cbmZ1bmN0aW9uIGR1bXBNb2R1bGVzKCkge1xuICAgIG1vZHVsZXMgPSBnZXRBbGxBcHBNb2R1bGVzKCk7XG4gICAgdmFyIGFwcF9wYXRoID0gT2JqQy5jbGFzc2VzLk5TQnVuZGxlLm1haW5CdW5kbGUoKS5idW5kbGVQYXRoKCk7XG4gICAgbG9hZEFsbER5bmFtaWNMaWJyYXJ5KGFwcF9wYXRoKTtcbiAgICAvLyBzdGFydCBkdW1wXG4gICAgbW9kdWxlcyA9IGdldEFsbEFwcE1vZHVsZXMoKTtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IG1vZHVsZXMubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgZHVtcE1vZHVsZShtb2R1bGVzW2ldLnBhdGgpO1xuICAgIH1cbiAgICBzZW5kKHsgdHlwZTogJ2R1bXAnLCBjb21wbGV0ZTogdHJ1ZSB9KTtcbn1cbigwLCB1dGlsXzEuYWRkUnBjRXhwb3J0cykoe1xuICAgIGR1bXBNb2R1bGVzOiBkdW1wTW9kdWxlc1xufSk7XG4iLCJcInVzZSBzdHJpY3RcIjtcbmV4cG9ydHMuX19lc01vZHVsZSA9IHRydWU7XG5leHBvcnRzLmRlYnVnID0gZXhwb3J0cy5pbmZvID0gZXhwb3J0cy53YXJuID0gZXhwb3J0cy5lcnJvciA9IGV4cG9ydHMuZ2V0RGV0ZWN0b3IgPSBleHBvcnRzLmxvZ09iakNGdW5jdGlvbiA9IGV4cG9ydHMubG9nSmF2YUZ1bmN0aW9uID0gZXhwb3J0cy5sb2dGdW5jdGlvbiA9IGV4cG9ydHMubG9nID0gdm9pZCAwO1xudmFyIHNlbnRNb2R1bGVzID0gW107XG4vKipcbiAqIFNlbmQgYSBtZXNzYWdlIHRvIFB5dGhvblxuICogQHBhcmFtIG1lc3NhZ2UgbWVzc2FnZSB0byBzZW5kXG4gKiBAcGFyYW0gY29udGV4dCBjb250ZXh0IG9mIHRoZSBwcm9ncmFtLCB1c2VkIHRvIGF0dGFjaCBhIGJhY2t0cmFjZSB0byB0aGUgbWVzc2FnZVxuICogQHBhcmFtIGRldGVjdG9yIGRldGVjdG9yIHRoYXQgY2FsbGVkIHRoaXMgZnVuY3Rpb25cbiAqL1xuZnVuY3Rpb24gbG9nKGRhdGEsIGNvbnRleHQsIGRldGVjdG9yKSB7XG4gICAgaWYgKGRldGVjdG9yID09PSB2b2lkIDApIHsgZGV0ZWN0b3IgPSBudWxsOyB9XG4gICAgLy8gRXh0cmFjdCBkZXRlY3RvciBjYWxsZXIgZnJvbSBzdGFjayB0cmFjZVxuICAgIGlmIChkZXRlY3RvciA9PT0gbnVsbClcbiAgICAgICAgZGV0ZWN0b3IgPSBnZXREZXRlY3RvcigpO1xuICAgIGRhdGEuZGV0ZWN0b3IgPSBkZXRlY3RvcjtcbiAgICB2YXIgbW9kdWxlcyA9IFByb2Nlc3MuZW51bWVyYXRlTW9kdWxlcygpO1xuICAgIGlmIChtb2R1bGVzLmxlbmd0aCA+IHNlbnRNb2R1bGVzLmxlbmd0aCkge1xuICAgICAgICAvLyBOZXcgbW9kdWxlcyBoYXZlIGJlZW4gbG9hZGVkLCBzZW5kIHRoZW0gdG8gcHl0aG9uXG4gICAgICAgIHNlbmQoe1xuICAgICAgICAgICAgdHlwZTogJ21vZHVsZXMnLFxuICAgICAgICAgICAgbW9kdWxlczogbW9kdWxlc1xuICAgICAgICB9KTtcbiAgICAgICAgc2VudE1vZHVsZXMgPSBtb2R1bGVzO1xuICAgIH1cbiAgICAvLyBBZGQgbmF0aXZlIGJhY2t0cmFjZVxuICAgIGlmIChkYXRhLmJhY2t0cmFjZSA9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgZGF0YS5iYWNrdHJhY2UgPSBUaHJlYWQuYmFja3RyYWNlKGNvbnRleHQsIEJhY2t0cmFjZXIuRlVaWlkpO1xuICAgIH1cbiAgICBpZiAoSmF2YS5hdmFpbGFibGUgJiYgZGF0YS5jb250ZXh0ICE9ICdqYXZhJykge1xuICAgICAgICAvLyBBZGQgamF2YSBiYWNrdHJhY2VcbiAgICAgICAgSmF2YS5wZXJmb3JtKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHZhciB0cmFjZSA9IEphdmEudXNlKCdqYXZhLmxhbmcuRXhjZXB0aW9uJykuJG5ldygpLmdldFN0YWNrVHJhY2UoKTtcbiAgICAgICAgICAgIGRhdGFbJ2phdmFfYmFja3RyYWNlJ10gPSB0cmFjZS5tYXAoZnVuY3Rpb24gKGUpIHsgcmV0dXJuIGUudG9TdHJpbmcoKS50cmltKCk7IH0pO1xuICAgICAgICAgICAgLy8gU2VuZCB0byBweXRob25cbiAgICAgICAgICAgIHNlbmQoZGF0YSk7XG4gICAgICAgIH0pO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgLy8gU2VuZCB0byBweXRob25cbiAgICAgICAgc2VuZChkYXRhKTtcbiAgICB9XG59XG5leHBvcnRzLmxvZyA9IGxvZztcbmZ1bmN0aW9uIGxvZ0Z1bmN0aW9uKGRhdGEsIGNvbmZpZGVudCkge1xuICAgIGlmIChjb25maWRlbnQgPT09IHZvaWQgMCkgeyBjb25maWRlbnQgPSB0cnVlOyB9XG4gICAgbG9nKHtcbiAgICAgICAgdHlwZTogJ2Z1bmN0aW9uJyxcbiAgICAgICAgY29udGV4dDogJ25hdGl2ZScsXG4gICAgICAgIFwiZnVuY3Rpb25cIjogZGF0YS5zeXNjYWxsLFxuICAgICAgICBhcmdzOiBkYXRhLmFyZ3MsXG4gICAgICAgIGNvbmZpZGVudDogY29uZmlkZW50XG4gICAgfSwgZGF0YS5jb250ZXh0LmNvbnRleHQsIGRhdGEuZGV0ZWN0b3IpO1xufVxuZXhwb3J0cy5sb2dGdW5jdGlvbiA9IGxvZ0Z1bmN0aW9uO1xuZnVuY3Rpb24gbG9nSmF2YUZ1bmN0aW9uKGRhdGEsIGNvbmZpZGVudCkge1xuICAgIGlmIChjb25maWRlbnQgPT09IHZvaWQgMCkgeyBjb25maWRlbnQgPSB0cnVlOyB9XG4gICAgbG9nKHtcbiAgICAgICAgdHlwZTogJ2Z1bmN0aW9uJyxcbiAgICAgICAgY29udGV4dDogJ2phdmEnLFxuICAgICAgICBcImZ1bmN0aW9uXCI6IGRhdGEuZnVuTmFtZSxcbiAgICAgICAgYXJnczogZGF0YS5hcmdzLFxuICAgICAgICBiYWNrdHJhY2U6IGRhdGEuYmFja3RyYWNlLFxuICAgICAgICBjb25maWRlbnQ6IGNvbmZpZGVudFxuICAgIH0sIGRhdGFbXCJ0aGlzXCJdLmNvbnRleHQsIGRhdGEuZGV0ZWN0b3IpO1xufVxuZXhwb3J0cy5sb2dKYXZhRnVuY3Rpb24gPSBsb2dKYXZhRnVuY3Rpb247XG5mdW5jdGlvbiBsb2dPYmpDRnVuY3Rpb24oZGF0YSwgY29uZmlkZW50KSB7XG4gICAgaWYgKGNvbmZpZGVudCA9PT0gdm9pZCAwKSB7IGNvbmZpZGVudCA9IHRydWU7IH1cbiAgICBsb2coe1xuICAgICAgICB0eXBlOiAnZnVuY3Rpb24nLFxuICAgICAgICBjb250ZXh0OiAnb2JqYycsXG4gICAgICAgIFwiZnVuY3Rpb25cIjogZGF0YS5mdW5OYW1lLFxuICAgICAgICBhcmdzOiBkYXRhLmFyZ3MubWFwKGZ1bmN0aW9uIChhcmcpIHsgcmV0dXJuIG5ldyBPYmpDLk9iamVjdChhcmcpLnRvU3RyaW5nKCk7IH0pLFxuICAgICAgICBjb25maWRlbnQ6IGNvbmZpZGVudFxuICAgIH0sIGRhdGFbXCJ0aGlzXCJdLmNvbnRleHQsIGRhdGEuZGV0ZWN0b3IpO1xufVxuZXhwb3J0cy5sb2dPYmpDRnVuY3Rpb24gPSBsb2dPYmpDRnVuY3Rpb247XG5mdW5jdGlvbiBnZXREZXRlY3RvcigpIHtcbiAgICB2YXIgc3RhY2sgPSAobmV3IEVycm9yKCkpLnN0YWNrO1xuICAgIHZhciBkZXRlY3Rvck1hdGNoID0gc3RhY2subWF0Y2goJ2RldGVjdG9ycy8oW15cXC5dKykudHMnKTtcbiAgICBpZiAoZGV0ZWN0b3JNYXRjaCkge1xuICAgICAgICByZXR1cm4gZGV0ZWN0b3JNYXRjaFsxXTtcbiAgICB9XG4gICAgZWxzZSBpZiAoc3RhY2suaW5kZXhPZignL3NjcmlwdDEuanMnKSA9PSAtMSkge1xuICAgICAgICBkZWJ1ZyhzdGFjayk7XG4gICAgICAgIHJldHVybiBudWxsO1xuICAgIH1cbn1cbmV4cG9ydHMuZ2V0RGV0ZWN0b3IgPSBnZXREZXRlY3RvcjtcbmZ1bmN0aW9uIGVycm9yKCkge1xuICAgIHZhciBtZXNzYWdlID0gW107XG4gICAgZm9yICh2YXIgX2kgPSAwOyBfaSA8IGFyZ3VtZW50cy5sZW5ndGg7IF9pKyspIHtcbiAgICAgICAgbWVzc2FnZVtfaV0gPSBhcmd1bWVudHNbX2ldO1xuICAgIH1cbiAgICBzZW5kKHtcbiAgICAgICAgdHlwZTogJ2xvZycsXG4gICAgICAgIGxldmVsOiAnZXJyb3InLFxuICAgICAgICBtZXNzYWdlOiBtZXNzYWdlLmpvaW4oJyAnKVxuICAgIH0pO1xufVxuZXhwb3J0cy5lcnJvciA9IGVycm9yO1xuZnVuY3Rpb24gd2FybigpIHtcbiAgICB2YXIgbWVzc2FnZSA9IFtdO1xuICAgIGZvciAodmFyIF9pID0gMDsgX2kgPCBhcmd1bWVudHMubGVuZ3RoOyBfaSsrKSB7XG4gICAgICAgIG1lc3NhZ2VbX2ldID0gYXJndW1lbnRzW19pXTtcbiAgICB9XG4gICAgc2VuZCh7XG4gICAgICAgIHR5cGU6ICdsb2cnLFxuICAgICAgICBsZXZlbDogJ3dhcm5pbmcnLFxuICAgICAgICBtZXNzYWdlOiBtZXNzYWdlLmpvaW4oJyAnKVxuICAgIH0pO1xufVxuZXhwb3J0cy53YXJuID0gd2FybjtcbmZ1bmN0aW9uIGluZm8oKSB7XG4gICAgdmFyIG1lc3NhZ2UgPSBbXTtcbiAgICBmb3IgKHZhciBfaSA9IDA7IF9pIDwgYXJndW1lbnRzLmxlbmd0aDsgX2krKykge1xuICAgICAgICBtZXNzYWdlW19pXSA9IGFyZ3VtZW50c1tfaV07XG4gICAgfVxuICAgIHNlbmQoe1xuICAgICAgICB0eXBlOiAnbG9nJyxcbiAgICAgICAgbGV2ZWw6ICdpbmZvJyxcbiAgICAgICAgbWVzc2FnZTogbWVzc2FnZS5qb2luKCcgJylcbiAgICB9KTtcbn1cbmV4cG9ydHMuaW5mbyA9IGluZm87XG5mdW5jdGlvbiBkZWJ1ZygpIHtcbiAgICB2YXIgbWVzc2FnZSA9IFtdO1xuICAgIGZvciAodmFyIF9pID0gMDsgX2kgPCBhcmd1bWVudHMubGVuZ3RoOyBfaSsrKSB7XG4gICAgICAgIG1lc3NhZ2VbX2ldID0gYXJndW1lbnRzW19pXTtcbiAgICB9XG4gICAgc2VuZCh7XG4gICAgICAgIHR5cGU6ICdsb2cnLFxuICAgICAgICBsZXZlbDogJ2RlYnVnJyxcbiAgICAgICAgbWVzc2FnZTogbWVzc2FnZS5qb2luKCcgJylcbiAgICB9KTtcbn1cbmV4cG9ydHMuZGVidWcgPSBkZWJ1ZztcbiIsIlwidXNlIHN0cmljdFwiO1xuZXhwb3J0cy5fX2VzTW9kdWxlID0gdHJ1ZTtcbmV4cG9ydHMuYWRkUnBjRXhwb3J0cyA9IGV4cG9ydHMud3JpdGVGaWxlID0gZXhwb3J0cy5yZWFkRmlsZSA9IGV4cG9ydHMuc3lzY2FsbCA9IHZvaWQgMDtcbi8qKlxuICogQ3JlYXRlIGEgTmF0aXZlRnVuY3Rpb24gdGhhdCBjYWxscyBhIHN5c2NhbGxcbiAqIEBwYXJhbSBuYW1lIHN5c2NhbGwgbmFtZVxuICogQHBhcmFtIHJldHVyblZhbHVlIHJldHVybiB2YWx1ZSB0eXBlXG4gKiBAcGFyYW0gYXJncyBhcmd1bWVudCB0eXBlc1xuICogQHJldHVybnMgTmF0aXZlRnVuY3Rpb24gb3IgbnVsbCBpZiBzeXNjYWxsIGRvZXNuJ3QgZXhpc3RcbiAqL1xuZnVuY3Rpb24gc3lzY2FsbChuYW1lLCByZXR1cm5WYWx1ZSwgYXJncykge1xuICAgIHZhciBhZGRyID0gTW9kdWxlLmZpbmRFeHBvcnRCeU5hbWUobnVsbCwgbmFtZSk7XG4gICAgaWYgKGFkZHIgPT09IG51bGwpXG4gICAgICAgIHJldHVybiBudWxsO1xuICAgIHJldHVybiBuZXcgTmF0aXZlRnVuY3Rpb24oYWRkciwgcmV0dXJuVmFsdWUsIGFyZ3MpO1xufVxuZXhwb3J0cy5zeXNjYWxsID0gc3lzY2FsbDtcbi8qKlxuICogUmVhZCBhIGZpbGUgZnJvbSB0aGUgZmlsZXN5c3RlbVxuICogQHBhcmFtIHBhdGggcGF0aCB0byB0aGUgZmlsZVxuICogQHJldHVybnMgZmlsZSBjb250ZW50cyBvciBudWxsIGlmIGZpbGUgZG9lc24ndCBleGlzdFxuICovXG5mdW5jdGlvbiByZWFkRmlsZShwYXRoKSB7XG4gICAgdmFyIG9wZW4gPSBzeXNjYWxsKCdvcGVuJywgJ2ludCcsIFsncG9pbnRlcicsICdpbnQnXSk7XG4gICAgdmFyIHJlYWQgPSBzeXNjYWxsKCdyZWFkJywgJ2ludCcsIFsnaW50JywgJ3BvaW50ZXInLCAnaW50J10pO1xuICAgIHZhciBjbG9zZSA9IHN5c2NhbGwoJ2Nsb3NlJywgJ2ludCcsIFsnaW50J10pO1xuICAgIHZhciBmZCA9IG9wZW4oTWVtb3J5LmFsbG9jVXRmOFN0cmluZyhwYXRoKSwgMCk7XG4gICAgaWYgKGZkID09PSAtMSlcbiAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgdmFyIGNvbnRlbnQgPSAnJztcbiAgICB2YXIgYnVmID0gTWVtb3J5LmFsbG9jKDQwOTYpO1xuICAgIHdoaWxlICh0cnVlKSB7XG4gICAgICAgIHZhciByZWFkQnl0ZXMgPSByZWFkKGZkLCBidWYsIDQwOTYpO1xuICAgICAgICBpZiAocmVhZEJ5dGVzID09PSAtMSlcbiAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICBpZiAocmVhZEJ5dGVzID09PSAwKVxuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIGNvbnRlbnQgKz0gYnVmLnJlYWRVdGY4U3RyaW5nKHJlYWRCeXRlcyk7XG4gICAgfVxuICAgIGNsb3NlKGZkKTtcbiAgICByZXR1cm4gY29udGVudDtcbn1cbmV4cG9ydHMucmVhZEZpbGUgPSByZWFkRmlsZTtcbi8qKlxuICogV3JpdGUgY29udGVudCB0byBhIGZpbGUgaW4gdGhlIGZpbGVzeXN0ZW1cbiAqIEBwYXJhbSBwYXRoIGZpbGUgdG8gd3JpdGUgdG9cbiAqIEBwYXJhbSBjb250ZW50IGNvbnRlbnQgdG8gd3JpdGVcbiAqIEByZXR1cm5zIHRydWUgaWYgc3VjY2Vzc2Z1bCwgZmFsc2Ugb3RoZXJ3aXNlXG4gKi9cbmZ1bmN0aW9uIHdyaXRlRmlsZShwYXRoLCBjb250ZW50KSB7XG4gICAgdHJ5IHtcbiAgICAgICAgLy8gQHRzLWlnbm9yZVxuICAgICAgICB2YXIgZmlsZSA9IG5ldyBGaWxlKHBhdGgsICd3Jyk7XG4gICAgICAgIC8vIEB0cy1pZ25vcmVcbiAgICAgICAgZmlsZS53cml0ZShjb250ZW50KTtcbiAgICAgICAgLy8gQHRzLWlnbm9yZVxuICAgICAgICBmaWxlLmZsdXNoKCk7XG4gICAgICAgIC8vIEB0cy1pZ25vcmVcbiAgICAgICAgZmlsZS5jbG9zZSgpO1xuICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9XG4gICAgY2F0Y2ggKGUpIHtcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cbn1cbmV4cG9ydHMud3JpdGVGaWxlID0gd3JpdGVGaWxlO1xuLyoqXG4gKiBBZGQgZnVuY3Rpb25zIHRvIHRoZSBycGMuZXhwb3J0cyBvYmplY3RcbiAqIEBwYXJhbSBleHBvcnRzIGZ1bmN0aW9ucyB0byBhZGRcbiAqL1xuZnVuY3Rpb24gYWRkUnBjRXhwb3J0cyhleHBvcnRzKSB7XG4gICAgT2JqZWN0LmFzc2lnbihycGMuZXhwb3J0cywgZXhwb3J0cyk7XG59XG5leHBvcnRzLmFkZFJwY0V4cG9ydHMgPSBhZGRScGNFeHBvcnRzO1xuIiwidmFyIG1hcCA9IHtcblx0XCIuL2RlYnVnLnRzXCI6IFwiLi9zcmMvZnJpZGEvZGV0ZWN0b3JzL2RlYnVnLnRzXCIsXG5cdFwiLi9lbXVsYXRpb24udHNcIjogXCIuL3NyYy9mcmlkYS9kZXRlY3RvcnMvZW11bGF0aW9uLnRzXCIsXG5cdFwiLi9ob29raW5nLnRzXCI6IFwiLi9zcmMvZnJpZGEvZGV0ZWN0b3JzL2hvb2tpbmcudHNcIixcblx0XCIuL2luZm8udHNcIjogXCIuL3NyYy9mcmlkYS9kZXRlY3RvcnMvaW5mby50c1wiLFxuXHRcIi4va2V5bG9nZ2VyLnRzXCI6IFwiLi9zcmMvZnJpZGEvZGV0ZWN0b3JzL2tleWxvZ2dlci50c1wiLFxuXHRcIi4vbG9ja3NjcmVlbi50c1wiOiBcIi4vc3JjL2ZyaWRhL2RldGVjdG9ycy9sb2Nrc2NyZWVuLnRzXCIsXG5cdFwiLi9waW5uaW5nLnRzXCI6IFwiLi9zcmMvZnJpZGEvZGV0ZWN0b3JzL3Bpbm5pbmcudHNcIixcblx0XCIuL3Jvb3QudHNcIjogXCIuL3NyYy9mcmlkYS9kZXRlY3RvcnMvcm9vdC50c1wiLFxuXHRcIi4vc2NyZWVucmVhZGVyLnRzXCI6IFwiLi9zcmMvZnJpZGEvZGV0ZWN0b3JzL3NjcmVlbnJlYWRlci50c1wiLFxuXHRcIi4vc3ZjLnRzXCI6IFwiLi9zcmMvZnJpZGEvZGV0ZWN0b3JzL3N2Yy50c1wiLFxuXHRcIi4vdGFtcGVyLnRzXCI6IFwiLi9zcmMvZnJpZGEvZGV0ZWN0b3JzL3RhbXBlci50c1wiXG59O1xuXG5cbmZ1bmN0aW9uIHdlYnBhY2tDb250ZXh0KHJlcSkge1xuXHR2YXIgaWQgPSB3ZWJwYWNrQ29udGV4dFJlc29sdmUocmVxKTtcblx0cmV0dXJuIF9fd2VicGFja19yZXF1aXJlX18oaWQpO1xufVxuZnVuY3Rpb24gd2VicGFja0NvbnRleHRSZXNvbHZlKHJlcSkge1xuXHRpZighX193ZWJwYWNrX3JlcXVpcmVfXy5vKG1hcCwgcmVxKSkge1xuXHRcdHZhciBlID0gbmV3IEVycm9yKFwiQ2Fubm90IGZpbmQgbW9kdWxlICdcIiArIHJlcSArIFwiJ1wiKTtcblx0XHRlLmNvZGUgPSAnTU9EVUxFX05PVF9GT1VORCc7XG5cdFx0dGhyb3cgZTtcblx0fVxuXHRyZXR1cm4gbWFwW3JlcV07XG59XG53ZWJwYWNrQ29udGV4dC5rZXlzID0gZnVuY3Rpb24gd2VicGFja0NvbnRleHRLZXlzKCkge1xuXHRyZXR1cm4gT2JqZWN0LmtleXMobWFwKTtcbn07XG53ZWJwYWNrQ29udGV4dC5yZXNvbHZlID0gd2VicGFja0NvbnRleHRSZXNvbHZlO1xubW9kdWxlLmV4cG9ydHMgPSB3ZWJwYWNrQ29udGV4dDtcbndlYnBhY2tDb250ZXh0LmlkID0gXCIuL3NyYy9mcmlkYS9kZXRlY3RvcnMgc3luYyByZWN1cnNpdmUgXFxcXC50cyRcIjsiLCIvLyBUaGUgbW9kdWxlIGNhY2hlXG52YXIgX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fID0ge307XG5cbi8vIFRoZSByZXF1aXJlIGZ1bmN0aW9uXG5mdW5jdGlvbiBfX3dlYnBhY2tfcmVxdWlyZV9fKG1vZHVsZUlkKSB7XG5cdC8vIENoZWNrIGlmIG1vZHVsZSBpcyBpbiBjYWNoZVxuXHR2YXIgY2FjaGVkTW9kdWxlID0gX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fW21vZHVsZUlkXTtcblx0aWYgKGNhY2hlZE1vZHVsZSAhPT0gdW5kZWZpbmVkKSB7XG5cdFx0cmV0dXJuIGNhY2hlZE1vZHVsZS5leHBvcnRzO1xuXHR9XG5cdC8vIENyZWF0ZSBhIG5ldyBtb2R1bGUgKGFuZCBwdXQgaXQgaW50byB0aGUgY2FjaGUpXG5cdHZhciBtb2R1bGUgPSBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX19bbW9kdWxlSWRdID0ge1xuXHRcdC8vIG5vIG1vZHVsZS5pZCBuZWVkZWRcblx0XHQvLyBubyBtb2R1bGUubG9hZGVkIG5lZWRlZFxuXHRcdGV4cG9ydHM6IHt9XG5cdH07XG5cblx0Ly8gRXhlY3V0ZSB0aGUgbW9kdWxlIGZ1bmN0aW9uXG5cdF9fd2VicGFja19tb2R1bGVzX19bbW9kdWxlSWRdLmNhbGwobW9kdWxlLmV4cG9ydHMsIG1vZHVsZSwgbW9kdWxlLmV4cG9ydHMsIF9fd2VicGFja19yZXF1aXJlX18pO1xuXG5cdC8vIFJldHVybiB0aGUgZXhwb3J0cyBvZiB0aGUgbW9kdWxlXG5cdHJldHVybiBtb2R1bGUuZXhwb3J0cztcbn1cblxuIiwiX193ZWJwYWNrX3JlcXVpcmVfXy5nID0gKGZ1bmN0aW9uKCkge1xuXHRpZiAodHlwZW9mIGdsb2JhbFRoaXMgPT09ICdvYmplY3QnKSByZXR1cm4gZ2xvYmFsVGhpcztcblx0dHJ5IHtcblx0XHRyZXR1cm4gdGhpcyB8fCBuZXcgRnVuY3Rpb24oJ3JldHVybiB0aGlzJykoKTtcblx0fSBjYXRjaCAoZSkge1xuXHRcdGlmICh0eXBlb2Ygd2luZG93ID09PSAnb2JqZWN0JykgcmV0dXJuIHdpbmRvdztcblx0fVxufSkoKTsiLCJfX3dlYnBhY2tfcmVxdWlyZV9fLm8gPSAob2JqLCBwcm9wKSA9PiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKG9iaiwgcHJvcCkpIiwiZ2xvYmFsLmNvbnRleHQgPSAne3tjb250ZXh0fX0nO1xuZ2xvYmFsLnNhZmVNb2RlID0gJ3t7c2FmZU1vZGV9fSc7XG5pZiAoSmF2YS5hdmFpbGFibGUpIHtcbiAgICAvLyBTYXZlIHRoZSBhcHBsaWNhdGlvbidzIGNsYXNzIGxvYWRlciBzaW5jZSB0aGUgZGVmYXVsdCBjbGFzcyBsb2FkZXIgaXNcbiAgICAvLyByZXBsYWNlZCBieSBGcmlkYSdzIGNsYXNzIGxvYWRlciBhZnRlciB1c2luZyBKYXZhLnJlZ2lzdGVyQ2xhc3NcbiAgICBKYXZhLnBlcmZvcm0oZnVuY3Rpb24gKCkge1xuICAgICAgICBnbG9iYWwuYXBwQ2xhc3NMb2FkZXIgPSBKYXZhLmNsYXNzRmFjdG9yeS5sb2FkZXI7XG4gICAgfSk7XG59XG5yZXF1aXJlKFwiLi9pbmMvdXRpbFwiKTtcbmlmIChQcm9jZXNzLnBsYXRmb3JtID09ICdkYXJ3aW4nKSB7XG4gICAgcmVxdWlyZShcIi4vaW5jL2R1bXBcIik7XG59XG4vLyBSZWdpc3RlciBkZXRlY3RvcnNcbnZhciBkZXRlY3RvcnMgPSByZXF1aXJlLmNvbnRleHQoXCIuL2RldGVjdG9yc1wiLCB0cnVlLCAvXFwudHMkLyk7XG5mb3IgKHZhciBfaSA9IDAsIF9hID0gZGV0ZWN0b3JzLmtleXMoKTsgX2kgPCBfYS5sZW5ndGg7IF9pKyspIHtcbiAgICB2YXIga2V5ID0gX2FbX2ldO1xuICAgIGRldGVjdG9ycyhrZXkpO1xufVxuIl0sIm5hbWVzIjpbXSwic291cmNlUm9vdCI6IiJ9