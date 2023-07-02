import { addJavaPreHook } from "../hooks/java";
import { addObjCPreHook } from "../hooks/objc";
import { logJavaFunction, logObjCFunction } from "../inc/log";

const PM = 'android.app.ApplicationPackageManager';

addJavaPreHook(`${PM}::getPackageInfo`, ['str', 'int'], (data) => {
    // Check if GET_SIGNATURES (0x40) or GET_SIGNING_CERTIFICATES (0x8000000) is set for current app
    if (data.args[0] != global.context.info.package || ((data.args[1] & 0x40) == 0 && (data.args[1] & 0x8000000) == 0)) return;
    logJavaFunction(data, false)
});

addJavaPreHook(`${PM}::getInstalledPackages`, ['int'], (data) => {
    // Check if GET_SIGNATURES (0x40) or GET_SIGNING_CERTIFICATES (0x8000000) is set
    if ((data.args[0] & 0x40) == 0 && (data.args[0] & 0x8000000) == 0) return;
    logJavaFunction(data, false)
});

addJavaPreHook(`${PM}::hasSigningCertificate`, ['int', '[B', 'int'], (data) => {
    // TODO: Check uid
    logJavaFunction(data)
});
addJavaPreHook(`${PM}::hasSigningCertificate`, ['str', '[B', 'int'], (data) => {
    logJavaFunction(data, data.args[0] == global.context.info.package)
});

// Check if Google Play Integrity API is used
addJavaPreHook('com.google.android.play.core.integrity.IntegrityManager::requestIntegrityToken', null, (data) => {
    logJavaFunction(data)
});

// Check if SafetyNet API is used
addJavaPreHook('com.google.android.gms.safetynet.SafetyNetClient::attest', ['[B', 'str'], (data) => {
    logJavaFunction(data)
});
addJavaPreHook('com.google.android.gms.safetynet.SafetyNetClient::attest', ['str', '[B'], (data) => {
    logJavaFunction(data)
});

// Check if DCAppAttestService is used
addObjCPreHook('-[DCAppAttestService attestKey:clientDataHash:completionHandler:]', 0, (data) => {
    logObjCFunction(data)
});