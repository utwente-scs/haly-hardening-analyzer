import { JavaCallbackData, addJavaPreHook, addJavaReplaceHook } from "../hooks/java";
import { addPostHook, addPreHook, CallbackData, PostCallbackData } from "../hooks/native";
import { ObjCPostCallbackData } from "../hooks/objc";
import { ObjCCallbackData, addObjCPreHook, addObjCPostHook } from "../hooks/objc";
import { logFunction, logJavaFunction, logObjCFunction } from "../inc/log";

////////////////////////////
// Android Pinning bypass //
////////////////////////////
// https://github.com/NEU-SNS/app-tls-pinning/blob/b0469990ad37c3068c227a44aa5f5bfb824ec3f7/code/certificate-pinning/DynamicAnalysis/frida/bypass_all_pinning.js

// TrustManager (Android < 7)
if (Java.available) {
    Java.perform(function() {
        const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        const TrustManager = Java.registerClass({
            // Implement a custom TrustManager
            name: 'nl.wilcovanbeijnum.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () {return []; }
            }
        });
        const trustManagers = [TrustManager.$new()];

        addJavaPreHook('javax.net.ssl.SSLContext::init', ['[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'], (data: JavaCallbackData) => {
            // Override the init method, specifying the custom TrustManager
            data.args[1] = trustManagers;
            logJavaFunction(data, false);
        }, false);
    });
}

let returnVoidHook = function(data: JavaCallbackData, confident: boolean = true) {
    logJavaFunction(data, confident);
};

let returnTrueHook = function(data: JavaCallbackData, confident: boolean = true) {
    logJavaFunction(data, confident);
    return true;
};

let okhttp3Pins = function(data) {
    if (data.this.findMatchingPins) {
        return data.this.findMatchingPins(data.args[0]).size() > 0;
    } else if (data.this.getPins) {
        return data.this.getPins().size() > 0;
    } else {
        return false;
    }
}

// OkHTTPv3
addJavaReplaceHook('okhttp3.CertificatePinner::check', ['str', 'java.util.List'], (data) => returnVoidHook(data, okhttp3Pins(data)));
addJavaReplaceHook('okhttp3.CertificatePinner::check', ['str', 'java.security.cert.Certificate'], (data) => returnVoidHook(data, okhttp3Pins(data)));
addJavaReplaceHook('okhttp3.CertificatePinner::check', ['str', 'str'], (data: JavaCallbackData) => {
    logJavaFunction(data, okhttp3Pins(data));
    return data.args[1];
});
addJavaReplaceHook('okhttp3.CertificatePinner::check', ['str', 'kotlin.jvm.functions.Function0'], (data) => returnVoidHook(data, data.this.getPins().size() > 0));


// Trustkit
addJavaReplaceHook('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier::verify', ['str', 'javax.net.ssl.SSLSession'], (data) => returnTrueHook(data, false));
addJavaReplaceHook('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier::verify', ['str', 'java.security.cert.X509Certificate'], (data) => returnTrueHook(data, false));
addJavaReplaceHook('com.datatheorem.android.trustkit.pinning.PinningTrustManager::checkServerTrusted', ['[Ljava.security.cert.X509Certificate;', 'str'], (data) => returnVoidHook(data, data.this.serverConfig.shouldEnforcePinning()));

// TrustManagerImpl (Android > 7)
addJavaReplaceHook('com.android.org.conscrypt.TrustManagerImpl::verifyChain', ['[Ljava.security.cert.X509Certificate;', '[Ljava.security.cert.TrustAnchor;', 'str', 'boolean', '[B', '[B'], (data: JavaCallbackData) => {
    logJavaFunction(data, data.args[1].length > 0);
    return data.args[0];
});

// Appcelerator Titanium PinningTrustManager
addJavaReplaceHook('appcelerator.https.PinningTrustManager::checkServerTrusted', ['[Ljava.security.cert.X509Certificate;', 'str'], (data) => returnVoidHook(data, false));

// Fabric PinningTrustManager
addJavaReplaceHook('io.fabric.sdk.android.services.network.PinningTrustManager::checkServerTrusted', ['[Ljava.security.cert.X509Certificate;', 'str'], (data) => returnVoidHook(data, data.this.pins.size() > 0));

// Conscrypt OpenSSLSocketImpl
addJavaReplaceHook('com.android.org.conscrypt.OpenSSLSocketImpl::verifyCertificateChain', ['[J', 'str'], (data) => returnVoidHook(data, false));

// Conscrypt OpenSSLEngineSocketImpl
addJavaReplaceHook('com.android.org.conscrypt.OpenSSLEngineSocketImpl::verifyCertificateChain', ['[J', 'str'], (data) => returnVoidHook(data, false));

// Apache Harmony OpenSSLSocketImpl
addJavaReplaceHook('org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl::verifyCertificateChain', ['[[B', 'str'], (data) => returnVoidHook(data, false));

// PhoneGap sslCertificateChecker
addJavaReplaceHook('nl.xservices.plugins.sslCertificateChecker::execute', ['str', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext'], (data) => returnTrueHook(data, data.args[1].getJSONArray(2).length() > 0));

// IBM MobileFirst WLClient
addJavaReplaceHook('com.worklight.wlclient.api.WLClient::pinTrustedCertificatePublicKey', ['str'], returnVoidHook);
addJavaReplaceHook('com.worklight.wlclient.api.WLClient::pinTrustedCertificatePublicKey', ['str[]'], returnVoidHook);

// IBM WorkLight HostNameVerifierWithCertificatePinning
addJavaReplaceHook('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning::verify', ['str', 'javax.net.ssl.SSLSocket'], (data) => returnVoidHook(data, false));
addJavaReplaceHook('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning::verify', ['str', 'java.security.cert.X509Certificate'], (data) => returnVoidHook(data, false));
addJavaReplaceHook('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning::verify', ['str[]', 'str[]'], (data) => returnVoidHook(data, false));
addJavaReplaceHook('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning::verify', ['str', 'javax.net.ssl.SSLSession'], (data) => returnTrueHook(data, false));

// Conscrypt CertPinManager
addJavaReplaceHook('org.conscrypt.CertPinManager::checkChainPinning', ['str', 'java.util.List'], returnVoidHook);

// Conscrypt CertPinManager (Legacy)
addJavaReplaceHook('org.conscrypt.CertPinManager::isChainValid', ['str', 'java.util.List'], (data) => returnTrueHook);

// CWAC-Netsecurity CertPinManager
addJavaReplaceHook('com.commonsware.cwac.netsecurity.conscrypt.CertPinManager::isChainValid', ['str', 'java.util.List'], returnTrueHook);

// Worklight Androidgap WLCertificatePinningPlugin
addJavaReplaceHook('com.worklight.androidgap.plugin.WLCertificatePinningPlugin::execute', ['str', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext'], returnTrueHook);

// Netty FingerprintTrustManagerFactory
addJavaReplaceHook('io.netty.handler.ssl.util.FingerprintTrustManagerFactory::checkTrusted', ['str', '[Ljava.security.cert.X509Certificate;'], (data) => returnVoidHook(data, data.this.fingerprints.length > 0));

// Squareup CertificatePinner
addJavaReplaceHook('com.squareup.okhttp.CertificatePinner::check', ['str', '[Ljava.security.cert.Certificate;'], (data) => returnVoidHook(data, data.this.hostnameToPins.get(data.args[0]) != null));
addJavaReplaceHook('com.squareup.okhttp.CertificatePinner::check', ['str', 'java.util.List'], (data) => returnVoidHook(data, data.this.hostnameToPins.get(data.args[0]) != null));

// Squareup OkHostnameVerifier
addJavaReplaceHook('com.squareup.okhttp.internal.tls.OkHostnameVerifier::verify', ['str', 'java.security.cert.X509Certificate'], (data) => returnTrueHook(data, false));
addJavaReplaceHook('com.squareup.okhttp.internal.tls.OkHostnameVerifier::verify', ['str', 'javax.net.ssl.SSLSession'], (data) => returnTrueHook(data, false));

// Android WebViewClient
addJavaReplaceHook('android.webkit.WebViewClient::onReceivedSslError', ['android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError'], (data) => returnVoidHook(data, false));
addJavaReplaceHook('android.webkit.WebViewClient::onReceivedSslError', ['android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError'], (data) => returnVoidHook(data, false));
addJavaReplaceHook('android.webkit.WebViewClient::onReceivedError', ['android.webkit.WebView', 'int', 'str', 'str'], (data) => returnVoidHook(data, false));
addJavaReplaceHook('android.webkit.WebViewClient::onReceivedError', ['android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError'], (data) => returnVoidHook(data, false));

// Apache Cordova WebViewClient
addJavaReplaceHook('org.apache.cordova.CordovaWebViewClient::onReceivedSslError', ['org.apache.cordova.CordovaWebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError'], (data: JavaCallbackData) => {
    logJavaFunction(data, false);
    data.args[2].proceed();
});

// Boye AbstractVerifier
addJavaReplaceHook('ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier::verify', ['str', 'javax.net.ssl.SSLSocket'], (data) => returnVoidHook(data, false));

// Apache AbstractVerifier
addJavaReplaceHook('org.apache.http.conn.ssl.AbstractVerifier::verify', ['str', 'str[]', 'str[]', 'boolean'], (data) => returnVoidHook(data, false));
addJavaReplaceHook('org.apache.http.conn.ssl.AbstractVerifier::verify', ['str', 'java.security.cert.X509Certificate'], (data) => returnVoidHook(data, false));
addJavaReplaceHook('org.apache.http.conn.ssl.AbstractVerifier::verify', ['str', 'javax.net.ssl.SSLSession'], (data) => returnTrueHook(data, false));
addJavaReplaceHook('org.apache.http.conn.ssl.AbstractVerifier::verify', ['str', 'javax.net.ssl.SSLSocket'], (data) => returnVoidHook(data, false));

// Chromium Cronet
addJavaPreHook('org.chromium.net.CronetEngine$Builder::enablePublicKeyPinningBypassForLocalTrustAnchors', ['boolean'], (data: JavaCallbackData) => {    
    data.args[0] = true;
});
addJavaReplaceHook('org.chromium.net.CronetEngine$Builder::addPublicKeyPins', ['str', 'java.util.Set', 'boolean', 'java.util.Date'], (data: JavaCallbackData) => {
    logJavaFunction(data);
    
    return data.this;
});

// Flutter Pinning packages http_certificate_pinning and ssl_pinning_plugin
addJavaReplaceHook('diefferson.http_certificate_pinning.HttpCertificatePinning::checkConnexion', ['java.lang.String', 'java.util.List', 'java.util.Map', 'int', 'java.lang.String'], returnTrueHook);
addJavaReplaceHook('com.macif.plugin.sslpinningplugin.SslPinningPlugin::checkPinning', ['java.lang.String', 'java.util.List', 'java.util.Map', 'int', 'java.lang.String'], returnTrueHook);

// Commbank KIAWhitelist 
addJavaReplaceHook('com.ICTSecurity.KIA.KIAWhitelist::verifyCertificate', ['str', 'str'], (data) => returnTrueHook(data, false));

////////////////////////
// iOS Pinning bypass //
////////////////////////
// https://github.com/sensepost/objection/blob/f47926e90ce8b6655ecb431730b6674e41bc5625/agent/src/ios/pinning.ts
if (global.safeMode != 'yes') {
    // AFSecurityPolicy setSSLPinningMode
    addObjCPreHook('-[AFSecurityPolicy setSSLPinningMode:]', 1, (data: ObjCCallbackData) => {
        if (!data.args[0].isNull()) {
            logObjCFunction(data);
            
            data.args[0] = ptr(0);
        }
    });

    // AFSecurityPolicy setAllowInvalidCertificates
    addObjCPreHook('-[AFSecurityPolicy setAllowInvalidCertificates:]', 1, (data: ObjCCallbackData) => {
        data.args[0] = ptr(1); // true
    });

    // AFSecurityPolicy policyWithPinningMode
    addObjCPreHook('+[AFSecurityPolicy policyWithPinningMode:]', 1, (data: ObjCCallbackData) => {
        if (!data.args[0].isNull()) {
            logObjCFunction(data);

            data.args[0] = ptr(0); // AFSSLPinningModeNone
        }
    });

    // AFSecurityPolicy policyWithPinningMode
    addObjCPreHook('+[AFSecurityPolicy policyWithPinningMode:withPinnedCertificates:]', 2, (data: ObjCCallbackData) => {
        if (!data.args[0].isNull()) {
            logObjCFunction(data);

            data.args[0] = ptr(0); // AFSSLPinningModeNone
        }
    });
}

if (ObjC.available) {
    const NSURLCredential = ObjC.classes.NSURLCredential;
    let resolver = new ApiResolver("objc");
    let search: ApiResolverMatch[] = resolver.enumerateMatches("-[* URLSession:didReceiveChallenge:completionHandler:]");
    for (const match of search) {
        Interceptor.attach(match.address, {
            onEnter(args) {
                let self = new ObjC.Object(args[0]);
                let selector = ObjC.selectorAsString(args[1]);

                let method = self.$methods.find(m => m.endsWith(' ' + selector));
                let funName = method.substring(0, 1) + '[' + self.$className + ' ' + method.substring(2) + ']';

                logObjCFunction({
                    fun: null,
                    funName: funName,
                    self: self,
                    args: [args[2], args[3]],
                    this: this,
                    detector: null
                }, false);

                let challenge = new ObjC.Object(args[3]);

                let completionHandler = new ObjC.Block(args[4]);
                let savedCompletionHandler = completionHandler.implementation;

                completionHandler.implementation = () => {
                    let credential = NSURLCredential.credentialForTrust_(challenge.protectionSpace().serverTrust());
                    let sender = challenge.sender();
                    if (sender != null) {
                        sender.useCredential_forAuthenticationChallenge_(credential, challenge);
                    }
                    savedCompletionHandler(0, credential);
                };
            },
        });
    }
}

// TSKPinningValidator evaluateTrust
addObjCPostHook('-[TSKPinningValidator evaluateTrust:forHostname:]', 2, (data: ObjCPostCallbackData) => {
    if (!data.retval.isNull()) {
        logObjCFunction(data);

        data.retval.replace(ptr(0));
    }
});

// CustomURLConnectionDelegate isFingerprintTrusted
addObjCPostHook('-[CustomURLConnectionDelegate isFingerprintTrusted:]', 1, (data: ObjCPostCallbackData) => {
    if (data.retval.isNull()) {
        logObjCFunction(data);

        data.retval.replace(ptr(1)); // true
    }
});

// SSLSetSessionOption
addPreHook('SSLSetSessionOption', ['ptr', 'int', 'int'], (data: CallbackData) => {
    if (data.args[1] == 0) { // option == SSLSessionOption.breakOnServerAuth
        logFunction(data, false);

        data.args[2] = 1; // true
    }
}, 'Security');

// SSLCreateContext
addPostHook('SSLCreateContext', ['ptr', 'int', 'int'], (data: PostCallbackData) => {
    let ctx = data.retval;
    if (!ctx.isNull()) {
        let SSLSetSessionOption = new NativeFunction(Module.findExportByName('Security', 'SSLSetSessionOption'), 'int', ['pointer', 'int', 'int']);
        SSLSetSessionOption(ctx, 0, 1); // SSLSessionOption.breakOnServerAuth true
    }
}, 'Security');

// SSLHandshake
addPostHook('SSLHandshake', ['ptr'], (data: PostCallbackData) => {
    if (data.retval.toInt32() == -9481) { // errSSLServerAuthCompleted
        let SSLHandshake = new NativeFunction(Module.findExportByName('Security', 'SSLHandshake'), 'int', ['pointer']);
        data.retval.replace(ptr(0));
        SSLHandshake(data.args[0]);
    }
}, 'Security');

// tls_helper_create_peer_trust and nw_tls_create_peer_trust
let functions = ['tls_helper_create_peer_trust', 'nw_tls_create_peer_trust'];
functions.forEach(functionName => {
    let func = Module.findExportByName(null, functionName);
    if (func != null) {
        Interceptor.replace(func, new NativeCallback((tls, server, trustRef) => {
            return 0; // errSecSuccess
        }, 'int', ['pointer', 'bool', 'pointer']));
    }
});

// SSL_set_custom_verify
if (ObjC.available) {
    let customVerify = Module.findExportByName(null, 'SSL_CTX_set_custom_verify');
    if (customVerify == null) {
        customVerify = Module.findExportByName(null, 'SSL_set_custom_verify');
    }
    let pskIdentity = Module.findExportByName(null, 'SSL_get_psk_identity');
    if (customVerify != null && pskIdentity != null) {
        const SSL_set_custom_verify = new NativeFunction(customVerify, 'void', ['pointer', 'int', 'pointer']);
        const SSL_get_psk_identity = new NativeFunction(pskIdentity, 'pointer', ['pointer']);

        const customVerifyCallback = new NativeCallback(function (ssl, out_alert) {
            return 0;
        }, "int", ["pointer", "pointer"]);

        Interceptor.replace(SSL_set_custom_verify, new NativeCallback(function (ssl, mode, callback) {
            logFunction({
                syscall: 'SSL_set_custom_verify',
                args: [ssl, mode, callback],
                // @ts-ignore
                context: this,
                detector: null,
            }, false)

            SSL_set_custom_verify(ssl, mode, customVerifyCallback);
        }, "void", ["pointer", "int", "pointer"]));

        Interceptor.replace(SSL_get_psk_identity, new NativeCallback(function (ssl) {
            return Memory.allocUtf8String('fakeIdentity');
        }, "pointer", ["pointer"]));
    }
}