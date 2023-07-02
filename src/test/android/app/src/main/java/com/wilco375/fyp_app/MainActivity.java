package com.wilco375.fyp_app;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Bundle;
import android.os.Debug;
import android.provider.Settings;
import android.view.inputmethod.InputMethodInfo;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;

import androidx.appcompat.app.AppCompatActivity;

import com.wilco375.fyp_app.databinding.ActivityMainBinding;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class MainActivity extends AppCompatActivity {

    static {
        System.loadLibrary("fyp_app");
    }

    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        setAllText();

        binding.getRoot().setOnClickListener(v -> {
            setAllText();
        });
    }

    private void setAllText() {
        binding.textInput.setText("");

        ///////////
        // Debug //
        ///////////
        setText("DEBUG", "");
        setText("isDebuggerConnected", !Debug.isDebuggerConnected());
        setText("waitingForDebugger", !Debug.waitingForDebugger());
        setText("FLAG_DEBUGGABLE", (getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0);
        setText("adb", Settings.Global.getInt(getContentResolver(), Settings.Global.ADB_ENABLED, 0) == 0);
        setText("developSettings", Settings.Secure.getInt(getContentResolver(), Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 0);
        setText("mockLocation", Settings.Secure.getInt(getContentResolver(), Settings.Secure.ALLOW_MOCK_LOCATION, 0) == 0);

        ///////////////
        // Emulation //
        ///////////////
        setText("\nEMULATION", "");
        setText("Build fields", !checkBuildFields());
        setText("Geny file", !new File("/dev/socket/genyd").exists());
        setText("Qemu file", !new File("/system/bin/qemu-props").exists());

        /////////////
        // Hooking //
        /////////////
        setText("\nHOOKING", "");
        boolean fridaInMaps = false;
        File maps = new File("/proc/self/maps");
        try {
            BufferedReader br = new BufferedReader(new FileReader(maps));
            String line;
            while ((line = br.readLine()) != null) {
                if (line.contains("frida")) {
                    fridaInMaps = true;
                    break;
                }
            }
            br.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        setText("Frida in maps", !fridaInMaps);

        boolean fridaInTaskStatus = false;
        // Loop over /proc/self/task/*/status
        File task = new File("/proc/self/task");
        File[] taskDirs = task.listFiles();
        for (File taskDir : taskDirs) {
            File status = new File(taskDir, "status");
            try {
                BufferedReader br = new BufferedReader(new FileReader(status));
                String line;
                while ((line = br.readLine()) != null) {
                    if (line.contains("frida")) {
                        fridaInTaskStatus = true;
                        break;
                    }
                }
                br.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        setText("Frida in task status", !fridaInTaskStatus);

        try {
            getClassLoader().loadClass("de.robv.android.xposed.XposedBridge");
            setText("Xposed class loader", false);
        } catch (ClassNotFoundException e) {
            setText("Xposed class loader", true);
        }

        try {
            getPackageManager().getApplicationInfo("de.robv.android.xposed.installer", 0);
            setText("Xposed app", false);
        } catch (PackageManager.NameNotFoundException e) {
            setText("Xposed app", true);
        }

        setText("Frida file", !new File("/system/bin/frida-server").exists());

        ///////////////
        // Keylogger //
        ///////////////
        setText("\nKEYLOGGER", "");
        InputMethodManager manager = (InputMethodManager) getSystemService(INPUT_METHOD_SERVICE);
        List<InputMethodInfo> list = manager.getEnabledInputMethodList();
        setText("Enabled input methods", true);

        String defaultInputMethod = Settings.Secure.getString(getContentResolver(), Settings.Secure.DEFAULT_INPUT_METHOD);
        setText("Default input method", true);

        EditText editText = new EditText(this);
        editText.setShowSoftInputOnFocus(false);
        setText("Hide soft input", true);

        /////////////
        // Pinning //
        /////////////
        setText("\nPINNING", "");
        SSLContext sslContext = null;
        try {
            sslContext = SSLContext.getInstance("TLS");
            TrustManager[] trustManagers = new TrustManager[]{new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    if (chain == null) {
                        throw new IllegalArgumentException("checkClientTrusted: X509Certificate array is null");
                    }
                    if (!(chain.length > 0)) {
                        throw new IllegalArgumentException("checkClientTrusted: X509Certificate is empty");
                    }
                    // Use assets/google.der to check
                    try (InputStream inStream = getAssets().open("google.der")) {
                        CertificateFactory cf = CertificateFactory.getInstance("X.509");
                        X509Certificate caCert = (X509Certificate) cf.generateCertificate(inStream);
                        for (X509Certificate cert : chain) {
                            // Check expiration date
                            cert.checkValidity();
                            // Check if google.com
                            cert.verify(caCert.getPublicKey());
                        }
                    } catch (Exception e) {
                        throw new CertificateException(e);
                    }
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    this.checkClientTrusted(chain, authType);
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }};
            sslContext.init(null, trustManagers, null);
            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
            HttpsURLConnection connection = (HttpsURLConnection) new URL("https://www.google.com").openConnection();
            setText("SSLContext", true);
        } catch (Exception e) {
            setText("SSLContext", false);
            setText(e.toString(), "");
        }

        //////////
        // Root //
        //////////
        setText("\nROOT", "");
        setText("su file", !new File("/system/bin/su").exists());
        boolean magiskInProcMounts = false;
        File procMounts = new File("/proc/mounts");
        try {
            BufferedReader br = new BufferedReader(new FileReader(procMounts));
            String line;
            while ((line = br.readLine()) != null) {
                if (line.contains("magisk")) {
                    magiskInProcMounts = true;
                    break;
                }
            }
            br.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        setText("Magisk in proc mounts", !magiskInProcMounts);
        try {
            getPackageManager().getPackageInfo("com.topjohnwu.magisk", 0);
            setText("Magisk app", false);
        } catch (PackageManager.NameNotFoundException e) {
            setText("Magisk app", true);
        }

        //////////////////
        // Screenreader //
        //////////////////
        setText("\nSCREENREADER", "");
        getWindow().setFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE, android.view.WindowManager.LayoutParams.FLAG_SECURE);
        setText("Secure flag", true);

        binding.randomSurfaceView.setSecure(true);
        setText("Secure SurfaceView", true);

        ////////////
        // Tamper //
        ////////////
        setText("\nTAMPER", "");
        try {
            Signature[] sigs = this.getPackageManager().getPackageInfo(this.getPackageName(), PackageManager.GET_SIGNATURES).signatures;
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
        setText("Signature", true);

        //////////////////////
        // Native functions //
        //////////////////////
        setText("\nNATIVE", "");
        binding.textInput.append(String.valueOf(stringFromJNI()));
    }

    private boolean checkBuildFields() {
        return ((Build.MANUFACTURER.equals("Google") && Build.BRAND.equals("google") &&
                ((Build.FINGERPRINT.startsWith("google/sdk_gphone_")
                        && Build.FINGERPRINT.endsWith(":user/release-keys")
                        && Build.PRODUCT.startsWith("sdk_gphone_")
                        && Build.MODEL.startsWith("sdk_gphone_"))
                        //alternative
                        || (Build.FINGERPRINT.startsWith("google/sdk_gphone64_")
                        && (Build.FINGERPRINT.endsWith(":userdebug/dev-keys") || Build.FINGERPRINT.endsWith(":user/release-keys"))
                        && Build.PRODUCT.startsWith("sdk_gphone64_")
                        && Build.MODEL.startsWith("sdk_gphone64_"))))
                //
                || Build.FINGERPRINT.startsWith("generic")
                || Build.FINGERPRINT.startsWith("unknown")
                || Build.MODEL.contains("google_sdk")
                || Build.MODEL.contains("Emulator")
                || Build.MODEL.contains("Android SDK built for x86")
                //bluestacks
                || "QC_Reference_Phone".equals(Build.BOARD) && !"Xiaomi".equals(Build.MANUFACTURER)
                //bluestacks
                || Build.MANUFACTURER.contains("Genymotion")
                || Build.HOST.startsWith("Build")
                //MSI App Player
                || Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")
                || Build.PRODUCT.equals("google_sdk"));
    }

    private void setText(String key, Object okOrText) {
        String value;
        if (okOrText instanceof Boolean) {
            value = ((Boolean) okOrText) ? "OK" : "NOT OK";
        } else {
            value = okOrText.toString();
        }

        if (!binding.textInput.getText().equals("")) {
            binding.textInput.append("\n");
        }
        binding.textInput.append(key + ": " + value);
    }

    /**
     * A native method that is implemented by the 'fyp_app' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();
}