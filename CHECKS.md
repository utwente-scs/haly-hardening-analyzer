# Checks
This document lists all the functions and syscalls that are hooked to check for hardening techniques.  
Their implementations can be found in [`src/python/detectors`](src/python/detectors) and [`src/frida/detectors`](src/frida/detectors).

## Apps
### Android
- `android.app.ApplicationPackageManager`  
We hook pretty much all methods of the package manager that can be used in some way to check if an app is installed.
- `android.content.Intent`   
Intents can be used to launch another package and can also be used to check if an app is installed.

## Files
- File pointer tracking  
When a file is opened we save its name with the filepointer so we can track file access to e.g. `fstat`.
- Hooking of pretty much all file systemcalls  
We hook the families `open`, `stat`, `exec` etc. to track and possibly blacklist files.
- Possibility to change permissions to read-only
Can be used to e.g. make system directories be perceived as read-only on a rooted device even if they are not.
- Possibility to replace a file with a virtual different one  
Can be used to e.g. replace `/proc/mounts` to hide mounts related to Magisk

## Ports
- Local port scanning
Pretend a local port is not open even if it is. Can be used to e.g. hide Frida or SSH connections.

## Debug
### General
- `ptrace`  
Can be used to check if the app is being debugged.

### Android
- `android.os.Debug::isDebuggerConnected()`  
Can be used to check if a debugger is connected.
- `android.os.Debug::waitingForDebugger()`  
Can be used to check if the app is waiting for a debugger.
- `android.context.ContextWrapper::getApplicationInfo()`  
Can be used to check if `FLAG_DEBUGGABLE` (0x2) is set.
- `android.provider.Settings$Secure::getString(ContentResolver, String)`   
Values `adb_enabled`, `development_settings_enabled`, `mock_location` can be used to check if the app is being debugged.

### iOS
- `sysctl`
Can be used with parameters CTL_KERN, KERN_PROC, KERN_PROC_PID, pid to check if flag `P_TRACED` is set.
- `getppid`
Can be used to check if the parent process is a debugger.

## Emulation
### General
- File blacklists  
Files that are not present on a non-emulator device can be used to check if the device is an emulator.

### Android
- `android.os.Build::{BOARD, BRAND, DEVICE, ...}`  
Check various build properties to see if they match a known emulator.

### iOS
- `getenv()` and `NSProcessInfo.environment`
Check various environment variables to see if they match a known emulator.

## Hooking
### General
- File blacklists  
Files related to hooking frameworks that are not present on a stock device can be used to check if hooking frameworks are installed.
- App blacklists  
Apps related to hooking frameworks that are not present on a stock device can be used to check if hooking frameworks are installed.
- Open Frida port
Can be used to check if Frida is running.

## Android
- Replace proc maps and status files
`/proc/<pid>/maps` and `/proc/<pid>/task/<tid>/status` can be used to check if Frida is hooked into a process or thread.

## iOS
- `_dyld_get_image_name()`
Can be used together with `_dyld_image_count()` to check if a hooking framework is loaded into memory.

## Keylogger
### Android
- `android.view.inputmethod.InputMethodManager::getInputMethodList()`  
Can be used to check if an untrusted input method is installed.
- `android.view.inputmethod.InputMethodManager::getEnabledInputMethodList()`  
Can be used to check if an untrusted input method is enabled.
- `android.provider.Settings$Secure::getString(ContentResolver, String)`  
Values `default_input_method`, `enabled_input_methods` can be used to check what input methods are enabled.
- `android.widget.EditText::setShowSoftInputOnFocus(boolean)`  
Can be used to disable the soft keyboard on an input in order to show a custom keyboard.

### iOS
- `UIResponder.textInputMode` and `UITextInputMode.activeInputModes`
Can be used to check if an untrusted input method is installed or used.
- `UIView.inputView`
Can be used to replace the soft keyboard with a custom keyboard.

## Pinning
### General
- Find certificate files/hashes
During static analysis, we find certificate files and hashes that may be used for pinning.
- Hook functions related to pinning in popular libraries

## Root
### General
- File or directory permissions  
Files or directories that are ro on a non-rooted device but rw on a rooted device can be used to check if the device is rooted.
- File blacklists  
Files that are not present on a non-rooted device can be used to check if the device is rooted.
- App blacklists  
Apps that are not present on a non-rooted device can be used to check if the device is rooted.

### Android
- `/proc/mounts`  
Mounts that do not exist on a non-rooted device or rw permissions instead of ro can be used to check if the device is rooted.

### iOS
- `genfsstat` and `getmntinfo`
These syscalls can be used to check if the device is rooted by checking the flags of the root directory.
- Open SSH ports
Can be used to check if the device is rooted.

## Screenreader
### Android
- `android.view.SurfaceView::setSecure(boolean)`  
Can be used to disable screenshots and screen recording by setting secure to `true`.
- `android.view.Window::setFlags`  
Can be used to disable screenshots and screen recording by setting `FLAG_SECURE` (0x2000)

## SVC
### General
- `svc`  
An svc ARM instruction is used to execute a systemcall and can be used to obfuscate syscalls by not jumping to the syscall address directly. We find these calls during static analysis and hook the address of the svc instruction during dynamic analysis.

## Tamper
### Android
- `android.content.pm.PackageInfo::signatures`
- `android.content.pm.PackageInfo::signingInfo`
- `android.content.pm.PackageInfo::hasSigningCertificate()`   
Can be used to check if the app is signed with a trusted certificate.
- `com.google.android.play.core.integrity.IntegrityManager::requestIntegrityToken()`
Implementation of attestation using the Google Play Integrity API.
- `com.google.android.gms.safetynet.SafetyNetClient::attest()`
Implementation of attestation using the SafetyNet API.

### iOS
- `DCAppAttestService.attestKey`
Implementation of attestation using the Apple App Attest Service.