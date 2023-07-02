import { addJavaPreHook } from "../hooks/java";

addJavaPreHook('android.app.Activity::onCreate', ['android.os.Bundle'], (data) => {
    if (global.safeMode == 'yes') return;

    let packageName = data.this.getPackageName();
    let pm = data.this.getPackageManager();
    let packageInfo = pm.getPackageInfo(packageName, 0);
    let appInfo = data.this.getApplicationInfo();
    let labelRes = appInfo.labelRes.value;
    let launchIntent = pm.getLaunchIntentForPackage(packageName);
    let info = {
        type: 'info',
        detector: 'info',
        info: {
            name: labelRes ? data.this.getString(labelRes) : appInfo.nonLocalizedLabel.value,
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
    let infoDict = ObjC.classes.NSBundle.mainBundle().infoDictionary();
    let info = {
        type: 'info',
        detector: 'info',
        info: {
            name: infoDict.objectForKey_("CFBundleDisplayName")?.toString() || infoDict.objectForKey_("CFBundleName")?.toString(),
            package: infoDict.objectForKey_("CFBundleIdentifier")?.toString(),
            executable: infoDict.objectForKey_("CFBundleExecutable")?.toString(),
            version_code: infoDict.objectForKey_("CFBundleVersion")?.toString(),
            version_name: infoDict.objectForKey_("CFBundleShortVersionString")?.toString(),
            min_sdk: infoDict.objectForKey_("MinimumOSVersion")?.toString(),
            main_activity: infoDict.objectForKey_("UILaunchStoryboardName")?.toString(),
        }
    }
    send(info);
}