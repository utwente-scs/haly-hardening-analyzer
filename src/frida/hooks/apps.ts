import { debug, log, logJavaFunction } from "../inc/log";
import { addJavaPostHook, addJavaPreHook, JavaCallbackData, JavaPostCallbackData } from "./java";
import { addObjCPreHook, ObjCCallbackData } from "./objc";
import { FilePattern } from './file'

export class AppsHooks {
    private static instance: AppsHooks;

    private constructor() { }

    public static getInstance(): AppsHooks {
        if (!AppsHooks.instance) {
            AppsHooks.instance = new AppsHooks();
        }

        return AppsHooks.instance;
    }

    /**
     * Blacklist a list of apps, so that the analyzed app detects it as not being installed
     * @param apps list of apps to blacklist
     */
    public blacklistAppsHook(apps: string[]) {
        if (Process.platform == 'darwin') {
            this.blacklistAppsHookIOS(apps);
        } else {
            this.blacklistAppsHookAndroid(apps);
        }
    }

    /**
     * Blacklist apps on iOS
     * @param apps list of apps to blacklist
     */
    private blacklistAppsHookIOS(apps: string[]) {
        let blacklist = FilePattern.from(apps);

        let checkBlacklist = (app: string, data: ObjCCallbackData, confident: boolean = true) => {
            let appURI = app.split('://')[0];
            if (blacklist.some(item => item.matches(appURI))) {
                log({
                    type: 'app',
                    context: 'objc',
                    app: app,
                    function: data.funName,
                    args: data.args.map(arg => new ObjC.Object(arg).toString()),
                    confident: confident
                }, data.this.context, data.detector)
                return true;
            } else {
                return false;
            }
        };

        addObjCPreHook('-[NSApplication canOpenURL:]', 1, (data) => {
            let app = new ObjC.Object(data.args[0]).toString();
            if (checkBlacklist(app, data)) {
                data.args[0] = ObjC.classes.NSURL.URLWithString_(ObjC.classes.NSString.stringWithString_('doesnotexist://'));
            }
        });

        addObjCPreHook('-[NSApplication openURL:]', 1, (data) => {
            let app = new ObjC.Object(data.args[0]).toString();
            if (checkBlacklist(app, data)) {
                data.args[0] = ObjC.classes.NSURL.URLWithString_(ObjC.classes.NSString.stringWithString_('doesnotexist://'));
            }
        });
    }

    /**
     * Blacklist apps on Android
     * @param apps list of apps to blacklist
     */
    private blacklistAppsHookAndroid(apps: string[]) {
        let checkBlacklist = (app: string, data: JavaCallbackData, confident: boolean = true) => {
            if (apps.includes(app)) {
                log({
                    type: 'app',
                    context: 'java',
                    app: app,
                    function: data.funName,
                    args: data.args,
                    backtrace: data.backtrace,
                    confident: confident
                }, data.this.context, data.detector)
                return true;
            } else {
                return false;
            }
        }

        // Hook PackageManager
        // TODO: Check that this also covers the `pm list packages` command once https://github.com/frida/frida/issues/2422 is resolved
        this.blacklistPackageManagerSingleApp(checkBlacklist);

        this.blacklistPackageManagerMultiApp(checkBlacklist);

        // Hook Intent
        this.blacklistIntent(checkBlacklist);

        // Hook ChangedPackages.getPackageNames()
        addJavaPostHook('android.content.pm.ChangedPackages::getPackageNames', [], (data: JavaPostCallbackData) => {
            let packages = data.retval;
            for (let i = 0; i < packages.size(); i++) {
                if (checkBlacklist(packages.get(i).toString(), data, false)) {
                    packages.remove(i);
                    i--;
                }
            }
        });

        // We could hook String comparison methods like String.equals to see if the app is comparing against a blacklisted app
        // but hooking String.equals is very slow and would slow down the app too much
    }

    /**
     * Blacklist apps on Android by hooking methods of the PackageManager class that take a single app as an argument
     * @param checkBlacklist function that checks if an app is blacklisted
     */
    private blacklistPackageManagerSingleApp(checkBlacklist: (app: string, data: JavaCallbackData) => boolean) {
        const PM = 'android.app.ApplicationPackageManager';

        // Signature (String packageName)
        addJavaPreHook([
            `${PM}::getApplicationBanner`,
            `${PM}::getApplicationEnabledSetting`,
            `${PM}::getApplicationIcon`,
            `${PM}::getApplicationLogo`,
            `${PM}::getInstallSourceInfo`,
            `${PM}::getInstallerPackageName`,
            `${PM}::getLaunchIntentForPackage`,
            `${PM}::getLaunchIntentSenderForPackage`,
            `${PM}::getLeanbackLaunchIntentForPackage`,
            `${PM}::getPackageGids`,
            `${PM}::getResourcesForApplication`,
            `${PM}::getTargetSdkVersion`,
            `${PM}::isPackageSuspended`
        ], ['str'], (data: JavaCallbackData) => {
            if (checkBlacklist(data.args[0], data)) {
                data.args[0] = 'doesnotexist';
            }
        });

        // Signature (String packageName, int flags)
        addJavaPreHook([
            `${PM}::getApplicationInfo`,
            `${PM}::getModuleInfo`,
            `${PM}::getPackageGids`,
            `${PM}::getPackageInfo`,
            `${PM}::getPackageUid`
        ], ['str', 'int'], (data: JavaCallbackData) => {
            if (checkBlacklist(data.args[0], data)) {
                data.args[0] = 'doesnotexist';
            }
        });

        // Signature (String packageName, int resourceId, ApplicationInfo appInfo)
        addJavaPreHook([
            `${PM}::getDrawable`,
            `${PM}::getText`,
            `${PM}::getXml`
        ], ['str', 'int', 'android.content.pm.ApplicationInfo'], (data: JavaCallbackData) => {
            if (checkBlacklist(data.args[0], data)) {
                data.args[0] = 'doesnotexist';
            }
        });

        // Signature (String packageName, PackageManager.ApplicationInfoFlags flags)
        addJavaPreHook([`${PM}::getApplicationInfo`], ['str', `${PM}.ApplicationInfoFlags`], (data: JavaCallbackData) => {
            if (checkBlacklist(data.args[0], data)) {
                data.args[0] = 'doesnotexist';
            }
        });

        // Signature (String packageName, PackageManager.PackageInfoFlags flags)
        addJavaPreHook([
            `${PM}::getPackageGids`,
            `${PM}::getPackageInfo`,
            `${PM}::getPackageUid`,
        ], ['str', `${PM}.PackageInfoFlags`], (data: JavaCallbackData) => {
            if (checkBlacklist(data.args[0], data)) {
                data.args[0] = 'doesnotexist';
            }
        });

        // Signature (String propertyName, String packageName)
        addJavaPreHook([
            `${PM}::checkPermission`,
            `${PM}::getProperty`,
        ], ['str', 'str'], (data: JavaCallbackData) => {
            if (checkBlacklist(data.args[1], data)) {
                data.args[1] = 'doesnotexist';
            }
        });
    }

    /**
     * Blacklist apps on Android by hooking methods of the PackageManager class that take a list of apps as an argument
     * @param checkBlacklist function that checks if an app is blacklisted
     */
    private blacklistPackageManagerMultiApp(checkBlacklist: (app: string, data: JavaCallbackData) => boolean) {
        let pm = 'android.app.ApplicationPackageManager';

        // Handler for methods that return List<ApplicationInfo | PackageInfo>
        let infoHandler = (data: JavaPostCallbackData) => {
            let apps = data.retval;
            for (let i = 0; i < apps.size(); i++) {
                let app = Java.cast(apps.get(i), Java.use(apps.get(i).getClass().getName()));
                if (checkBlacklist(app.packageName.value, data)) {
                    apps.remove(i);
                    i--;
                }
            }
        }

        // Signature (int flags) => List<ApplicationInfo | PackageInfo>
        addJavaPostHook([
            `${pm}::getInstalledApplications`,
            `${pm}::getInstalledPackages`
        ], ['int'], infoHandler);

        // Signature (PackageManager.PackageInfoFlags flags) => List<PackageInfo>
        addJavaPostHook([`${pm}::getInstalledPackages`], [`${pm}.PackageInfoFlags`], infoHandler);

        // Signature (String[] permissions, int flags) => List<PackageInfo>
        addJavaPostHook([`${pm}::getPackagesHoldingPermissions`], ['str[]', 'int'], infoHandler);

        // Signature (String[] packages, PackageManager.PackageInfoFlags flags) => List<PackageInfo>
        addJavaPostHook([`${pm}::getPackagesHoldingPermissions`], ['str[]', `${pm}.PackageInfoFlags`], infoHandler);

        // Signature (int flags) => List<PackageInfo>
        addJavaPostHook([`${pm}::getPreferredPackages`], ['int'], infoHandler);

        // Signature (int flags) => List<ModuleInfo>
        addJavaPostHook([`${pm}::getInstalledModules`], ['int'], (data: JavaPostCallbackData) => {
            let apps = data.retval;
            for (let i = 0; i < apps.size(); i++) {
                let app = Java.cast(apps.get(i), Java.use(apps.get(i).getClass().getName()));
                if (app == null) continue;
                if (checkBlacklist(app.getPackageName(), data)) {
                    apps.remove(i);
                    i--;
                }
            }
        });

        // Signature (int uid) => String[]
        addJavaPostHook([`${pm}::getPackagesForUid`], ['int'], (data: JavaPostCallbackData) => {
            let apps = data.retval;
            let newApps = [];
            for (let i = 0; i < apps.length; i++) {
                if (!checkBlacklist(apps[i], data)) {
                    newApps.push(apps[i]);
                }
            }
            data.retval = newApps;
        });
    }

    /**
     * Blacklist apps on Android by hooking methods of the Intent class
     * @param checkBlacklist function that checks if an app is blacklisted
     */
    private blacklistIntent(checkBlacklist: (app: string, data: JavaCallbackData) => boolean) {
        let intent = 'android.content.Intent';

        addJavaPreHook(`${intent}::setPackage`, ['str'], (data: JavaCallbackData) => {
            if (checkBlacklist(data.args[0], data)) {
                data.args[0] = 'doesnotexist';
            }
        });

        addJavaPreHook(`${intent}::setClassName`, ['str', 'str'], (data: JavaCallbackData) => {
            if (checkBlacklist(data.args[0], data)) {
                data.args[0] = 'doesnotexist';
            }
        });

        addJavaPreHook(`${intent}::setComponent`, ['android.content.ComponentName'], (data: JavaCallbackData) => {
            if (data.args[0] == null) return;
            if (checkBlacklist(data.args[0].getPackageName(), data)) {
                data.args[0].setPackageName('doesnotexist');
            }
        });
    }
}