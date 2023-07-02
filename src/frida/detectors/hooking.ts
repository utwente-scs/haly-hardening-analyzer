import { AppsHooks } from "../hooks/apps";
import { FilePattern, FileHooks } from "../hooks/file";
import { addPostHook } from "../hooks/native";
import { addJavaPreHook } from "../hooks/java";
import { logFunction, logJavaFunction, warn } from "../inc/log";
import { readFile } from "../inc/util";
import { addOpenPortHook } from "../hooks/socket";

let fileHooks = FileHooks.getInstance();
let appsHooks = AppsHooks.getInstance();

let filesPattern = FilePattern.from(global.context.hooking.files)
// Hide blacklisted files
fileHooks.accessFileHook(filesPattern, true);

appsHooks.blacklistAppsHook(global.context.hooking.apps);

// Hook _dyld_get_image_name
addPostHook('_dyld_get_image_name', ['int'], (data) => {
    if (data.args[0] == 0) {
        // Main app binary, always queried on app startup
        return;
    }

    let imageName = data.retval.isNull() ? null : data.retval.readUtf8String();
    let matches = imageName && filesPattern.some(item => item.matches(imageName));
    if (matches) {
        data.retval.replace(Memory.allocUtf8String('nonexistentlib.dylib'));
    }

    logFunction({
        ...data,
        args: [
            data.args[0],
            imageName
        ]
    }, false);
});

addPostHook('_dyld_image_count', [], (data) => {
    logFunction(data, false);
});

if (Java.available) {
    Java.perform(() => {
        Java.enumerateClassLoaders({
            onMatch(loader) {
                [['str'], ['str', 'bool']].forEach(argTypes => {
                    addJavaPreHook(loader.loadClass, argTypes, (data) => {
                        // Check for attempts to load e.g. de.robv.android.xposed.XposedBridge
                        global.context.hooking.apps.forEach(app => {
                            if (data.args[0].toLowerCase().includes(app)) {
                                logJavaFunction(data);
                            }
                        });
                    }, false);
                });
            },
            onComplete() {}
        });
    })
}

// Add port hook for default Frida port (27042)
addOpenPortHook(27042);

if (Java.available) {
    Java.perform(() => {
        // Hide Frida from /proc/<pid>/maps since tempFileNaming prefix can end up in maps.
        // https://github.com/sensepost/objection/blob/f47926e90ce8b6655ecb431730b6674e41bc5625/agent/src/android/pinning.ts#L43
        // https://github.com/frida/frida-java-bridge/blob/8b3790f7489ff5be7b19ddaccf5149d4e7738460/lib/class-factory.js#L94
        if (Java.classFactory.tempFileNaming.prefix == 'frida') {
            Java.classFactory.tempFileNaming.prefix = 'hardeninganalyzer';
        }
    });
}

// Modify /proc/<pid>/maps files
fileHooks.replaceFileHook('/proc/', 'maps', (filename) => {
    let maps = readFile(filename);
    if (maps == null) {
        warn("Failed to read " + filename);
        return null;
    }

    let modifiedMaps = '';
    for (let line of maps.split('\n')) {
        // Remove traces of frida from maps
        if (line.includes('frida')) continue;

        line = line.replace('rwxp', 'r-xp');

        modifiedMaps += line + '\n';
    }

    return modifiedMaps;
}, false);


// Modify /proc/<pid>/task/<tid>/status files
fileHooks.replaceFileHook('/proc/', 'status', (filename) => {
    let maps = readFile(filename);
    if (maps == null) {
        warn("Failed to read " + filename);
        return null;
    }

    let modifiedMaps = '';
    for (let line of maps.split('\n')) {
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
