import { addJavaPreHook, JavaCallbackData } from "../hooks/java";
import { FilePattern, FileHooks } from "../hooks/file";
import { addPreHook } from "../hooks/native";
import { log, logFunction, logObjCFunction } from "../inc/log";
import { addObjCPreHook } from "../hooks/objc";

// Hide blacklisted files
FileHooks.getInstance().accessFileHook(FilePattern.from(global.context.emulation.files), true);

// We cannot hook Build.{field} because it is not a method
// We could approach this using taint analysis by setting the Build fields to a unique value
// and check if these values are used in e.g. String.equals(), however this is slows down the app too much

if (Process.platform == 'darwin') {
    let simulatorEnvs = global.context.emulation.environment;

    addPreHook('getenv', ['str'], (data) => {
        if (simulatorEnvs.indexOf(data.args[0]) >= 0) {
            logFunction(data);
        }
    }, 'libsystem_c.dylib');

    addObjCPreHook('-[NSProcessInfo environment]', 0, (data) => {
        // Since this returns an NSArray of environment variables, we cannot be sure
        // if these environment variables are checked for simulator environment variables
        logObjCFunction(data, false);
    });
}