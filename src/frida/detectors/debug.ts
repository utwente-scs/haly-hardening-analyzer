import { addJavaPostHook } from "../hooks/java";
import { addPreHook, addPostHook } from "../hooks/native";
import { logFunction, logJavaFunction } from "../inc/log";

addJavaPostHook('android.os.Debug::isDebuggerConnected', [], (data) => {
    logJavaFunction(data);
    data.retval = false;
});

addJavaPostHook('android.os.Debug::waitingForDebugger', [], (data) => {
    logJavaFunction(data);
    data.retval = false;
});

// We don't hook ContextWrapper.getApplicationInfo() because it would cause a lot of false positives
// and make the app unresponsive, even though it could be used to check the app for FLAG_DEBUGGABLE

addJavaPostHook('android.provider.Settings$Secure::getString', ['android.content.ContentResolver', 'str'], (data) => {
    if (['adb_enabled', 'development_settings_enabled', 'mock_location'].includes(data.args[1])) {   
        logJavaFunction(data);
        if (data.funName.includes('String')) {
            data.retval = '0';
        } else {
            data.retval = 0;
        }
    }
});

addPreHook('ptrace', ['int', 'int', 'int', 'int'], (data) => {
    logFunction(data);

    // No need to patch value, we don't use tracing
});

if (Process.platform == 'darwin') {
    addPreHook('sysctl', ['ptr', 'uint', 'ptr', 'uint', 'ptr', 'uint'], (data) => {
        let mib = data.args[0];
        let ctl = mib.readU32();
        var kern = mib.add(4).readU32();
        var kernProc = mib.add(8).readU32();
        var kernProcPid = mib.add(12).readU32();
        if (ctl == 1 && kern == 14 && kernProc == 1) { // 1 = CTL_KERN, 14 = KERN_PROC, 1 = KERN_PROC_PID
            // https://msolarana.netlify.app/2018/09/14/anti-debugging/#using-sysctl
            // Returned value can be checked for P_TRACED flag
            let logArgs = [[ctl, kern, kernProc, kernProcPid]].concat(data.args.slice(1));
            logFunction({
                ...data,
                args: logArgs
            }, false);
            
            // No need to patch return value, we don't use tracing
        }
    })

    addPostHook('getppid', [], (data) => {
        logFunction(data);

        // Parent process id should always be 1 (launchd)
        data.retval.replace(1);
    });
}