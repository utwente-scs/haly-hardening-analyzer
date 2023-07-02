import { addRpcExports } from "../inc/util";
import { CallbackData, PostCallbackData, convertArgs, getAppliedHooks, InvocationReturnValue } from '../hooks/native'
import { log, debug, warn } from "../inc/log";

addRpcExports({
    hookSvcs
})

// List of svc instructions that could not be hooked when starting the app
let unhookedSvcs = [];

/**
 * Hook system calls by the addresses of the svc asm instructions
 * @param svcs svc instruction offsets, grouped by module name
 * @param appClass app class to use as the class loader when dynamically loading libraries
 */
function hookSvcs(svcs: object) {
    if (global.safeMode == 'yes') return;

    // Hook svcs
    Object.keys(svcs).forEach(moduleName => {
        let module: Module = Process.findModuleByName(moduleName);
        let modulePath: string = svcs[moduleName][0]['path'];

        let loadSvcs = () => {
            svcs[moduleName].forEach(svc => {
                hookSvc(module.base, svc['offset'], module.name);
            });
        }
        let deferLoadSvcs = (error: any) => {
            warn("Failed to dynamically load library", moduleName, error)
            svcs[moduleName].forEach(svc => {
                unhookedSvcs.push({
                    module: moduleName,
                    address: svc['offset']
                });
            });
        }

        if (module == null) {
            // Try to load the module using System.loadLibrary
            // We don´t want to hook the svcs after the library is loaded by the app since we might miss 
            // some executions of svc calls just after the library is loaded because it takes some time for 
            // the hooks to be applied when the app is running
            // Instead we load and hook the library while the app is still paused
            if (Java.available) {
                Java.perform(() => {
                    try {
                        const Runtime = Java.use('java.lang.Runtime');
                        let classLoaderClass;
                        if (global.appClassLoader) {
                            classLoaderClass = global.appClassLoader;
                        } else {
                            classLoaderClass = Java.classFactory.loader;
                        }
                        // loadLibrary(String libname, ClassLoader loader) is no longer available on newer Android versions
                        // so we use the undocumented function loadLibrary0(Class<?> fromClass, String libname) instead
                        // This might break on future Android versions
                        // TODO: Hook VMStack.getCallingClassLoader() to return the classloader of appClass instead
                        Runtime.getRuntime().loadLibrary0(classLoaderClass, modulePath);
                        module = Process.findModuleByName(moduleName);
                        loadSvcs();
                    } catch (e) {
                        if (e.toString().includes('unable to intercept function')) {
                            // For some reason, some apps segfault if we catch this exception
                            // We ignore this error in src/python/dynamic.py
                            // TODO: Validate this does not prevent the rest of the script from running
                            throw e;
                        } else {
                            deferLoadSvcs(e);
                        }
                    }
                });
            } else if (ObjC.available) {
                try {
                    let bundlePath = ObjC.classes.NSBundle.mainBundle().bundlePath();
                    bundlePath = bundlePath.stringByAppendingPathComponent_(modulePath);
                    if (modulePath.endsWith(".framework")) {
                        let bundle = ObjC.classes.NSBundle.bundleWithPath_(bundlePath);
                        if (bundle.isLoaded()) {
                            warn("Failed to dynamically load framework", moduleName, "framework already loaded but not available as a module")
                        }
                        if (bundle.load()) {
                            loadSvcs();
                        } else {
                            deferLoadSvcs("failed to load bundle");
                        }
                    } else if (modulePath.endsWith('.dylib')) {
                        let dlopen = new NativeFunction(Module.findExportByName(null, 'dlopen'), 'pointer', ['pointer', 'int']);
                        if(dlopen(Memory.allocUtf8String(bundlePath.UTF8String()), 9)) {
                            loadSvcs();
                        } else {
                            deferLoadSvcs("failed to load dylib");
                        }
                    } else {
                        deferLoadSvcs("unknown library type");
                    }
                } catch (e) {
                    deferLoadSvcs(e);
                }
            }
        } else {
            loadSvcs();
        }
    })

    let libdl = Process.platform == 'darwin' ? 'libdyld.dylib' : 'libdl.so';
    Interceptor.attach(Module.findExportByName(libdl, 'dlopen'), {
        onEnter: function () {
            hookUnhookedSvcs();
        }
    })
    if (Process.platform != 'darwin') {
        // Crashes the app if hooked on iOS
        Interceptor.attach(Module.findExportByName(libdl, 'dlsym'), {
            onEnter: function (args) {
                // Check if the function is JNI_OnLoad, which is called after a library is loaded
                if (args[1].readUtf8String() != 'JNI_OnLoad') return;

                hookUnhookedSvcs();
            }
        })
    }
}

function hookSvc(moduleBaseAddress: NativePointer, svcAddress: number | NativePointer, module: string) {
    let syscall = null;
    let syscallArgs = [];

    let address = moduleBaseAddress.add(svcAddress);

    try {
        // On entering a svc syscall
        Interceptor.attach(address, function () {
            let id = this.context[Process.platform == 'darwin' ? 'x16' : 'x8'].toInt32();
            syscall = global.context.syscall_names[id];

            let appliedHooks = getAppliedHooks();
            if (appliedHooks[syscall] === undefined) return;

            let args = ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7'].map((arg) => ptr(this.context[arg]));

            log({
                type: 'svc',
                context: 'native',
                function: 'svc',
                args: args,
                confident: true,
                svc_id: id,
                svc_syscall: syscall
            }, this.context);

            appliedHooks[syscall].forEach(hook => {
                hook.args = convertArgs(args, hook.argTypes, syscall);

                if (hook.type === 'pre') {
                    let hookArgs = [...hook.args];
                    let data: CallbackData = { args: hook.args, syscall, context: this, detector: hook.detector };
                    hook.handler(data);

                    // Replace arguments if they were changed
                    for (let i = 0; i < hookArgs.length; i++) {
                        if (hookArgs[i] !== hook.args[i]) {
                            // If string, use Memory.allocUtf8String
                            if (typeof hook.args[i] === 'string') {
                                this.context['x' + i] = Memory.allocUtf8String(hook.args[i]);
                            } else if (typeof hook.args[i] === 'number') {
                                if (hook.argTypes[i] === 'uint') {
                                    if (hook.argTypes[i] === 'uint' || hook.argTypes[i] === 'int') {
                                        this.context['x' + i] = ptr(hook.args[i])
                                    } else if (hook.argTypes[i] === 'long') {
                                        this.context['x' + i].writeLong(hook.args[i]);
                                    }
                                } else {
                                    this.context['x' + i] = Memory.alloc(4).writeInt(hook.args[i]);
                                }
                            } else {
                                this.context['x' + i] = hook.args[i];
                            }
                        }
                    }
                }
            });
        });

        // On return from a svc syscall
        Interceptor.attach(address.add(4), function () {
            if (syscall == null) return;

            let appliedHooks = getAppliedHooks();
            if (appliedHooks[syscall] === undefined) return;

            // Create return value as InvocationReturnValue
            let returnValue = ptr(this.context['x0']) as InvocationReturnValue;
            returnValue.replace = (value: number | NativePointerValue) => {
                this.context['x0'] = value;
            }

            appliedHooks[syscall].forEach(hook => {
                if (hook.type === 'post') {
                    let data: PostCallbackData = { args: hook.args, syscall, retval: returnValue, context: this, detector: hook.detector };
                    hook.handler(data);
                }
            });
        });
    } catch (e) {
        warn("Failed to hook svc at", address, e)
    }
}

function hookUnhookedSvcs() {
    let newUnhookedSvcs = [];

    unhookedSvcs.forEach(svc => {
        let module = Process.findModuleByName(svc['module']);
        if (module != null) {
            hookSvc(module.base, svc['address'], module.name);
        } else {
            newUnhookedSvcs.push(svc);
        }
    });

    unhookedSvcs = newUnhookedSvcs;
}