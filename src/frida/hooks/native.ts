import { getDetector, debug } from "../inc/log";

/**
 * Return value pointer 
 * Fixes argument type of InvocationReturnValue.replace(value)
 */
export declare class InvocationReturnValue extends NativePointer {
    replace(value: NativePointerValue | number): void;
}

/**
 * Types to which arguments can be converted
 */
export type ArgType = 'str' | 'str[]' | 'uint' | 'int' | 'long' | 'ptr'; 

/**
 * Callback data for pre hooks
 */
export interface CallbackData {
    syscall: string;
    args: any[];
    context: InvocationContext;
    detector: string;
}

/**
 * Callback data for post hooks
 */
export interface PostCallbackData extends CallbackData {
    retval: InvocationReturnValue;
}

export type Hook = {
    syscall: string;
    type: 'pre' | 'post';
    argTypes: ArgType[];
    handler: (data: CallbackData | PostCallbackData) => void;
    detector: string;
    args: any[] | null;
};

let appliedHooks: {[key: string]: Hook[]} = {};

/**
 * Add a new hook to the given syscall(s) with a handler that is called before the syscall is executed (onEnter)
 * @param syscalls syscall or list of syscalls to intercept
 * @param argTypes list of types the arguments should be converted to
 * @param handler handler to call when the syscall is intercepted
 * @param mod module to search for the syscall in (defaults to null on macOS, libc.so on Android)
 */
export function addPreHook(syscalls: string | string[], argTypes: ArgType[] | null = null, handler: (data: CallbackData) => void, mod: string | null = null) {
    addHook(syscalls, 'pre', argTypes, handler, mod);
}

/**
 * Add a new hook to the given syscall(s) with a handler that is called after the syscall has returned (onLeave)
 * @param syscalls syscall or list of syscalls to intercept
 * @param argTypes list of types the arguments should be converted to
 * @param handler handler to call when the syscall has returned
 * @param mod module to search for the syscall in (defaults to null on macOS, libc.so on Android)
 */
export function addPostHook(syscalls: string | string[], argTypes: ArgType[] | null = null, handler: (data: PostCallbackData) => void, mod: string | null = null) {
    addHook(syscalls, 'post', argTypes, handler, mod);
}

/**
 * Add a new hook to the given syscall(s)
 * @param syscall syscall or list of syscalls to intercept
 * @param type call handler either on onEnter (pre) or onLeave (post)
 * @param argTypes list of types the arguments should be converted to
 * @param handler handler to call when the syscall is intercepted
 * @param mod module to search for the syscall in (defaults to null on macOS, libc.so on Android)
 */
function addHook(syscall: string | string[], type: 'pre' | 'post', argTypes: ArgType[] | null, handler: (data: CallbackData) => void, mod: string | null = null) {
    if (syscall instanceof Array) {
        // Add hook for every syscall in the array
        syscall.forEach((s) => {
            addHook(s, type, argTypes, handler);
        })
        return;
    }

    // Also add a hook for the 64 bit version of the syscall
    if (!syscall.endsWith('64')) addHook(syscall + '64', type, argTypes, handler);

    if (mod === null) {
        // On iOS, the syscalls are spread over multiple modules so we let Frida find the correct module
        mod = Process.platform === 'darwin' ? null : 'libc.so';
    }
    let syscallPointer = Module.findExportByName(mod, syscall);
    if (syscallPointer === null) {
        if (!syscall.endsWith('64')) {
            let androidOnlySyscalls = ['android_fdsan_close_with_tag', 'android_fdsan_set_owner_tag', 'readdir64_r', 'execvpe'];
            if (Process.platform == 'darwin' && androidOnlySyscalls.indexOf(syscall) >= 0) return;
            debug("[!] Unable to find syscall", syscall);
        } 
        return;
    }

    let detector = getDetector();

    if (appliedHooks[syscall] === undefined) {
        // We only apply one hook to a syscall because we get undefined behaviour when we attach multiple times
        appliedHooks[syscall] = [];
        appliedHooks[syscall].push({ syscall, type, argTypes, handler, detector, args: null });

        Interceptor.attach(syscallPointer, {
            onEnter(args) {
                let hooks = appliedHooks[syscall];
                hooks.forEach((hook) => {
                    // Save arguments for post hook
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
                                    args[i] = Memory.allocUtf8String(hook.args[i]);
                                } else if (typeof hook.args[i] === 'number') {
                                    if (hook.argTypes[i] === 'uint' || hook.argTypes[i] === 'int') {
                                        args[i] = ptr(hook.args[i])
                                    } else if (hook.argTypes[i] === 'long') {
                                        args[i].writeLong(hook.args[i]);
                                    }
                                } else {
                                    args[i] = hook.args[i];
                                }
                            }
                        }
                    }
                });
            },
            onLeave(retval) {
                let hooks = appliedHooks[syscall];
                hooks.forEach((hook) => {
                    if (hook.type !== 'post') return;

                    let data: PostCallbackData = { args: hook.args, retval, syscall, context: this, detector: hook.detector }
                    hook.handler(data)
                });
            }
        });
    } else {
        appliedHooks[syscall].push({ syscall, type, argTypes, handler, detector, args: null });
    }
}

/**
 * Get a list of all the hooked native functions
 * @returns list of all the hooked native functions as a dictionary mapping the syscall name to the hook
 */
export function getAppliedHooks(): {[key: string]: Hook[]} {
    return appliedHooks;
}

/**
 * Convert arguments from NativePointers to the given types
 * @param args arguments as a list of NativePointers
 * @param argTypes types the arguments need to be converted to, indexes correspond with elements in args
 * @param syscall the syscall for which the arguments are converted
 * @returns list of converted arguments
 */
export function convertArgs(args: NativePointer[], argTypes: ArgType[] | null, syscall: string): any[] {
    if (argTypes === null) return args;

    let convertedArgs: any[] = [];

    // Convert argument types
    for (let i = 0; i < argTypes.length; i++) {
        try {
            switch (argTypes[i]) {
                case 'str':
                    convertedArgs.push(args[i].readCString());
                    break;
                case 'uint':
                    convertedArgs.push(args[i].toUInt32());
                    break;
                case 'int':
                    convertedArgs.push(args[i].toInt32());
                    break;
                case 'long': 
                    convertedArgs.push(args[i].readLong());
                case 'ptr':
                    convertedArgs.push(args[i]);
                    break;
                case 'str[]':
                    convertedArgs.push([]);
                    let arrayI = 0;
                    while (!args[i].add(arrayI).readPointer().isNull()) {
                        convertedArgs[i].push(args[i].add(arrayI).readPointer().readCString());
                        arrayI += Process.pointerSize;
                    }
                default:
                    debug("argType", argTypes[i], "is not implemented");
                    convertedArgs.push(null);
            }
        } catch (e) {
            convertedArgs.push(null);

            if (e.toString().indexOf("access violation") != -1) continue;
            debug("Failed to convert argument", i, "of syscall", syscall, ":", e);
        }
    }

    return convertedArgs;
}