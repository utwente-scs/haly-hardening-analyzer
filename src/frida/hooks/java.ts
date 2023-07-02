import { getDetector, debug } from "../inc/log";

export interface JavaCallbackData {
    fun: any;
    funName: string;
    args: any[];
    this: any;
    detector: string;
    backtrace: string[];
}

type Hook = {
    javaFun: any;
    type: 'pre' | 'post' | 'replace';
    handler: (data: JavaCallbackData | JavaPostCallbackData) => void;
    detector: string;
};

let appliedHooks: Hook[] = [];

/**
 * Callback data for post hooks
 */
export interface JavaPostCallbackData extends JavaCallbackData {
    retval: any;
}

/**
 * Hook a Java function before calling its original implementation, allowing for the modification of arguments
 * @param fun function to hook
 * @param argTypes types of the arguments of the function to hook. Used to find the correct overload of the function. If null, the first overload is used
 * @param handler callback function to call before the original function
 * @param initJava whether to initialize Java context before hooking. Set to false if you are already in a Java.perform() block
 * @param detector detector that called this function
 */
export function addJavaPreHook(fun: string | string[] | any | any[], argTypes: string[] | null = null, handler: (data: JavaCallbackData) => void, initJava: boolean = true, detector: string | null = null) {
    addHook(fun, 'pre', argTypes, handler, initJava, detector);
}

/**
 * Hook a Java function after calling its original implementation, allowing for the modification of the return value
 * @param fun function to hook
 * @param argTypes types of the arguments of the function to hook. Used to find the correct overload of the function. If null, the first overload is used
 * @param handler callback function to call after the original function
 * @param initJava whether to initialize Java context before hooking. Set to false if you are already in a Java.perform() block
 * @param detector detector that called this function
 */
export function addJavaPostHook(fun: string | string[] | any | any[], argTypes: string[] | null = null, handler: (data: JavaPostCallbackData) => void, initJava: boolean = true, detector: string | null = null) {
    addHook(fun, 'post', argTypes, handler, initJava, detector);
}

/**
 * Hook a Java function and replace its original implementation
 * @param fun function to hook
 * @param argTypes types of the arguments of the function to hook. Used to find the correct overload of the function. If null, the first overload is used
 * @param handler callback function to call instead of the original function
 * @param initJava whether to initialize Java context before hooking. Set to false if you are already in a Java.perform() block
 * @param detector detector that called this function
 */
export function addJavaReplaceHook(fun: string | string[] | any | any[], argTypes: string[] | null = null, handler: (data: JavaPostCallbackData) => void, initJava: boolean = true, detector: string | null = null) {
    addHook(fun, 'replace', argTypes, handler, initJava, detector);
}

/**
 * Hook a Java function
 * @param fun function to hook
 * @param type type of hook to add
 * @param argTypes types of the arguments of the function to hook. Used to find the correct overload of the function. If null, the first overload is used
 * @param handler callback function to call when hooked function is called
 * @param initJava whether to initialize Java context before hooking. Set to false if you are already in a Java.perform() block
 * @param detector detector that called this function
 */
function addHook(fun: string | string[] | any | any[], type: 'pre' | 'post' | 'replace', argTypes: string[] | null, handler: (data: JavaCallbackData) => void, initJava: boolean = true, detector: string | null = null) {
    if (fun == 'android.provider.Settings$Secure::getString') {
        ['Secure', 'Global'].forEach((cls) => {
            ['String', 'Int', 'Long', 'Float'].forEach((varType) => {
                if (varType !== 'String' || cls === 'Global') {
                    addHook(`android.provider.Settings$${cls}::get${varType}`, type, argTypes, handler);
                }
                if (varType !== 'String') {
                    addHook(`android.provider.Settings$${cls}::get${varType}`, type, [...argTypes, varType.toLowerCase()], handler);
                }
            });
        });
    }
    
    if (fun instanceof Array) {
        // Add hook for every syscall in the array
        fun.forEach((f) => {
            addHook(f, type, argTypes, handler);
        })
        return;
    }

    if (typeof fun !== 'string') {
        // Assume Java already initialized and we are in a Java.perform() block
        initJava = false;
    }

    if (initJava && !Java.available) {
        return;
    }

    // Replace argType 'str' with 'java.lang.String'  and '[]' with '[L...;'
    if (argTypes) {
        argTypes = argTypes.map((argType) => {
            if (argType === 'str') {
                return 'java.lang.String';
            } else if (argType === 'str[]') {
                return '[Ljava.lang.String;';
            } else if (argType.endsWith('[]')) {
                return `[L${argType.slice(0, -2)};`;
            } else {
                return argType;
            }
        });
    }

    if (initJava && !detector) {
        detector = getDetector();
    }

    let overwriteFunction = () => {
        let javaFun: any;
        let funName: string = null;
        if (typeof fun === 'string') {
            let cls = fun.split('::')[0];
            let name = fun.split('::')[1];
            let javaCls;
            try {
                javaCls = Java.use(cls);
            } catch (e) {
                debug(`[!] Unable to find class ${cls} in Java`);
                return;
            }
            javaFun = javaCls[name];
            if (!javaFun) {
                debug(`[!] Unable to find function ${fun} in Java`);
                return;
            }
            funName = fun.replace('$', '.');
        } else {
            javaFun = fun;
        }

        try {
            if (argTypes !== null) {
                javaFun = javaFun.overload(...argTypes);
            }
            if (!javaFun) {
                debug(`[!] Unable to find overload of function ${fun} in Java`);
                return;
            }
        } catch (e) {
            debug(`[!] Unable to find function ${fun} with argTypes ${argTypes} in Java`);
            return;
        }

        let isHooked = appliedHooks.find(hook => hook.javaFun === javaFun);
        appliedHooks.push({ javaFun, type, handler, detector });
        if (!isHooked) {
            javaFun.implementation = function (...args) {
                let trace = Java.use('java.lang.Exception').$new().getStackTrace();
                if (!funName) {
                    let method = trace[0];
                    funName = method.getClassName().replace('$', '.') + "::" + method.getMethodName();
                }

                let backtrace = trace.map(e => e.toString().trim());

                let hooks = appliedHooks.filter(hook => hook.javaFun === javaFun);

                let replaced = false;
                let retval;
                hooks.forEach(hook => {
                    if (hook.type === 'replace') {
                        let data: JavaCallbackData = { fun: javaFun, funName, args, this: this, detector: hook.detector, backtrace };
                        retval = hook.handler(data);
                        replaced = true;
                    }
                });

                if (replaced) {
                    return retval;
                }

                hooks.forEach(hook => {
                    if (hook.type === 'pre') {
                        let data: JavaCallbackData = { fun: javaFun, funName, args, this: this, detector: hook.detector, backtrace };
                        hook.handler(data);

                        // Convert any string args to Java.lang.String
                        args.map(arg => arg instanceof String ? Java.use('java.lang.String').$new(arg) : arg);
                    }
                });

                retval = javaFun.call(this, ...args);

                let originalRetval = retval;
                hooks.forEach(hook => {
                    if (hook.type === 'post') {
                        let data: JavaPostCallbackData = { fun: javaFun, funName, args, this: this, retval, detector: hook.detector, backtrace };
                        hook.handler(data);

                        if (data.retval !==  originalRetval) {
                            retval = data.retval;
                        }
                    }
                });

                return retval;
            };
        }
    };

    if (initJava) {
        Java.perform(overwriteFunction);
    } else {
        overwriteFunction();
    }
}