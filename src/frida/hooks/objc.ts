import { getDetector, debug } from "../inc/log";
import { CallbackData } from "./native";

export interface ObjCCallbackData {
    fun: any;
    funName: string;
    args: any[];
    self: any;
    this: any;
    detector: string;
}

type Hook = {
    objcFun: any;
    type: 'pre' | 'post';
    handler: (data: ObjCCallbackData | ObjCPostCallbackData) => void;
    detector: string;
};

let appliedHooks: Hook[] = [];

/**
 * Callback data for post hooks
 */
export interface ObjCPostCallbackData extends ObjCCallbackData {
    retval: any;
}

/**
 * Hook an Objective-C function before calling its original implementation, allowing for the modification of arguments
 * @param fun function to hook
 * @param argCount number of arguments the function takes
 * @param handler callback function to call before the original function
 * @param detector detector that called this function
 */
export function addObjCPreHook(fun: string | string[] | any | any[], argCount: number, handler: (data: ObjCCallbackData) => void, detector: string | null = null) {
    addHook(fun, argCount, 'pre', handler, detector);
}

/**
 * Hook an Objective-C function after calling its original implementation, allowing for the modification of the return value
 * @param fun function to hook
 * @param argCount number of arguments the function takes
 * @param handler callback function to call after the original function
 * @param detector detector that called this function
 */
export function addObjCPostHook(fun: string | string[] | any | any[], argCount: number, handler: (data: ObjCPostCallbackData) => void, detector: string | null = null) {
    addHook(fun, argCount, 'post', handler, detector);
}

/**
 * Hook an Objective-C function and replace its original implementation
 * @param fun function to hook
 * @param argCount number of arguments the function takes
 * @param handler callback function to call instead of the original function
 * @param detector detector that called this function
 */
function addHook(fun: string | string[] | any | any[], argCount: number, type: 'pre' | 'post', handler: (data: ObjCCallbackData) => void, detector: string | null = null) {
    // TODO: Does this work properly if the same function is hooked multiple times?
    if (fun instanceof Array) {
        // Add hook for every syscall in the array
        fun.forEach((f) => {
            addHook(f, argCount, type, handler);
        })
        return;
    }

    if (!ObjC.available) {
        return;
    }

    if (detector == null) {
        detector = getDetector();
    }

    let objcFun: any;
    let funName: string = null;
    if (typeof fun === 'string') {
        let modifier = fun.substring(0, 1);
        let identifier = fun.substring(1).replace('[', '').replace(']', '').split(' ');
        let cls = identifier[0];
        let name = identifier[1];
        let objcCls = ObjC.classes[cls];
        if (objcCls === undefined && cls == 'NSApplication') {
            cls = 'UIApplication';
            objcCls = ObjC.classes[cls];
        }
        if (objcCls === undefined) {
            debug(`[!] Unable to find class ${cls} in Objective-C`);
            return;
        }
        objcFun = objcCls[modifier + ' ' + name];
        if (objcFun === undefined) {
            debug(`[!] Unable to find function ${fun} in Objective-C`);
            return;
        }
    } else {
        objcFun = fun;
    } 


    let isHooked = appliedHooks.find(h => h.objcFun === objcFun);
    appliedHooks.push({ objcFun, type, handler, detector });
    if (!isHooked) {
        let self;
        let selector;
        let funArgs;
        Interceptor.attach(objcFun.implementation, {
            onEnter: function (args) {
                self = new ObjC.Object(args[0]);
                selector = ObjC.selectorAsString(args[1]);
                funArgs = [];
                for (let i = 0; i < argCount; i++) {
                    funArgs.push(args[i + 2]);
                }
                if (!funName) {
                    let method = self.$methods.find(m => m.endsWith(' ' + selector));
                    funName = method.substring(0, 1) + '[' + self.$className + ' ' + method.substring(2) + ']';
                }

                let hooks = appliedHooks.filter(h => h.objcFun === objcFun);
                hooks.forEach(hook => {
                    if (hook.type === 'pre') {
                        let data: ObjCCallbackData = { fun: objcFun, funName, args: funArgs, self: self, this: this, detector: hook.detector };
                        hook.handler(data);
                        for (let i = 0; i < argCount; i++) {
                            args[i + 2] = funArgs[i];
                        }
                    }
                })
            },
            onLeave: function (retval) {
                let hooks = appliedHooks.filter(h => h.objcFun === objcFun);
                hooks.forEach(hook => {
                    if (hook.type === 'post') {
                        let data: ObjCPostCallbackData = { fun: objcFun, funName, args: funArgs, self: self, this: this, retval, detector: hook.detector };
                        hook.handler(data);
                    }
                })
            }
        })
    }
}