import { JavaCallbackData } from '../hooks/java';
import { CallbackData } from '../hooks/native';
import { ObjCCallbackData } from '../hooks/objc';
import { Message } from './messages';

let sentModules = [];

/**
 * Send a message to Python
 * @param message message to send
 * @param context context of the program, used to attach a backtrace to the message
 * @param detector detector that called this function
 */
export function log(data: Message, context: CpuContext, detector: string | null = null) {
    // Extract detector caller from stack trace
    if (detector === null)
        detector = getDetector()
    
    data.detector = detector;

    let modules = Process.enumerateModules();
    if (modules.length > sentModules.length) {
        // New modules have been loaded, send them to python
        send({
            type: 'modules',
            modules: modules,
        })
        sentModules = modules;
    }

    // Add native backtrace
    if (data.backtrace == undefined) {
        data.backtrace = Thread.backtrace(context, Backtracer.FUZZY)
    }
    if (Java.available && data.context != 'java') {
        // Add java backtrace
        Java.perform(() => {
            let trace = Java.use('java.lang.Exception').$new().getStackTrace();
            data['java_backtrace'] = trace.map(e => e.toString().trim());

            // Send to python
            send(data)
        })
    } else {
        // Send to python
        send(data)
    }
}

export function logFunction(data: CallbackData, confident: boolean = true) {
    log({
        type: 'function',
        context: 'native',
        function: data.syscall,
        args: data.args,
        confident: confident,
    }, data.context.context, data.detector)
}

export function logJavaFunction(data: JavaCallbackData, confident: boolean = true) {
    log({
        type: 'function',
        context: 'java',
        function: data.funName,
        args: data.args,
        backtrace: data.backtrace,
        confident: confident,
    }, data.this.context, data.detector)
}

export function logObjCFunction(data: ObjCCallbackData, confident: boolean = true) {
    log({
        type: 'function',
        context: 'objc',
        function: data.funName,
        args: data.args.map(arg => new ObjC.Object(arg).toString()),
        confident: confident,
    }, data.this.context, data.detector)
}

export function getDetector(): string | null {
    let stack = (new Error()).stack
    let detectorMatch = stack.match('detectors/([^\.]+).ts');
    if (detectorMatch) {
        return detectorMatch[1];
    } else if (stack.indexOf('/script1.js') == -1) {
        debug(stack)
        return null;
    }
}

export function error(...message: any[]) {
    send({
        type: 'log',
        level: 'error',
        message: message.join(' ')
    })
}

export function warn(...message: any[]) {
    send({
        type: 'log',
        level: 'warning',
        message: message.join(' ')
    })
}

export function info(...message: any[]) {
    send({
        type: 'log',
        level: 'info',
        message: message.join(' ')
    })
}

export function debug(...message: any[]) {
    send({
        type: 'log',
        level: 'debug',
        message: message.join(' ')
    })
}