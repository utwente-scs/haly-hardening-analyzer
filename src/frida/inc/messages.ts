export type Message = {
    type: string; // Message type
    function: string; // Hooked function or syscall
    context: 'java' | 'objc' | 'native'; // Whether the hooked function is Java, Objective-C or native
    args: any[]; // Arguments passed to the function or syscall
    confident: boolean; // Whether the detector is confident (unlikely false positive) in the result

    // Will be added by log() if not set
    // Can be assumed to be set once message is sent to python
    backtrace?: any[]; // Backtrace
    detector?: string; // Detector that sent the message

    [key: string]: any; // Other fields are defined below per message type
};

// Hooked function executed
export type FunctionMessage = Message & {
    type: 'function';
}

// android.os.Build.{field} property compared
export type BuildMessage = Message & {
    type: 'build';
    field: string;
}

// File accessed
export type FileMessage = Message & {
    type: 'file';
    file: string;
};

// App accessed
export type AppMessage = Message & {
    type: 'app';
    app: string;
};

// Syscall executed using svc instruction
export type SvcMessage = Message & {
    type: 'svc';
    svc_id: number;
    svc_syscall: string;
};