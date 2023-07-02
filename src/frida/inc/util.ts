/**
 * Create a NativeFunction that calls a syscall
 * @param name syscall name
 * @param returnValue return value type
 * @param args argument types
 * @returns NativeFunction or null if syscall doesn't exist
 */
export function syscall(name: string, returnValue: NativeFunctionReturnType, args: NativeFunctionArgumentType[]): NativeFunction<any, any> | null {
    let addr = Module.findExportByName(null, name);
    if (addr === null) return null;
    return new NativeFunction(addr, returnValue, args);
}

/**
 * Read a file from the filesystem
 * @param path path to the file
 * @returns file contents or null if file doesn't exist
 */
export function readFile(path: string): string {
    let open = syscall('open', 'int', ['pointer', 'int']);
    let read = syscall('read', 'int', ['int', 'pointer', 'int']);
    let close = syscall('close', 'int', ['int']);

    let fd = open(Memory.allocUtf8String(path), 0);
    if (fd === -1) return null;

    let content = '';
    let buf = Memory.alloc(4096);
    while (true) {
        let readBytes = read(fd, buf, 4096);
        if (readBytes === -1) return null;
        if (readBytes === 0) break;
        content += buf.readUtf8String(readBytes);
    }
    
    close(fd);

    return content;
}

/**
 * Write content to a file in the filesystem
 * @param path file to write to 
 * @param content content to write
 * @returns true if successful, false otherwise
 */
export function writeFile(path: string, content: string) {
    try {
        // @ts-ignore
        let file = new File(path, 'w');
        // @ts-ignore
        file.write(content);
        // @ts-ignore
        file.flush();
        // @ts-ignore
        file.close();
        return true;
    } catch (e) {
        return false;
    }
}

/**
 * Add functions to the rpc.exports object
 * @param exports functions to add
 */
export function addRpcExports(exports: object) {
    Object.assign(rpc.exports, exports);
}