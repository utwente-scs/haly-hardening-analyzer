import { addPostHook, addPreHook, CallbackData, PostCallbackData } from "./native";
import { log, getDetector, error } from "../inc/log";
import { syscall, writeFile } from "../inc/util"
import { read } from "fs";

/**
 * Class used to match file paths against a blacklist
 * Matching can be performed by filename or substring
 */
export class FilePattern {
    private path: string;
    private matching: 'contains' | 'filename' | 'startsWith' | 'endsWith';

    /**
     * Construct a file pattern that can be used for blacklisting files
     * @param path path to match
     * @param matching matching method
     */
    constructor(path: string, matching: 'contains' | 'filename' | 'startsWith' | 'endsWith') {
        this.path = path.toLowerCase();
        this.matching = matching;
    }
    
    /**
     * Check if an absolute path matches this pattern
     * @param path absolute path to check
     * @returns true if path matches this pattern, false otherwise
     */
    public matches(path: string | null): boolean {
        if (path === null || path === undefined) return false;
        path = path.toLowerCase();

        // Ignore files of the current application
        if (path.includes(global.context.info.package)) return false;
        if (global.context.info.executable && path.includes(global.context.info.executable + '.app')) return false;

        // Ignore frida internal files that are accessed during normal operation
        // TODO: See if there is a way to still detect when these files are accessed by 
        // the app instead of frida itself
        if (path.startsWith('/data/local/tmp/re.frida.server/linjector-') || 
                path.startsWith('/data/local/tmp/re.frida.server/frida-')) 
            return false;

        switch (this.matching) {
            case 'contains':
                return path.includes(this.path);
            case 'filename':
                if (this.path.includes('/')) {
                    return path == this.path;
                } else {
                    return path.split('/').pop() == this.path;
                }
            case 'startsWith':
                return path.startsWith(this.path);
            case 'endsWith':
                return path.endsWith(this.path);
        }
    }

    /**
     * Construct a list of file patterns from a list of strings
     * A * at the start or end of a string is considered a wildcard
     * @param list list of strings
     * @returns list of file patterns
     */
    public static from(list: string[]): FilePattern[] {
        return list.map(path => {
            let startsWithWildcard = path.startsWith('*');
            let endsWithWildcard = path.endsWith('*');
            let matching;
            if (startsWithWildcard && endsWithWildcard) {
                matching = 'contains';
                path = path.substring(1, path.length - 1);
            } else if (startsWithWildcard) {
                matching = 'endsWith';
                path = path.substring(1);
            } else if (endsWithWildcard) {
                matching = 'startsWith';
                path = path.substring(0, path.length - 1);
            } else {
                matching = 'filename';
            }
            return new FilePattern(path, matching)
        });
    }
}

/**
 * Singleton class wrapper used to easily add hooks to file operations
 */
export class FileHooks {
    private static instance: FileHooks;
    
    private fileDescriptors: {[key: number]: string} = {};

    private constructor() {
        // Add hooks so we can associate file descriptors with file paths
        addPostHook(['open', 'open_dprotected_np', 'open_extended', 'open_nocancel', 'guarded_open_np', 'guarded_open_dprotected_np', 'creat'], ['str'], (data: PostCallbackData) => {
            if (data.retval.toInt32() < 0) return;
            this.fileDescriptors[data.retval.toInt32()] = data.args[0];
        });

        addPostHook(['close', 'android_fdsan_close_with_tag', 'sys_close', 'sys_close_nocancel', 'guarded_close_np'], ['int'], (data: PostCallbackData) => {
            if (data.retval.toInt32() != 0) return;
            delete this.fileDescriptors[data.args[0]];
        });

        addPostHook(['openat', 'openat_nocancel'], ['int', 'str'], (data: PostCallbackData) => {
            if (data.retval.toInt32() < 0) return;
            this.fileDescriptors[data.retval.toInt32()] = this.fileDescriptors[data.args[0]] + '/' + data.args[1];
        });
    }

    public static getInstance(): FileHooks {
        if (!FileHooks.instance) {
            FileHooks.instance = new FileHooks();
        }
        return FileHooks.instance;
    }

    private fileHandler = (list: FilePattern[], callback: (data: CallbackData) => void) => {
        return (data: CallbackData) => {
            if (data.args.length < 1) return;
            let path;
            if (typeof data.args[0] == 'string') {
                // Args: path
                path = data.args[0];
            } else if (data.args.length >= 2 && typeof data.args[0] == 'number' && typeof data.args[1] == 'string') {
                // Args: fd, path
                path = data.args[1];
                if (data.args[0] && this.fileDescriptors[data.args[0]])
                    path = this.fileDescriptors[data.args[0]] + '/' + path;
            } else if (typeof data.args[0] == 'number') {
                // Args: fd
                path = this.fileDescriptors[data.args[0]]
            } else {
                return;
            }

            if (list.some(item => item.matches(path))) {
                logFile(data, path);

                callback(data);
            }
        }
    }

    /**
     * Adds hooks to file operations related to the listed files. Can also blacklist files so they are not visible to the app
     * @param list list of file paths
     * @param blacklist if true, the list is treated as a blacklist, otherwise the function will only log access to matching files
     */
    public accessFileHook(list: FilePattern[], blacklist=false) {
        // Args: path
        let fileHook = this.fileHandler(list, (data: CallbackData) => {
            if (blacklist) {
                data.args[0] = "/doesnotexist";
            }
        });

        // Args: fd, path
        let fileatHook = this.fileHandler(list, (data: CallbackData) => {
            if (blacklist) {
                data.args[1] = "/doesnotexist";
            }
        });

        // Args: fd
        let ffileHook = this.fileHandler(list, (data: CallbackData) => {
            // No need to check for blacklist, since the app would be unable to construct a file descriptor 
            // to these files since we hook open and openat
        });

        let openSyscalls = ['open', 'open_dprotected_np', 'open_extended', 'open_nocancel', 'guarded_open_np', 'guarded_open_dprotected_np', 'creat', 'access', 'access_extended'];
        addPreHook(openSyscalls, ['str'], fileHook);

        let openatSyscalls = ['openat', 'openat_nocancel', 'faccessat'];
        addPreHook(openatSyscalls, ['int', 'str'], fileatHook);

        let statSyscalls = ['lstat', 'stat', 'statfs', 'statvfs'];
        addPreHook(statSyscalls, ['str', 'ptr'], fileHook);

        let fstatSyscalls = ['fstat', 'sys_fstat', 'fstatfs', 'fstatvfs'];
        addPreHook(fstatSyscalls, ['int', 'ptr'], ffileHook);

        addPreHook('fstatat', ['int', 'str', 'ptr', 'int'], fileatHook);

        addPreHook('pathconf', ['str', 'int'], fileHook);

        addPreHook(['fpathconf', 'sys_fpathconf'], ['int', 'int'], ffileHook);

        addPreHook('getattrlist', ['str', 'ptr', 'ptr', 'int'], fileHook);

        addPreHook('fgetattrlist', ['int', 'ptr', 'ptr', 'int'], ffileHook);

        addPreHook('getattrlistat', ['int', 'str', 'ptr', 'ptr', 'int'], fileatHook);

        addPreHook('readlink', ['str'], fileHook);

        addPreHook('readlinkat', ['int', 'str'], fileatHook);

        let readlinkHook = (data: PostCallbackData) => {
            let linkPathIndex = 1;
            if (typeof data.args[0] != 'string') {
                linkPathIndex = 2;
            }

            if (list.some(item => item.matches(data.args[linkPathIndex]))) {
                logFile(data, data.args[linkPathIndex]);

                if (blacklist) {
                    data.args[linkPathIndex] = '/dev/null';
                }
            }
        }

        addPostHook('readlink', ['str', 'str'], readlinkHook)

        addPreHook('readlinkat', ['int', 'str', 'str'], readlinkHook);

        // TODO: Blacklist individual directory entries
        addPreHook('getattrlistbulk', ['int', 'ptr', 'ptr', 'int', 'int'], ffileHook);
        addPreHook('getdirentriesattr', ['int', 'ptr', 'ptr', 'int', 'long', 'long', 'long', 'int'], ffileHook);
        addPreHook('getdirentries', ['int', 'ptr', 'int', 'ptr'], ffileHook);

        // Hook executing files
        let exec = ['execve', 'execv', 'execvp', 'execvpe'];
        addPreHook(exec, ['str', 'ptr'], fileHook);
        addPreHook('system', ['str'], fileHook);
    }

    /**
     * Virtually change permissions of files matching the list to read-only
     * @param list list of file paths
     */
    public roPermissionsFileHook(list: FilePattern[]) {
        let stat = syscall('stat', 'int', ['pointer', 'pointer']);

        function setPermissions(statStruct: NativePointer) {
            // Set file permissions to read-only in st_mode
            // unsigned long+unsigned long = 8+8 = 16
            let permissions = statStruct.add(16).readU32();

            // Clear write permissions
            permissions = (permissions & ~0o222) >>> 0;

            statStruct.add(16).writeU32(permissions);
        }

        let setPermissionsHook = this.fileHandler(list, (data: PostCallbackData) => {
            let statStruct;
            if (typeof data.args[1] == 'number') {
                // Args: fd, stat
                statStruct = data.args[1];
            } else if (typeof data.args[2] == 'number') {
                // Args: fd, path, stat
                statStruct = data.args[2];
            } else {
                return;
            }
            
            setPermissions(statStruct);
        });

        addPostHook(['stat', 'stat_extended'], ['str', 'ptr'], setPermissionsHook);

        addPostHook(['lstat', 'lstat_extended'], ['str', 'ptr'], this.fileHandler(list, (data: PostCallbackData) => {
            // Use stat so we don't return a symlink
            stat(Memory.allocUtf8String(data.args[0]), data.args[1]);

            setPermissions(data.args[1]);
        }));

        addPostHook(['fstat', 'sys_fstat_extended', 'sys_fstat'], ['int', 'ptr'], setPermissionsHook);

        addPreHook(['fstatat'], ['int', 'str', 'ptr', 'int'], this.fileHandler(list, (data: CallbackData) => {
            // Unset AT_SYMLINK_NOFOLLOW
            data.args[3] &= ~0x100;
        }));

        addPostHook(['fstatat'], ['int', 'str', 'ptr', 'int'], setPermissionsHook);

        let setAccessibleHook = this.fileHandler(list, (data: PostCallbackData) => {
            let mode;
            if (typeof data.args[1] == 'number') {
                // Args: fd, mode
                mode = data.args[1];
            } else if (typeof data.args[2] == 'number') {
                // Args: fd, path, mode
                mode = data.args[2];
            }

            if (mode & 0o222) {
                data.retval.replace(-1);
                data.context.errno = 13; // EACCES
            }
        });

        addPostHook(['access', 'access_extended'], ['str', 'int'], setAccessibleHook);
        addPostHook('faccessat', ['int', 'str', 'int', 'int'], setAccessibleHook);

        addPreHook('readlink', ['str'], this.fileHandler(list, (data: CallbackData) => {
            data.args[0] = "/"; // Make sure EINVAL is returned (not a symlink)
        }));

        addPreHook('readlinkat', ['int', 'str'], this.fileHandler(list, (data: CallbackData) => {
            data.args[1] = "/"; // Make sure EINVAL is returned (not a symlink)
        }));

        let epermHook = this.fileHandler(list, (data: PostCallbackData) => {
            data.retval.replace(-1);
            data.context.errno = 1; // EPERM
        });

        let writeSyscalls = ['write', 'write_nocancel', 'writev', 'writev_nocancel', 'pwrite', 'pwrite_nocancel', 'pwritev', 'pwritev2', 'sys_pwritev', 'sys_pwritev_nocancel'];
        addPreHook(writeSyscalls, ['int', 'ptr', 'uint'], this.fileHandler(list, (data: PostCallbackData) => {
            data.args[2] = 0;
        }));
        addPostHook(writeSyscalls, ['int', 'ptr', 'uint'], epermHook);

        let guardedWriteSyscalls = ['guarded_write_np', 'guarded_pwrite_np', 'guarded_writev_np'];
        addPreHook(guardedWriteSyscalls, ['int', 'ptr', 'ptr', 'uint'], this.fileHandler(list, (data: PostCallbackData) => {
            data.args[3] = 0;
        }));
        addPostHook(guardedWriteSyscalls, ['int', 'ptr', 'ptr', 'uint'], epermHook);
    }

    /**
     * Virtually replace a (readonly) file with new context by hooking all file operations
     * @param path some parent directory of file to replace
     * @param filename name of file to replace
     * @param callback callback to generate new file contents
     */
    public replaceFileHook(path: string, filename: string, callback: (path: string) => string | null, confident: boolean = true) {
        // Create a temporary file to replace a file
        let tmpDir = null;
        if (Process.platform == 'darwin') {
            if (ObjC.available) {
                // NSTemporaryDirectory()
                let NSTemporaryDirectory = new NativeFunction(Module.findExportByName(null, 'NSTemporaryDirectory'), 'pointer', []);
                tmpDir = (new ObjC.Object(NSTemporaryDirectory())).toString();
            } else {
                error("Cannot replace file on iOS without Objective-C runtime");
                return;
            }
        } else {
            // Android
            let packageId = global.context.info.package;
            tmpDir = "/data/data/" + packageId;
        }

        let open = syscall('open', 'int', ['pointer', 'int']);
        let close = syscall('close', 'int', ['int']);

        let replaceFileHandler = (openPath: string, flags: number, data: PostCallbackData) => {
            if (openPath != null && openPath.startsWith(path) && openPath.endsWith(filename)) {
                let newFile = callback(openPath);
                if (newFile != null) {
                    logFile(data, openPath, confident);

                    // Write newFile to temporary file
                    let tmpFile = tmpDir + '/' + openPath.replace(/\//g, '_') + '_' + (new Date()).getTime() + '.tmp';
                    let success = writeFile(tmpFile, newFile);
                    if (!success) {
                        error("Failed to write temporary file " + tmpFile + " for " + openPath + " replacement");
                        return;
                    }

                    // Replace file descriptor
                    let tmpFilePath = Memory.allocUtf8String(tmpFile);
                    let fd = open(tmpFilePath, flags);
                    if (fd == -1) {
                        error("Failed to open temporary file for " + openPath + " replacement");
                        return;
                    }

                    this.fileDescriptors[fd] = openPath;

                    close(data.retval.toInt32());
                    data.retval.replace(fd);
                }
            }
        }

        addPostHook(['open', 'open_dprotected_np', 'open_extended', 'open_nocancel', 'guarded_open_np', 'guarded_open_dprotected_np', 'creat'], ['str', 'int'], (data: PostCallbackData) => {
            let openPath = data.args[0];
            replaceFileHandler(openPath, data.args[1], data);
        });

        addPostHook(['openat', 'openat_nocancel'], ['int', 'str', 'int'], (data: PostCallbackData) => {
            let openPath = data.args[1];
            if (data.args[0] && this.fileDescriptors[data.args[0]])
            openPath = this.fileDescriptors[data.args[0]] + '/' + openPath;
            replaceFileHandler(openPath, data.args[2], data);
        });
    }
}

function logFile(data: CallbackData, path: string, confident: boolean = true) {
    log({
        type: 'file',
        context: 'native',
        function: data.syscall,
        args: data.args,
        confident: confident,
        file: path
    }, data.context.context, data.detector)
}