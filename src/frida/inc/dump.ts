import { debug, warn } from "./log";
import { addRpcExports } from './util';

/* 
This file is a modified version of frida-ios-dump by AloneMonkey:
https://github.com/AloneMonkey/frida-ios-dump/blob/master/dump.js
Changes:
- Decrypt module in memory and send to python with Frida message instead of writing to file and copying with SCP
- Remove unused code
- Replace console.log with debug/warn function
- Add error handling to library loading
*/

Module.ensureInitialized('Foundation');

var O_RDONLY = 0;

var SEEK_SET = 0;
var SEEK_END = 2;

function allocStr(str) {
    return Memory.allocUtf8String(str);
}

function getU32(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    //@ts-ignore
    return Memory.readU32(addr);
}

function putU64(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    //@ts-ignore
    return Memory.writeU64(addr, n);
}

function malloc(size) {
    return Memory.alloc(size);
}

function getExportFunction(type, name, ret, args) {
    var nptr;
    nptr = Module.findExportByName(null, name);
    if (nptr === null) {
        warn("cannot find " + name);
        return null;
    } else {
        if (type === "f") {
            var funclet = new NativeFunction(nptr, ret, args);
            if (typeof funclet === "undefined") {
                warn("parse error " + name);
                return null;
            }
            return funclet;
        } else if (type === "d") {
            //@ts-ignore
            var datalet = Memory.readPointer(nptr);
            if (typeof datalet === "undefined") {
                warn("parse error " + name);
                return null;
            }
            return datalet;
        }
    }
}

var wrapper_open = getExportFunction("f", "open", "int", ["pointer", "int", "int"]);
var read = getExportFunction("f", "read", "int", ["int", "pointer", "int"]);
var lseek = getExportFunction("f", "lseek", "int64", ["int", "int64", "int"]);
var close = getExportFunction("f", "close", "int", ["int"]);
var dlopen = getExportFunction("f", "dlopen", "pointer", ["pointer", "int"]);

function open(pathname, flags, mode) {
    if (typeof pathname == "string") {
        pathname = allocStr(pathname);
    }
    return wrapper_open(pathname, flags, mode);
}

var modules = null;
function getAllAppModules() {
    modules = new Array();
    var tmpmods = Process.enumerateModules();
    for (var i = 0; i < tmpmods.length; i++) {
        if (tmpmods[i].path.indexOf(".app") != -1) {
            modules.push(tmpmods[i]);
        }
    }
    return modules;
}

var FAT_MAGIC = 0xcafebabe;
var FAT_CIGAM = 0xbebafeca;
var MH_MAGIC = 0xfeedface;
var MH_CIGAM = 0xcefaedfe;
var MH_MAGIC_64 = 0xfeedfacf;
var MH_CIGAM_64 = 0xcffaedfe;
var LC_ENCRYPTION_INFO = 0x21;
var LC_ENCRYPTION_INFO_64 = 0x2C;

function pad(str, n) {
    return Array(n - str.length + 1).join("0") + str;
}

function swap32(value) {
    value = pad(value.toString(16), 8)
    var result = "";
    for (var i = 0; i < value.length; i = i + 2) {
        result += value.charAt(value.length - i - 2);
        result += value.charAt(value.length - i - 1);
    }
    return parseInt(result, 16)
}

function dumpModule(name) {
    if (modules == null) {
        modules = getAllAppModules();
    }

    var targetmod = null;
    for (var i = 0; i < modules.length; i++) {
        if (modules[i].path.indexOf(name) != -1) {
            targetmod = modules[i];
            break;
        }
    }
    if (targetmod == null) {
        warn("Cannot find module");
        return;
    }
    var modbase = targetmod.base;
    var modpath = targetmod.path;

    var foldmodule = open(modpath, O_RDONLY, 0);

    if (foldmodule == -1) {
        warn("Cannot open file" + foldmodule);
        return;
    }

    var size_of_mach_header = 0;
    var magic = getU32(modbase);
    var cur_cpu_type = getU32(modbase.add(4));
    var cur_cpu_subtype = getU32(modbase.add(8));
    if (magic == MH_MAGIC || magic == MH_CIGAM) {
        size_of_mach_header = 28;
    } else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        size_of_mach_header = 32;
    }

    var BUFSIZE = 4096;
    var buffer = malloc(BUFSIZE);

    read(foldmodule, buffer, BUFSIZE);

    var fileoffset = 0;
    var filesize = 0;
    var fmodule_offset = 0;
    magic = getU32(buffer);
    if (magic == FAT_CIGAM || magic == FAT_MAGIC) {
        var off = 4;
        var archs = swap32(getU32(buffer.add(off)));
        for (var i = 0; i < archs; i++) {
            var cputype = swap32(getU32(buffer.add(off + 4)));
            var cpusubtype = swap32(getU32(buffer.add(off + 8)));
            if (cur_cpu_type == cputype && cur_cpu_subtype == cpusubtype) {
                fileoffset = swap32(getU32(buffer.add(off + 12)));
                filesize = swap32(getU32(buffer.add(off + 16)));
                break;
            }
            off += 20;
        }

        var fmodule = malloc(filesize);

        if (fileoffset == 0 || filesize == 0)
            return;

        lseek(foldmodule, fileoffset, SEEK_SET);
        //@ts-ignore
        for (var i = 0; i < parseInt(filesize / BUFSIZE); i++) {
            read(foldmodule, buffer, BUFSIZE);
            Memory.copy(fmodule.add(fmodule_offset), buffer, BUFSIZE);
            fmodule_offset += BUFSIZE;
        }
        if (filesize % BUFSIZE) {
            read(foldmodule, buffer, filesize % BUFSIZE);
            Memory.copy(fmodule.add(fmodule_offset), buffer, filesize % BUFSIZE);
            fmodule_offset += filesize % BUFSIZE;
        }
    } else {
        filesize = parseInt(lseek(foldmodule, 0, SEEK_END));
        var fmodule = malloc(filesize);

        var readLen = 0;
        lseek(foldmodule, 0, SEEK_SET);
        while (readLen = read(foldmodule, buffer, BUFSIZE)) {
            Memory.copy(fmodule.add(fmodule_offset), buffer, readLen);
            fmodule_offset += readLen;
        }
    }

    var ncmds = getU32(modbase.add(16));
    var off = size_of_mach_header;
    var offset_cryptid = -1;
    var crypt_off = 0;
    var crypt_size = 0;
    for (var i = 0; i < ncmds; i++) {
        var cmd = getU32(modbase.add(off));
        var cmdsize = getU32(modbase.add(off + 4));
        if (cmd == LC_ENCRYPTION_INFO || cmd == LC_ENCRYPTION_INFO_64) {
            offset_cryptid = off + 16;
            crypt_off = getU32(modbase.add(off + 8));
            crypt_size = getU32(modbase.add(off + 12));
        }
        off += cmdsize;
    }

    if (offset_cryptid != -1) {
        var tpbuf = malloc(8);
        putU64(tpbuf, 0);
        fmodule_offset = offset_cryptid;
        Memory.copy(fmodule.add(fmodule_offset), tpbuf, 4);
        fmodule_offset = crypt_off;
        Memory.copy(fmodule.add(fmodule_offset), modbase.add(crypt_off), crypt_size);
    }

    close(foldmodule);

    // Send max 64 MiB at a time
    let maxSize = 0x4000000;
    for (let offset = 0; offset < filesize; offset += maxSize) {
        let readLength = Math.min(maxSize, filesize - offset);
        send({ type: 'dump', complete: false, module: targetmod.name, path: modpath, offset }, fmodule.add(offset).readByteArray(readLength));
    }
}

function loadAllDynamicLibrary(app_path) {
    var defaultManager = ObjC.classes.NSFileManager.defaultManager();
    var errorPtr = Memory.alloc(Process.pointerSize);
    //@ts-ignore
    Memory.writePointer(errorPtr, NULL);
    var filenames = defaultManager.contentsOfDirectoryAtPath_error_(app_path, errorPtr);
    for (var i = 0, l = filenames.count(); i < l; i++) {
        var file_name = filenames.objectAtIndex_(i);
        var file_path = app_path.stringByAppendingPathComponent_(file_name);
        if (file_name.hasSuffix_(".framework")) {
            var bundle = ObjC.classes.NSBundle.bundleWithPath_(file_path);
            if (bundle.isLoaded()) {
                debug(file_name + " has been loaded. ");
            } else {
                if (bundle.load()) {
                    debug("Load " + file_name + " success. ");
                } else {
                    warn("Load " + file_name + " failed. ");
                }
            }
        } else if (file_name.hasSuffix_(".bundle") ||
            file_name.hasSuffix_(".momd") ||
            file_name.hasSuffix_(".strings") ||
            file_name.hasSuffix_(".appex") ||
            file_name.hasSuffix_(".app") ||
            file_name.hasSuffix_(".lproj") ||
            file_name.hasSuffix_(".storyboardc")) {
            continue;
        } else {
            var isDirPtr = Memory.alloc(Process.pointerSize);
            //@ts-ignore
            Memory.writePointer(isDirPtr, NULL);
            defaultManager.fileExistsAtPath_isDirectory_(file_path, isDirPtr);
            //@ts-ignore
            if (Memory.readPointer(isDirPtr) == 1) {
                loadAllDynamicLibrary(file_path);
            } else {
                if (file_name.hasSuffix_(".dylib")) {
                    var is_loaded = 0;
                    for (var j = 0; j < modules.length; j++) {
                        if (modules[j].path.indexOf(file_name) != -1) {
                            is_loaded = 1;
                            debug(file_name + " has been dlopen.");
                            break;
                        }
                    }

                    if (!is_loaded) {
                        // Added error handling via try catch to prevent program from crashing
                        // when a library cannot be loaded.
                        const file_path_ptr = allocStr(file_path.UTF8String());
                        try {
                            if (dlopen(file_path_ptr, 9)) {
                                debug("dlopen " + file_name + " success. ");
                            } else {
                                warn("dlopen " + file_name + " failed. ");
                            }
                        } catch (e) {
                            warn("dlopen " + file_name + " failed: " + e.message);
                        }
                    }
                }
            }
        }
    }
}

function dumpModules() {
    modules = getAllAppModules();
    var app_path = ObjC.classes.NSBundle.mainBundle().bundlePath();
    loadAllDynamicLibrary(app_path);
    // start dump
    modules = getAllAppModules();
    for (var i = 0; i < modules.length; i++) {
        dumpModule(modules[i].path);
    }
    send({ type: 'dump', complete: true });
}

addRpcExports({
    dumpModules: dumpModules
});