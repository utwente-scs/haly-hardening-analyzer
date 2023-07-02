import { AppsHooks } from "../hooks/apps";
import { FilePattern, FileHooks } from "../hooks/file";
import { readFile } from "../inc/util";
import { logFunction, warn } from "../inc/log";
import { addPostHook, PostCallbackData } from "../hooks/native";
import { addOpenPortHook } from "../hooks/socket";

let fileHooks = FileHooks.getInstance();
let appsHooks = AppsHooks.getInstance();

// Hide blacklisted files
fileHooks.accessFileHook(FilePattern.from(global.context.root.files.blacklist), true);
fileHooks.accessFileHook(FilePattern.from(global.context.root.files.log));

// Modify /proc/mounts and /proc/<pid>/mounts files
fileHooks.replaceFileHook('/proc/', 'mounts', getModifiedProcMounts);

fileHooks.roPermissionsFileHook(FilePattern.from(global.context.root.files.ro));

fixRootFlags();

// Add port hook for ssh ports
addOpenPortHook(22);
addOpenPortHook(2222);

appsHooks.blacklistAppsHook(global.context.root.apps.blacklist);

global.context.root.syscalls.forEach(syscall => {
    addPostHook(syscall, [], data => {
        logFunction(data);

        // We do not need to patch the return value here since the jailbreak 
        // we are using does not change the allowed syscalls
    })   
})

function fixRootFlags() {
    let rootFlagsHandler = (data: PostCallbackData) => {
        if (data.args[0].isNull()) return;

        logFunction(data, false);
        
        let mntonnamePtr = ptr(data.args[0]).add(0x58);
        if(mntonnamePtr.readCString() != "/" ){
            return null;
        }

        // Assume that '/' is always first in the array and it'd the only fs that differs when jailbroken
        let flagsPtr = ptr(data.args[0]).add(0x40);

        // MNT_RDONLY | MNT_ROOTFS | MNT_DOVOLFS | MNT_JOURNALED | MNT_MULTILABEL | MNT_NOSUID | MNT_SNAPSHOT
        flagsPtr.writeU32(0x4480C009);
    }

    addPostHook('getfsstat', ['ptr', 'int', 'int'], rootFlagsHandler)
    addPostHook('getmntinfo', ['ptr', 'int'], rootFlagsHandler)
}

/**
 * Get a modified /proc/mounts file that doesn't contain blacklisted mount points
 */
function getModifiedProcMounts(filename): string | null {
    let procMounts = readFile(filename);
    if (procMounts == null) {
        warn("Failed to read " + filename);
        return null;
    }

    // Get magisk mount point (e.g. /dev/lVGHs/.magisk/block/system_root => /dev/lVGHs) and add to blacklist
    let blacklist = global.context.root.mounts.blacklist;
    let magiskMount = procMounts
        .split('\n')
        .find(line => line.includes('/.magisk/'));
    if (magiskMount) {
        magiskMount = magiskMount.split('/.magisk/')[0];
        let magiskMountPath = magiskMount.split(' ');
        blacklist.push(magiskMountPath[magiskMountPath.length - 1]);
    }

    let modifiedProcMounts = '';
    for (let line of procMounts.split('\n')) {
        if (blacklist.some(word => line.includes(word))) continue;
        modifiedProcMounts += line + '\n';
    }

    return modifiedProcMounts;
}