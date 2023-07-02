import requests
import json
from os.path import join, dirname
import re

# Get Android arm syscalls
android_url = 'https://raw.githubusercontent.com/aosp-mirror/platform_bionic/master/libc/kernel/uapi/asm-generic/unistd.h'
response = requests.get(android_url).text
syscalls = {}
for line in response.split('\n'):
    # Lines have format "#define __NR_io_setup 0" or "#define __NR3264_fcntl 25"
    syscall = re.search(r'__NR(?:3264)?_([a-zA-Z0-9_]+) ([0-9]+)', line)
    if syscall is None:
        continue
    syscall = syscall.groups()
    syscalls[int(syscall[1])] = syscall[0]

with open(join(dirname(__file__), 'syscalls-android.json'), 'w') as f:
    json.dump(syscalls, f, separators=(',', ':'))

# Get iOS syscalls
ios_url = 'https://raw.githubusercontent.com/apple/darwin-xnu/main/bsd/kern/syscalls.master'
response = requests.get(ios_url).text
syscalls = {}
for line in response.split('\n'):
    # Lines have format "1	AUE_EXIT	ALL	{ void exit(int rval) NO_SYSCALL_STUB; }"
    syscall = re.search(r'([0-9]+)[^{]+{ [^ ]+ ([a-zA-Z0-9_]+)\(', line)
    if syscall is None:
        continue
    syscall = syscall.groups()
    if 'nosys' in syscall[1].lower():
        continue
    syscalls[int(syscall[0])] = syscall[1]
    
with open(join(dirname(__file__), 'syscalls-ios.json'), 'w') as f:
    json.dump(syscalls, f, separators=(',', ':'))
