#include <jni.h>
#include <string>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <android/log.h>
#include <sys/ptrace.h>
#include <dirent.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

extern "C" JNIEXPORT jstring JNICALL
Java_com_wilco375_fyp_1app_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject thiz) {
    char* retval = (char*) calloc(1, 4096);

    // Ignore return value since ptrace is not supported on all devices
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    strcat(retval, "\nPtrace: OK");

    // SU binary check using SVC syscall
    char suPath[16] = "/system/bin/su\0";
    int fp;
    // 56 = openat syscall, so openat(-1, "/system/bin/su", O_RDONLY)
    asm volatile("mov x8, %1\n"
                 "mov x0, %2\n"
                 "mov x1, %3\n"
                 "mov x2, %4\n"
                 "svc #0\n"
                 "mov %0, x0\n"
            : "=r"(fp)
            : "r"(56), "r"(-1), "r"(&suPath), "r"(0)
            : "x8", "x0", "x1", "x2");
    if (fp >= 0) {
        strcat(retval, "\nsu binary SVC: NOT OK");
        close(fp);
    } else {
        strcat(retval, "\nsu binary SVC: OK");
    }

    // Loop over files in /proc/self/fd and execute readlink on them
    // to get the path of the file they point to.
    DIR* dir = opendir("/proc/self/fd");
    if (dir == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, "from-C", "opendir: %s", strerror(errno));
    } else {
        struct dirent* entry;
        char path[PATH_MAX];
        char target[PATH_MAX];
        bool fridaFound = false;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type != DT_LNK) {
                continue;
            }

            snprintf(path, sizeof(path), "/proc/self/fd/%s", entry->d_name);

            ssize_t len = readlink(path, target, sizeof(target) - 1);
            if (len == -1) {
                __android_log_print(ANDROID_LOG_ERROR, "from-C", "readlink: %s", strerror(errno));
            } else {
                target[len] = '\0';

                // Check if 'frida' in path
                if (strstr(target, "frida") != NULL) {
                    fridaFound = true;
                    break;
                }
            }
        }

        if (fridaFound) {
            strcat(retval, "\nFrida: NOT OK");
        } else {
            strcat(retval, "\nFrida: OK");
        }

        closedir(dir);
    }


    // Check if port 27042 is open on localhost
    int sockfd;
    struct sockaddr_in server_addr;
    int port = 27042;

    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) >= 0) {
        // Set up server address structure
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        // Connect to the server
        if (connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) == 0) {
            strcat(retval, "\nPort 27042: NOT OK");
            close(sockfd);
        } else {
            strcat(retval, "\nPort 27042: OK");
        }
    } else {
        __android_log_print(ANDROID_LOG_ERROR, "from-C", "socket: %s", strerror(errno));
    }

    return (*env).NewStringUTF(retval);
}
