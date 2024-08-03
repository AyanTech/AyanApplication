#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <jni.h>

// Function declarations
int is_frida_process_running();
int is_frida_library_loaded();
int is_device_rooted();
int check_additional_root_indicators();

// Function to check for Frida-related processes
int is_frida_process_running() {
    const char *frida_processes[] = {"frida-server", "gadget", "frida-helper", NULL};
    DIR *dir = opendir("/proc");
    if (!dir) return 0;

    struct dirent *entry;
    char path[256];
    char cmdline[256];
    int fd;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            snprintf(path, sizeof(path), "/proc/%s/cmdline", entry->d_name);
            fd = open(path, O_RDONLY);
            if (fd > 0) {
                if (read(fd, cmdline, sizeof(cmdline)) > 0) {
                    for (int i = 0; frida_processes[i] != NULL; i++) {
                        if (strstr(cmdline, frida_processes[i]) != NULL) {
                            close(fd);
                            closedir(dir);
                            return 1; // Frida process detected
                        }
                    }
                }
                close(fd);
            }
        }
    }
    closedir(dir);
    return 0; // No Frida processes detected
}

// Function to check for Frida-related libraries
int is_frida_library_loaded() {
    const char *frida_libraries[] = {"libfrida-gadget.so", "libfrida-agent.so", NULL};
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return 0;

    char line[256];
    while (fgets(line, sizeof(line), maps)) {
        for (int i = 0; frida_libraries[i] != NULL; i++) {
            if (strstr(line, frida_libraries[i]) != NULL) {
                fclose(maps);
                return 1; // Frida library detected
            }
        }
    }
    fclose(maps);
    return 0; // No Frida libraries detected
}

// Function to check if the device is rooted
int is_device_rooted() {
    const char *su_paths[] = {"/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/sd/xbin/su",
                              "/system/bin/.ext/su", "/system/usr/we-need-root/su", "/system/app/Superuser.apk",
                              "/system/app/SuperSU.apk", "/system/xbin/daemonsu", NULL};
    struct stat st;

    for (int i = 0; su_paths[i] != NULL; i++) {
        if (stat(su_paths[i], &st) == 0) {
            return 1; // Rooted
        }
    }
    return 0; // Not rooted
}

// Function to check for other common indicators of root access
int check_additional_root_indicators() {
    const char *root_indicators[] = {"/system/xbin/su", "/system/bin/su", "/system/app/Superuser.apk",
                                     "/system/app/SuperSU.apk", "/system/bin/.ext", "/system/usr/we-need-root",
                                     "/system/xbin/busybox", "/system/xbin/daemonsu", "/system/etc/init.d",
                                     "/sbin/su", NULL};
    struct stat st;

    for (int i = 0; root_indicators[i] != NULL; i++) {
        if (stat(root_indicators[i], &st) == 0) {
            return 1; // Root indicator found
        }
    }
    return 0; // No root indicators found
}

// Main detection function
int is_frida_or_root_detected() {
    if (is_frida_process_running() || is_frida_library_loaded() || is_device_rooted() || check_additional_root_indicators()) {
        return 1; // Frida or root detected
    }
    return 0; // Frida and root not detected
}

// JNI function to expose detection to Java/Kotlin
JNIEXPORT jint
Java_ir_ayantech_ghabzino_helper_AnalyticsHelper_isFridaOrRootDetected(JNIEnv *env, jobject instance) {
    return is_frida_or_root_detected();
}
