#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <sys/mount.h>
#include <stdlib.h>
#include <sys/stat.h>
#ifdef __linux__
#include <sys/sysmacros.h>
#endif
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

pid_t child_proc = -1;

static void intHan(int signum) {
    if (child_proc != -1) {
        kill(child_proc, SIGKILL);
    }
}

static void try_mount_proc(void) {
#ifdef __linux__
    mkdir("/proc", 0555);
    if (mount("proc", "/proc", "proc", 0, NULL) != 0) {
        perror("mount /proc failed (continuing)");
    }
#else
    /* Non-Linux host: skip mounting /proc inside chroot */
#endif
}

int main(int argc, char *argv[], char *envp[]) {
    if (signal(SIGINT, intHan) == SIG_ERR) {
        perror("signal");
        return 1;
    }

    if (chdir("./rootfs") != 0) {
        perror("chdir");
        return 1;
    }
    if (chroot("./") != 0) {
        perror("chroot");
        return 1;
    }
    // Try to mount /proc inside chroot (helps bionic/linker64)
    try_mount_proc();
    // Ensure key files exist before exec
    struct stat st;
    if (stat("/system/bin/linker64", &st) != 0) {
        perror("missing /system/bin/linker64");
    }
    if (stat("/system/bin/main", &st) != 0) {
        perror("missing /system/bin/main");
    }
    // Ensure /dev exists for urandom
#ifdef __linux__
    mkdir("/dev", 0755);
    mknod("/dev/urandom", S_IFCHR | 0666, makedev(1, 9));
#endif
    chmod("/system/bin/linker64", 0755);
    chmod("/system/bin/main", 0755);

    child_proc = fork();
    if (child_proc == -1) {
        perror("fork");
        return 1;
    }

    if (child_proc > 0) {
        close(STDOUT_FILENO);
        wait(NULL);  // Parent waits for the child process to terminate
        return 0;
    }

    // Child process logic
    mkdir("/data/data/com.apple.android.music/files", 0777);
    mkdir("/data/data/com.apple.android.music/files/mpl_db", 0777);
    // Check required shared libraries presence in /system/lib64
    int missing_libs = 0;
    if (stat("/system/lib64/libc++_shared.so", &st) != 0) {
        perror("missing /system/lib64/libc++_shared.so");
        missing_libs++;
    }
    if (stat("/system/lib64/libandroidappmusic.so", &st) != 0) {
        perror("missing /system/lib64/libandroidappmusic.so");
        missing_libs++;
    }
    if (stat("/system/lib64/libstoreservicescore.so", &st) != 0) {
        perror("missing /system/lib64/libstoreservicescore.so");
        missing_libs++;
    }
    if (stat("/system/lib64/libmediaplatform.so", &st) != 0) {
        perror("missing /system/lib64/libmediaplatform.so");
        missing_libs++;
    }
    if (missing_libs > 0) {
        fprintf(stderr, "FATAL: %d required libs missing under /system/lib64.\n", missing_libs);
        return 2;
    }
    // Hint linker search path just in case
    setenv("LD_LIBRARY_PATH", "/system/lib64", 1);
    execve("/system/bin/main", argv, envp);
    perror("execve");
    return 1;
}