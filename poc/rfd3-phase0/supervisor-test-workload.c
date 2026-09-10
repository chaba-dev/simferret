/*
 * Test-only workload for the RFD 3 Phase 0 supervisor cleanup regression.
 *
 * The supervisor regression test execs this program as the primary guest
 * workload. It reads its mode from /mode inside the workload root and leaves a
 * descendant behind in one of two shapes, so the supervisor's cleanup barrier
 * can be exercised without QEMU:
 *
 *   writer: a descendant writes to the inherited output pipe without pausing
 *           while the primary exits immediately, so the primary's exit must be
 *           noticed while the pipe is still busy;
 *   silent: the primary closes its output descriptors before it exits, so end of
 *           file arrives first, while a descendant that holds no output
 *           descriptor stays alive.
 *
 * This program is not part of the guest image and is not installed.
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#define MODE_PATH "/mode"

static void read_mode(char *buffer, size_t size) {
    ssize_t received;
    int fd = open(MODE_PATH, O_RDONLY);

    if (fd < 0) {
        _exit(130);
    }
    received = read(fd, buffer, size - 1);
    close(fd);
    if (received <= 0) {
        _exit(131);
    }
    buffer[received] = '\0';
    while (received > 0 &&
           (buffer[received - 1] == '\n' || buffer[received - 1] == '\r')) {
        buffer[--received] = '\0';
    }
}

int main(void) {
    static char block[4096];
    char mode[32];
    pid_t descendant;

    read_mode(mode, sizeof(mode));

    descendant = fork();
    if (descendant < 0) {
        _exit(132);
    }
    if (descendant == 0) {
        if (strcmp(mode, "writer") == 0) {
            /*
             * SIGPIPE is ignored and write errors are retried so this
             * descendant cannot die on its own: if it did, the supervisor would
             * see end of file and the regression this mode exists to detect
             * would go unnoticed. A line every millisecond keeps the output
             * pipe busy well inside the supervisor's poll timeout while
             * bounding what a failing supervisor can write.
             */
            signal(SIGPIPE, SIG_IGN);
            memset(block, 'w', sizeof(block));
            block[15] = '\n';
            for (;;) {
                (void)write(STDOUT_FILENO, block, 16);
                usleep(1000);
            }
        }
        if (strcmp(mode, "silent") == 0) {
            close(STDIN_FILENO);
            close(STDOUT_FILENO);
            close(STDERR_FILENO);
            for (;;) {
                sleep(30);
            }
        }
        _exit(133);
    }

    if (strcmp(mode, "writer") == 0) {
        _exit(0);
    }
    if (strcmp(mode, "silent") == 0) {
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        usleep(200000);
        _exit(0);
    }
    _exit(134);
}
