/*
 * RFD 3 Phase 0 spike guest supervisor.
 *
 * Boots one external workload inside a private chroot, feeds it a fixed command
 * sequence, drains its output while it runs, then kills and reaps every
 * remaining guest process before reporting completion. This is a spike, not the
 * Phase 2 agent: it exposes no command protocol, makes no application-protocol
 * assertions, and does not yet apply a normalized launch configuration.
 *
 * Output is drained concurrently with the workload rather than after it exits,
 * so a workload that writes more than the pipe buffer cannot deadlock against
 * the supervisor's wait.
 */

#include <errno.h>
#include <fcntl.h>
#include <linux/reboot.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * Paths and the power-off call are overridable so the supervisor's cleanup
 * behavior can be exercised by the regression test in a PID namespace on the
 * host, where the paths are test-local and powering off is not a namespace
 * operation. The guest build uses the defaults below.
 */
#ifndef WORKLOAD_ROOT
#define WORKLOAD_ROOT "/workload"
#endif
#ifndef WORKLOAD_PROGRAM
#define WORKLOAD_PROGRAM "/bin/simferret-workload-fixture"
#endif
#ifndef COMMAND_PATH
#define COMMAND_PATH "/etc/simferret-commands"
#endif
#ifndef SOURCE_PATH
#define SOURCE_PATH "/etc/simferret-source-kind"
#endif
#define OUTPUT_BUFFER_BYTES 4096
#define POLL_TIMEOUT_MS 50

static void finish(int status) {
    fflush(stdout);
    sync();
#ifndef SIMFERRET_SUPERVISOR_TEST_NO_REBOOT
    reboot(LINUX_REBOOT_CMD_POWER_OFF);
#endif
    _exit(status);
}

static void fail(const char *kind) {
    printf("SIMFERRET_PHASE0_INFRA_FAILURE kind=%s\n", kind);
    finish(1);
}

static int read_label(const char *path, char *buffer, size_t size) {
    ssize_t received;

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    received = read(fd, buffer, size - 1);
    close(fd);
    if (received < 0) {
        return -1;
    }
    buffer[received] = '\0';
    while (received > 0 &&
           (buffer[received - 1] == '\n' || buffer[received - 1] == '\r')) {
        buffer[--received] = '\0';
    }
    return 0;
}

int main(void) {
    char source[64];
    char buffer[OUTPUT_BUFFER_BYTES];
    size_t output_bytes = 0;
    int commands;
    int output[2];
    int status = 0;
    int workload_status;
    int reaped = 0;
    int workload_exited = 0;
    int killed = 0;
    pid_t child;

    if (getpid() != 1) {
        fail("not_init");
    }
    if (read_label(SOURCE_PATH, source, sizeof(source)) != 0) {
        fail("source_label");
    }

    if (mkdir(WORKLOAD_ROOT "/tmp", 0777) != 0 && errno != EEXIST) {
        fail("overlay_tmp");
    }
    if (chmod(WORKLOAD_ROOT "/tmp", 01777) != 0) {
        fail("overlay_tmp_mode");
    }

    commands = open(COMMAND_PATH, O_RDONLY);
    if (commands < 0) {
        fail("command_file");
    }
    if (pipe(output) != 0) {
        fail("pipe");
    }

    child = fork();
    if (child < 0) {
        fail("fork");
    }
    if (child == 0) {
        if (dup2(commands, STDIN_FILENO) != STDIN_FILENO ||
            dup2(output[1], STDOUT_FILENO) != STDOUT_FILENO ||
            dup2(output[1], STDERR_FILENO) != STDERR_FILENO) {
            _exit(120);
        }
        close(commands);
        close(output[0]);
        close(output[1]);
        if (chroot(WORKLOAD_ROOT) != 0 || chdir("/") != 0) {
            _exit(121);
        }
        execl(WORKLOAD_PROGRAM, WORKLOAD_PROGRAM, (char *)NULL);
        _exit(122);
    }

    close(commands);
    close(output[1]);

    /*
     * Drain output while the workload runs. Every guest process other than this
     * supervisor is a workload member, so once the primary process is gone the
     * remaining members are killed and the pipe reaches end of file. An escaped
     * descendant that keeps the output descriptor open therefore delays EOF
     * until the cleanup barrier, which is exactly the property being shown.
     */
    for (;;) {
        struct pollfd descriptor = {.fd = output[0], .events = POLLIN};
        int ready;

        /*
         * Observe the primary process on every iteration rather than only when
         * the pipe is idle. A descendant that keeps writing would otherwise
         * hold the supervisor in the read branch and postpone the cleanup
         * barrier indefinitely.
         */
        if (!workload_exited && waitpid(child, &status, WNOHANG) == child) {
            workload_exited = 1;
        }
        if (workload_exited && !killed) {
            if (kill(-1, SIGKILL) != 0 && errno != ESRCH) {
                fail("kill_remaining");
            }
            killed = 1;
        }

        ready = poll(&descriptor, 1, POLL_TIMEOUT_MS);
        if (ready > 0) {
            ssize_t received = read(output[0], buffer, sizeof(buffer));
            if (received > 0) {
                if (fwrite(buffer, 1, (size_t)received, stdout) != (size_t)received) {
                    fail("write_output");
                }
                output_bytes += (size_t)received;
                continue;
            }
            if (received == 0) {
                break;
            }
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            fail("read_output");
        } else if (ready < 0 && errno != EINTR) {
            fail("poll_output");
        }
    }
    close(output[0]);

    /*
     * End of file can arrive before the primary is reaped, for example when a
     * workload closes its output descriptors and keeps running. Guarantee the
     * cleanup barrier on that path too, before blocking on a living descendant.
     */
    if (!workload_exited) {
        if (waitpid(child, &status, 0) != child) {
            fail("wait_workload");
        }
        workload_exited = 1;
    }
    if (!killed) {
        if (kill(-1, SIGKILL) != 0 && errno != ESRCH) {
            fail("kill_remaining");
        }
        killed = 1;
    }
    workload_status = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);

    for (;;) {
        pid_t process = waitpid(-1, NULL, 0);
        if (process > 0) {
            reaped++;
            continue;
        }
        if (process < 0 && errno == EINTR) {
            continue;
        }
        break;
    }

    printf("supervisor source=%s\n", source);
    printf("supervisor workload_status=%d\n", workload_status);
    printf("supervisor cleanup_reaped=%d\n", reaped);
    printf("supervisor output_bytes=%zu\n", output_bytes);

    if (workload_status != 0) {
        fail("workload_status");
    }
    if (reaped < 1) {
        fail("cleanup_barrier");
    }
    printf("SIMFERRET_PHASE0_SUPERVISOR_OK version=1\n");
    finish(0);
}
