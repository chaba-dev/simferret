/*
 * SimFerret host-input probe.
 *
 * Answers the question the time-model probe does not: does a guest that waits
 * for host input receive it under a given QEMU time model? It runs as the guest
 * init, prints READY, and polls the console until the line arrives or the host
 * stops the emulator, reporting the line it received and how many polls it took.
 *
 * The host stops this guest through the emulator's monitor, writes its line, and
 * resumes it, so the line is submitted while this loop cannot be polling and the
 * polling it does after the resume is polling after the write. That ordering is
 * what makes the absence of a GOT report a measurement: a guest that stopped
 * polling before the write would make the same report, and no poll limit can
 * rule that out from inside the guest. There is therefore no iteration limit.
 * The loop runs until the line arrives or the emulator is stopped, and the
 * host's wait is what ends the experiment.
 *
 * The bounded poll matters. A blocking read measures only whether the guest is
 * woken from an unbounded halt; this loop arms a 100 ms timer on every
 * iteration, so it also measures whether input arrives while virtual time keeps
 * advancing. Both were measured, and neither delivered input under the pinned
 * model with record/replay enabled.
 */

#include <errno.h>
#include <linux/reboot.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/reboot.h>
#include <unistd.h>

#define POLL_TIMEOUT_MS 100
#define REPORT_INTERVAL 10

int main(void) {
    char line[128];
    struct pollfd descriptor = {.fd = 0, .events = POLLIN, .revents = 0};
    int iterations = 0;

    printf("READY\n");
    fflush(stdout);

    for (;;) {
        int ready = poll(&descriptor, 1, POLL_TIMEOUT_MS);

        if (ready < 0) {
            printf("POLL-ERROR errno=%d\n", errno);
            fflush(stdout);
            break;
        }
        iterations++;
        if (ready > 0) {
            memset(line, 0, sizeof(line));
            if (fgets(line, sizeof(line), stdin) == NULL) {
                printf("EOF\n");
                fflush(stdout);
                break;
            }
            line[strcspn(line, "\r\n")] = '\0';
            printf("GOT:%s iterations=%d\n", line, iterations);
            fflush(stdout);
            sync();
            reboot(LINUX_REBOOT_CMD_POWER_OFF);
            return 0;
        }
        if (iterations % REPORT_INTERVAL == 0) {
            printf("WAITING iterations=%d\n", iterations);
            fflush(stdout);
        }
    }
    sync();
    reboot(LINUX_REBOOT_CMD_POWER_OFF);
    return 1;
}
