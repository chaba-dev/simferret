/*
 * Regression tests for the host-input probe guest.
 *
 * The shell probe's measurement rests on properties of the guest loop that a
 * harness double cannot check: the loop has no iteration limit, so a line that
 * arrives after many polls is still reported as received, and the guest never
 * reports that it gave up. This harness drives the real loop
 * (`poc/time-model/input-probe.c`) with stubbed system calls, so restoring a
 * bound, or a give-up report, fails the test rather than passing it.
 *
 * The scenario is selected on the command line and the guest's output is read by
 * `scripts/time-model-input-probe-test.sh`, which is what asserts on it.
 *
 * usage: input-probe-test <late-delivery|no-limit|immediate>
 */

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/reboot.h>

/* The guest under test, with its own entry point renamed. */
#define main guest_main
#include "input-probe.c"
#undef main

static int poll_calls = 0;
static int deliver_after = -1; /* report data available after this many polls */
static int stop_after = 0;     /* end the process after this many polls */
static int rebooted = 0;

static const char guest_line[] = "hello-from-host\n";

int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    (void)nfds;
    (void)timeout;

    poll_calls++;
    if (deliver_after >= 0 && poll_calls > deliver_after) {
        fds->revents = POLLIN;
        return 1;
    }
    if (stop_after > 0 && poll_calls >= stop_after) {
        /* The host stops the emulator, which ends the guest with it. */
        exit(0);
    }
    return 0;
}

char *fgets(char *buffer, int size, FILE *stream) {
    size_t length = strlen(guest_line);

    (void)stream;
    if (size <= 0 || (size_t)size <= length) {
        return NULL;
    }
    memcpy(buffer, guest_line, length + 1);
    return buffer;
}

int reboot(int command) {
    (void)command;
    rebooted = 1;
    return 0;
}

void sync(void) {}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <late-delivery|no-limit|immediate>\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "late-delivery") == 0) {
        /* Beyond the 2000 polls the guest used to stop after. */
        deliver_after = 2500;
    } else if (strcmp(argv[1], "no-limit") == 0) {
        stop_after = 100000;
    } else if (strcmp(argv[1], "immediate") == 0) {
        deliver_after = 0;
    } else {
        fprintf(stderr, "%s: unknown scenario: %s\n", argv[0], argv[1]);
        return 2;
    }

    int status = guest_main();
    printf("rebooted=%d polls=%d\n", rebooted, poll_calls);
    return status;
}
