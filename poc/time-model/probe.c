/*
 * SimFerret guest time-model probe.
 *
 * Answers one question: is guest-observable time a reproducible function of a
 * fixed VM configuration? It runs as the guest init, takes five measurements
 * that mirror how real services use time (sleep, CPU work inside a window,
 * a fixed computation racing a deadline, short-sleep quantization), prints
 * them, and powers off.
 *
 * This is a diagnostic, not a workload. The checksum line is a control: it is a
 * pure function of the fixed computation, so a stable checksum means that
 * computation produced the same result even though its measured duration
 * changed. It does not establish that the guest executed an identical
 * instruction stream; the spin counts differ between runs, which shows that it
 * did not.
 */

#include <errno.h>
#include <linux/reboot.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/reboot.h>
#include <time.h>
#include <unistd.h>

#define NS_PER_MS 1000000ull
#define SLEEP_NS (20ull * NS_PER_MS)
#define WINDOW_NS (20ull * NS_PER_MS)
#define SPIN_CHUNK 10000ull
#define SPIN_CHECKS 64ull
#define RACE_WORK 2000000ull
#define SLEEP_LOOP 100ull
#define MIX_MULTIPLIER 6364136223846793005ull

static uint64_t monotonic_ns(void) {
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000000000ull + (uint64_t)now.tv_nsec;
}

static void sleep_ns(uint64_t nanoseconds) {
    struct timespec request = {
        .tv_sec = (time_t)(nanoseconds / 1000000000ull),
        .tv_nsec = (long)(nanoseconds % 1000000000ull),
    };

    while (nanosleep(&request, &request) != 0 && errno == EINTR) {
    }
}

static uint64_t mix(uint64_t state, uint64_t index) {
    return state * MIX_MULTIPLIER + index + 1;
}

int main(void) {
    uint64_t spin_state = 0;
    uint64_t race_state = 0;
    uint64_t start;
    uint64_t elapsed;

    /* 1. Does a fixed sleep complete in the requested virtual duration? */
    start = monotonic_ns();
    sleep_ns(SLEEP_NS);
    printf("probe sleep requested_ns=%llu observed_ns=%llu\n",
           (unsigned long long)SLEEP_NS,
           (unsigned long long)(monotonic_ns() - start));

    /*
     * 2. How many fixed CPU chunks complete before the first poll that finds
     * the window expired. The clock is polled only once per SPIN_CHECKS chunks
     * and the terminating batch is counted in full, so this is a
     * polling-quantized count rather than throughput inside the window: each
     * polling batch can already exceed WINDOW_NS at coarse time scales.
     * Both the chunk count and the accumulated state are time-dependent, so
     * neither is a control.
     */
    start = monotonic_ns();
    uint64_t chunks = 0;
    for (;;) {
        uint64_t checks = 0;
        do {
            for (uint64_t index = 0; index < SPIN_CHUNK; index++) {
                spin_state = mix(spin_state, index);
            }
            chunks++;
        } while (++checks < SPIN_CHECKS);
        if (monotonic_ns() - start >= WINDOW_NS) {
            break;
        }
    }
    printf("probe spin chunks=%llu window_ns=%llu state=%llu\n",
           (unsigned long long)chunks, (unsigned long long)WINDOW_NS,
           (unsigned long long)spin_state);

    /*
     * 3. Does a fixed computation finish inside one fixed virtual deadline?
     * The iteration count is fixed, so race_state is a pure function of the
     * executed instruction stream and is the experiment's control.
     */
    start = monotonic_ns();
    for (uint64_t index = 0; index < RACE_WORK; index++) {
        race_state = mix(race_state, index);
    }
    elapsed = monotonic_ns() - start;
    printf("probe race work=%llu elapsed_ns=%llu within_deadline=%s\n",
           (unsigned long long)RACE_WORK, (unsigned long long)elapsed,
           elapsed < WINDOW_NS ? "yes" : "no");

    /* 4. Are many short sleeps quantized reproducibly? */
    start = monotonic_ns();
    for (uint64_t index = 0; index < SLEEP_LOOP; index++) {
        sleep_ns(NS_PER_MS);
    }
    printf("probe sleep_loop iterations=%llu observed_ns=%llu\n",
           (unsigned long long)SLEEP_LOOP,
           (unsigned long long)(monotonic_ns() - start));

    printf("probe checksum value=%llu\n", (unsigned long long)race_state);
    fflush(stdout);
    sync();
    reboot(LINUX_REBOOT_CMD_POWER_OFF);
    return 0;
}
