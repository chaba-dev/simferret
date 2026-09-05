#include <errno.h>
#include <linux/reboot.h>
#include <stdio.h>
#include <string.h>
#include <sys/reboot.h>
#include <unistd.h>

int main(void) {
    static const char marker[] = "SIMFERRET_PHASE0_OK version=1\n";

    if (write(STDOUT_FILENO, marker, sizeof(marker) - 1) < 0) {
        fprintf(stderr, "init: write: %s\n", strerror(errno));
        return 1;
    }

    sync();
    if (reboot(LINUX_REBOOT_CMD_POWER_OFF) < 0) {
        fprintf(stderr, "init: reboot: %s\n", strerror(errno));
        return 1;
    }

    return 0;
}
