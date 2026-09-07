#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    static const char request[] = "simferret-outage-probe";
    struct sockaddr_in peer = {
        .sin_family = AF_INET,
        .sin_port = htons(69),
    };
    int socket_fd;
    int send_error;
    ssize_t sent;

    if (inet_pton(AF_INET, "10.0.2.2", &peer.sin_addr) != 1) {
        fprintf(stderr, "outage-probe: invalid fixed peer address\n");
        return 1;
    }
    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        fprintf(stderr, "outage-probe: socket: %s\n", strerror(errno));
        return 1;
    }

    errno = 0;
    sent = sendto(socket_fd, request, sizeof(request) - 1, 0,
                  (const struct sockaddr *)&peer, sizeof(peer));
    send_error = errno;
    if (close(socket_fd) < 0) {
        fprintf(stderr, "outage-probe: close: %s\n", strerror(errno));
        return 1;
    }
    if (sent >= 0) {
        fprintf(stderr, "outage-probe: packet unexpectedly sent\n");
        return 1;
    }
    if (send_error != EACCES) {
        fprintf(stderr, "outage-probe: sendto: expected EACCES, got %s\n",
                strerror(send_error));
        return 1;
    }
    return 0;
}
