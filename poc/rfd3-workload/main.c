#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define COMMAND_BYTES 256
#define TFTP_BYTES 516
#define TOKEN_BYTES 128

#ifndef FIXTURE_PEER_ADDRESS
#define FIXTURE_PEER_ADDRESS "10.0.2.2"
#endif

#ifndef FIXTURE_TFTP_PORT
#define FIXTURE_TFTP_PORT 69
#endif

static const char *const peer_address = FIXTURE_PEER_ADDRESS;
static const char *const state_path = "/tmp/simferret-fixture-state";

static int valid_token(const char *value) {
    size_t length = strlen(value);

    if (length == 0 || length >= TOKEN_BYTES) {
        return 0;
    }
    for (size_t index = 0; index < length; index++) {
        char character = value[index];
        if (!((character >= 'a' && character <= 'z') ||
              (character >= 'A' && character <= 'Z') ||
              (character >= '0' && character <= '9') || character == '-' ||
              character == '_')) {
            return 0;
        }
    }
    return 1;
}

static int valid_request_id(const char *value) {
    static const char prefix[] = "request-";

    return strncmp(value, prefix, sizeof(prefix) - 1) == 0 &&
           valid_token(value) && value[sizeof(prefix) - 1] != '\0';
}

static int emit_state(void) {
    int stale = access(state_path, F_OK) == 0;
    FILE *state;

    if (!stale && errno != ENOENT) {
        perror("fixture: inspect state");
        return -1;
    }
    state = fopen(state_path, "wx");
    if (state == NULL) {
        if (!stale) {
            perror("fixture: create state");
            return -1;
        }
    } else if (fclose(state) != 0) {
        perror("fixture: close state");
        return -1;
    }
    printf("state value=%s\n", stale ? "stale" : "fresh");
    return fflush(stdout);
}

static int spawn_escaped_descendant(void) {
    int ready[2];
    pid_t child;
    char marker;

    if (pipe(ready) != 0) {
        perror("fixture: pipe");
        return -1;
    }
    child = fork();
    if (child < 0) {
        perror("fixture: fork");
        return -1;
    }
    if (child == 0) {
        pid_t descendant = fork();

        close(ready[0]);
        if (descendant < 0) {
            _exit(1);
        }
        if (descendant > 0) {
            _exit(0);
        }
        if (setsid() < 0 || signal(SIGTERM, SIG_IGN) == SIG_ERR ||
            write(ready[1], "R", 1) != 1) {
            _exit(1);
        }
        close(ready[1]);
        for (;;) {
            pause();
        }
    }

    close(ready[1]);
    if (waitpid(child, NULL, 0) != child || read(ready[0], &marker, 1) != 1 ||
        marker != 'R') {
        fprintf(stderr, "fixture: descendant did not become ready\n");
        close(ready[0]);
        return -1;
    }
    close(ready[0]);
    printf("descendant state=escaped\n");
    return fflush(stdout);
}

static int tftp_request(const char *request_id, const char *expected_payload) {
    struct sockaddr_in peer = {
        .sin_family = AF_INET,
        .sin_port = htons(FIXTURE_TFTP_PORT),
    };
    struct sockaddr_in server;
    socklen_t server_length = sizeof(server);
    struct timeval timeout = {.tv_sec = 2, .tv_usec = 0};
    unsigned char request[TOKEN_BYTES + 9] = {0, 1};
    unsigned char response[TFTP_BYTES];
    char expected[TFTP_BYTES];
    size_t request_length = strlen(request_id);
    ssize_t received;
    int socket_fd;
    int expected_length;

    if (!valid_request_id(request_id) || !valid_token(expected_payload) ||
        request_length + 9 > sizeof(request)) {
        fprintf(stderr, "fixture: invalid request expectation\n");
        return -1;
    }
    if (inet_pton(AF_INET, peer_address, &peer.sin_addr) != 1) {
        fprintf(stderr, "fixture: invalid fixed peer address\n");
        return -1;
    }
    memcpy(request + 2, request_id, request_length);
    memcpy(request + 2 + request_length, "\0octet\0", 7);

    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0 ||
        setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(timeout)) != 0) {
        perror("fixture: socket");
        if (socket_fd >= 0) {
            close(socket_fd);
        }
        return -1;
    }
    if (sendto(socket_fd, request, request_length + 9, 0,
               (const struct sockaddr *)&peer, sizeof(peer)) < 0) {
        int send_errno = errno;
        close(socket_fd);
        if (send_errno == EACCES) {
            printf("network state=unavailable request=%s errno=%d\n", request_id,
                   send_errno);
            return fflush(stdout);
        }
        errno = send_errno;
        perror("fixture: send request");
        return -1;
    }

    received = recvfrom(socket_fd, response, sizeof(response), 0,
                        (struct sockaddr *)&server, &server_length);
    if (received < 4 || server.sin_family != AF_INET ||
        server.sin_addr.s_addr != peer.sin_addr.s_addr || response[0] != 0 ||
        response[1] != 3 || response[2] != 0 || response[3] != 1) {
        close(socket_fd);
        fprintf(stderr, "fixture: invalid TFTP response\n");
        return -1;
    }
    if (sendto(socket_fd, (unsigned char[]){0, 4, 0, 1}, 4, 0,
               (const struct sockaddr *)&server, server_length) != 4) {
        close(socket_fd);
        perror("fixture: acknowledge response");
        return -1;
    }
    close(socket_fd);

    expected_length = snprintf(expected, sizeof(expected),
                               "request_id=%s\npayload=%s\n", request_id,
                               expected_payload);
    if (expected_length < 0 || (size_t)expected_length != (size_t)received - 4 ||
        memcmp(response + 4, expected, (size_t)expected_length) != 0) {
        fprintf(stderr, "fixture: response content mismatch\n");
        return -1;
    }
    printf("network state=ok request=%s\n", request_id);
    return fflush(stdout);
}

int main(void) {
    char command[COMMAND_BYTES];
    int descendant_spawned = 0;

    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("ready version=1\n");
    while (fgets(command, sizeof(command), stdin) != NULL) {
        char *argument;
        char *second_argument = NULL;
        size_t length = strlen(command);

        if (length == 0 || command[length - 1] != '\n') {
            fprintf(stderr, "fixture: command exceeds limit\n");
            return 2;
        }
        command[length - 1] = '\0';
        argument = strchr(command, ' ');
        if (argument != NULL) {
            *argument++ = '\0';
            second_argument = strchr(argument, ' ');
            if (second_argument != NULL) {
                *second_argument++ = '\0';
            }
        }

        if (strcmp(command, "echo") == 0 && argument != NULL &&
            second_argument == NULL && valid_token(argument)) {
            printf("echo value=%s\n", argument);
        } else if (strcmp(command, "state") == 0 && argument == NULL) {
            if (emit_state() != 0) {
                return 1;
            }
        } else if (strcmp(command, "spawn-descendant") == 0 && argument == NULL) {
            if (descendant_spawned) {
                fprintf(stderr, "fixture: descendant already spawned\n");
                return 2;
            }
            if (spawn_escaped_descendant() != 0) {
                return 1;
            }
            descendant_spawned = 1;
        } else if (strcmp(command, "fetch") == 0 && argument != NULL &&
                   second_argument != NULL &&
                   strchr(second_argument, ' ') == NULL) {
            if (tftp_request(argument, second_argument) != 0) {
                return 1;
            }
        } else if (strcmp(command, "exit") == 0 && argument == NULL) {
            printf("stopped status=0\n");
            return 0;
        } else {
            fprintf(stderr, "fixture: invalid command\n");
            return 2;
        }
    }
    return ferror(stdin) ? 1 : 0;
}
