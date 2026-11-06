/* Ordinary private socket/close regressions; never invokes the PID1 bootstrap. */
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/socket.h>

static const char *stage = "startup";
static ssize_t observed_recvmsg(int fd, struct msghdr *msg, int flags) {
    ssize_t n = recvmsg(fd, msg, flags);
    fprintf(stderr, "owner_eof_test stage=%s n=%zd flags=0x%x control=%zu\n",
        stage, n, msg->msg_flags, msg->msg_controllen);
    return n;
}

#define recvmsg observed_recvmsg
#define main worker_owner_entrypoint
#include "../worker_owner.c"
#undef main
#undef recvmsg

static void check(int condition) {
    if (!condition) _exit(1);
}

static void sockets(int pair[2]) {
    int one = 1;
    check(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) == 0);
    check(setsockopt(pair[0], SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)) == 0);
}

static short ready(int fd) {
    struct pollfd event = { .fd = fd, .events = POLLIN };
    check(poll(&event, 1, 1000) == 1);
    check((event.revents & (POLLIN | POLLHUP)) == (POLLIN | POLLHUP));
    return event.revents;
}

static void queued_packet_then_eof(void) {
    stage = "queued_packet";
    int pair[2]; sockets(pair);
    struct packet sent = { .magic = MAGIC, .type = DONE };
    sent.binding[0] = 42;
    send_packet(pair[1], &sent);
    check(close(pair[1]) == 0);
    short event = ready(pair[0]);
    struct packet got;
    check(receive(pair[0], getpid(), getuid(), event & POLLHUP, &got) == 1);
    check(memcmp(&sent, &got, sizeof(sent)) == 0);
    stage = "queued_eof";
    event = ready(pair[0]);
    check(receive(pair[0], getpid(), getuid(), event & POLLHUP, &got) == 0);
    check(close(pair[0]) == 0);
}

static void eof_before_waitable_child(void) {
    stage = "nonwaitable_child_eof";
    int pair[2], release[2]; sockets(pair);
    check(pipe2(release, O_CLOEXEC) == 0);
    pid_t child = fork();
    check(child >= 0);
    if (child == 0) {
        check(close(pair[0]) == 0 && close(release[1]) == 0);
        check(close(pair[1]) == 0);
        char byte;
        check(read(release[0], &byte, 1) == 1);
        _exit(0);
    }
    check(close(pair[1]) == 0 && close(release[0]) == 0);
    short event = ready(pair[0]);
    int status;
    check(waitpid(child, &status, WNOHANG) == 0);
    struct packet got;
    check(receive(pair[0], child, getuid(), event & POLLHUP, &got) == 0);
    check(waitpid(child, &status, WNOHANG) == 0);
    check(write(release[1], "x", 1) == 1 && close(release[1]) == 0);
    check(waitpid(child, &status, 0) == child);
    check(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    check(close(pair[0]) == 0);
}

static void refused(int malformed) {
    stage = malformed ? "malformed_packet_refused" : "active_eof_refused";
    pid_t child = fork();
    check(child >= 0);
    if (child == 0) {
        int pair[2]; sockets(pair);
        if (malformed) check(send(pair[1], "x", 1, MSG_NOSIGNAL) == 1);
        check(close(pair[1]) == 0);
        short event = ready(pair[0]);
        struct packet got;
        /* A malformed queued packet remains a refusal even in terminal state;
         * clean EOF remains a refusal while an attempt is still active. */
        (void)receive(pair[0], getpid(), getuid(), malformed && (event & POLLHUP), &got);
        _exit(1);
    }
    int status;
    check(waitpid(child, &status, 0) == child);
    check(WIFEXITED(status) && WEXITSTATUS(status) == 125);
}

int main(void) {
    check(getuid() == getgid());
    queued_packet_then_eof();
    eof_before_waitable_child();
    refused(0);
    refused(1);
    return 0;
}
