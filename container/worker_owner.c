/* Worker-only PID-namespace owner. No policy, network, arbitrary argv or plugins. */
#define _GNU_SOURCE
#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <limits.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "worker owner protocol currently requires little-endian Linux"
#endif
#define OWNER 10000
#define RUNNER 10001
#ifdef VARDR_PERSISTENT
#define MAGIC 0x33574456u
#define READY_SCHEMA "vardr.worker-owner-ready/3"
#else
#define MAGIC 0x32574456u
#define READY_SCHEMA "vardr.worker-owner-ready/2"
#endif
#define NS 1000000000ULL
#define REPORT_RUNWAY (150ULL * NS)
#define BOOT 0u
#define READY 1u
#define HELLO 2u
#define LEASE 3u
#define DONE 4u
#define ACK 5u
#define MAX_ATTEMPTS 32u
#define IDLE_SECONDS 60u
struct packet { uint32_t magic, type; uint64_t sequence, lease, hard; unsigned char binding[32]; };
_Static_assert(sizeof(struct packet) == 64, "fixed local protocol ABI");
struct protocol {
    int hello, armed, done;
    uint64_t sequence, lease, hard, work_end, grant_end;
    unsigned char binding[32];
    uint64_t idle_seconds, maximum;
#ifdef VARDR_PERSISTENT
    uint64_t eof_end;
#endif
};
static volatile sig_atomic_t stopping;
static void stopped(int signo) { (void)signo; stopping = 1; }
static void fail(void) { _exit(125); }
static char *child_env[64];
static size_t env_count;
static void keep_env(const char *name) {
    const char *value = getenv(name);
    if (!value) return;
    size_t n = strlen(name), v = strlen(value);
    if (v > 8192 || env_count >= 63) fail();
    char *entry = malloc(n + v + 2);
    if (!entry) fail();
    memcpy(entry, name, n); entry[n] = '='; memcpy(entry + n + 1, value, v + 1);
    child_env[env_count++] = entry;
}
static void fixed_env(const char *entry) {
    if (env_count >= 63 || !(child_env[env_count++] = strdup(entry))) fail();
}
static void prepare_environment(void) {
    const char *fixed[] = {"VARDRMAP_URL", "VARDRMAP_API_KEY", "VARDRRUNNER_NAME",
        "VARDRRUNNER_WORKER_DURATION_SECONDS", "VARDRRUNNER_WORKER_WAIT_SECONDS",
        "VARDRRUNNER_WORKER_ADMISSION_WAIT_SECONDS", "VARDRRUNNER_ALLOW_PRIVATE_TARGETS",
        "VARDRRUNNER_DENY_TARGETS", "VARDRRUNNER_ALLOW_DENIED_TARGETS", "VARDRRUNNER_MAX_TARGETS",
        "VARDRRUNNER_MAX_ARTIFACT_MB", "VARDRRUNNER_MAX_CONCURRENT_JOBS",
        "VARDRRUNNER_MIN_FREE_DISK_MB", "VARDRRUNNER_TOOL_TIMEOUT", NULL};
    for (size_t i = 0; fixed[i]; i++) keep_env(fixed[i]);
    const char *declared = getenv("VARDRRUNNER_WORKER_CREDENTIAL_ENV");
    if (declared && *declared) {
        if (strlen(declared) > 4096) fail();
        if (*declared == ',' || declared[strlen(declared) - 1] == ',' || strstr(declared, ",,")) fail();
        char *list = strdup(declared), *save = NULL;
        if (!list) fail();
        size_t count = 0;
        char names[32][129];
        for (char *name = strtok_r(list, ",", &save); name; name = strtok_r(NULL, ",", &save)) {
            size_t n = strlen(name);
            if (++count > 32 || !n || n > 128 || !((name[0] >= 'A' && name[0] <= 'Z') ||
                (name[0] >= 'a' && name[0] <= 'z') || name[0] == '_')) fail();
            for (size_t i = 0; i < n; i++)
                if (!((name[i] >= 'A' && name[i] <= 'Z') ||
                    (name[i] >= 'a' && name[i] <= 'z') ||
                    (name[i] >= '0' && name[i] <= '9') || name[i] == '_')) fail();
            /* A credential name cannot configure an interpreter, loader or runtime. */
            const char *denied[] = {"LD", "DYLD", "PYTHON", "GCONV", "GLIBC", "OPENSSL",
                "SSL", "REQUESTS", "MALLOC", "LIB", "GTK", "GIO", "GI_", "QT", "DBUS",
                "PATH", "HOME", "LANG", "LC_", "XDG", "TMP", "TEMP", "TZ", "SHELL",
                "ENV", "BASH", "VARDRMAP", "VARDRRUNNER", "HTTP_PROXY", "HTTPS_PROXY",
                "ALL_PROXY", "NO_PROXY", NULL};
            for (size_t i = 0; denied[i]; i++)
                if (!strncasecmp(name, denied[i], strlen(denied[i]))) fail();
            for (size_t i = 0; i + 1 < count; i++) if (!strcmp(name, names[i])) fail();
            strcpy(names[count - 1], name); keep_env(name);
        }
        free(list);
    }
    fixed_env("HOME=/home/runner");
    fixed_env("PATH=/opt/vardrtools/bin:/usr/local/bin:/usr/bin:/bin");
    fixed_env("VARDRRUNNER_TOOLS_DIR=/opt/vardrtools");
    fixed_env("REQUESTS_CA_BUNDLE=/trust/root.crt");
    fixed_env("LANG=C.UTF-8"); fixed_env("TMPDIR=/tmp");
    fixed_env("XDG_CONFIG_HOME=/home/runner/.vardrmap");
    fixed_env("XDG_CACHE_HOME=/home/runner/.vardrmap/tool-cache");
    child_env[env_count] = NULL;
    /* Before NSS lookups as well as before Python's dynamic loader starts. */
    extern char **environ;
    for (char **p = environ; *p; p++) explicit_bzero(*p, strlen(*p));
    if (clearenv()) fail();
}
static uint64_t now_ns(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_BOOTTIME, &t) || t.tv_sec < 0) fail();
    return (uint64_t)t.tv_sec * NS + (uint64_t)t.tv_nsec;
}
static void caps(struct __user_cap_data_struct data[2]) {
    struct __user_cap_header_struct header = { _LINUX_CAPABILITY_VERSION_3, 0 };
    if (syscall(SYS_capget, &header, data)) fail();
}
static void zero_caps(void) {
    struct __user_cap_header_struct header = { _LINUX_CAPABILITY_VERSION_3, 0 };
    struct __user_cap_data_struct data[2] = {{0}, {0}};
    if (syscall(SYS_capset, &header, data)) fail();
}
static void verify_zero(void) {
    struct __user_cap_data_struct data[2];
    caps(data);
    for (int i = 0; i < 2; i++)
        if (data[i].effective || data[i].permitted || data[i].inheritable) fail();
    for (int i = 0; i < 64; i++) {
        int b = prctl(PR_CAPBSET_READ, i, 0, 0, 0);
        if (b < 0 && errno == EINVAL) break;
        if (b != 0 || prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, i, 0, 0) != 0) fail();
    }
    if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) fail();
}
static void credentials(uid_t id) {
    uid_t r, e, s; gid_t gr, ge, gs;
    if (setgroups(0, NULL) || setresgid(id, id, id) || setresuid(id, id, id)) fail();
    zero_caps();
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)) fail();
    if (getresuid(&r, &e, &s) || getresgid(&gr, &ge, &gs) ||
        r != id || e != id || s != id || gr != id || ge != id || gs != id ||
        getgroups(0, NULL) != 0) fail();
    verify_zero();
}
static void send_packet(int fd, const struct packet *p) {
    if (send(fd, p, sizeof(*p), MSG_NOSIGNAL | MSG_DONTWAIT) != (ssize_t)sizeof(*p)) fail();
}
static void close_inherited(void) {
    /* Single-threaded before exec: no new descriptors can race this bounded walk. */
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) fail();
    int own = dirfd(directory), fds[256];
    if (own < 0) fail();
    size_t count = 0, entries = 0;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(directory))) {
        if (++entries > 258) fail();
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char *end;
        errno = 0;
        long value = strtol(entry->d_name, &end, 10);
        if (errno || *end || end == entry->d_name || value < 0 || value > INT_MAX) fail();
        if (value > 3 && value != own) {
            if (count == 256) fail();
            fds[count++] = (int)value;
        }
    }
    if (errno || closedir(directory)) fail();
    for (size_t i = 0; i < count; i++) if (close(fds[i])) fail();
}
static int receive(int fd, pid_t pid, uid_t uid, int eof_allowed, struct packet *p) {
    char ancillary[CMSG_SPACE(sizeof(struct ucred))];
    struct iovec iov = { p, sizeof(*p) };
    struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = ancillary, .msg_controllen = sizeof(ancillary) };
    ssize_t n = recvmsg(fd, &msg, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
    /* Linux may echo the requested CMSG_CLOEXEC flag even on clean EOF. */
    if (n == 0 && !(msg.msg_flags & ~MSG_CMSG_CLOEXEC) && msg.msg_controllen == 0) {
        if (!eof_allowed) fail();
        return 0;
    }
    if (n != (ssize_t)sizeof(*p) || msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC) || p->magic != MAGIC) fail();
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    if (!c || c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_CREDENTIALS ||
        c->cmsg_len != CMSG_LEN(sizeof(struct ucred)) || CMSG_NXTHDR(&msg, c)) fail();
    struct ucred cred; memcpy(&cred, CMSG_DATA(c), sizeof(cred));
    if (cred.pid != pid || cred.uid != uid || cred.gid != uid) fail();
    return 1;
}
static void idle(struct protocol *state, uint64_t now) {
#ifdef VARDR_PERSISTENT
    uint64_t seconds = state->idle_seconds;
    if (!seconds) { state->lease = state->hard = UINT64_MAX; return; }
#else
    uint64_t seconds = IDLE_SECONDS;
#endif
    if (now > UINT64_MAX - seconds * NS) fail();
    state->lease = state->hard = now + seconds * NS;
    if (state->work_end < state->lease) state->lease = state->hard = state->work_end;
}
#ifdef VARDR_PERSISTENT
static void eof_wait(struct protocol *state, uint64_t now) {
    if (state->armed) fail();
    if (!state->eof_end) {
        if (now > UINT64_MAX - 5 * NS) fail();
        state->eof_end = now + 5 * NS;
    }
    if (now >= state->eof_end) fail();
}
#endif
static void accept_packet(struct protocol *state, const struct packet *p,
    const unsigned char nonce[32], uint64_t now) {
#ifdef VARDR_PERSISTENT
    if (state->eof_end) fail();
#endif
    if (now >= state->lease || now >= state->hard || now >= state->grant_end) fail();
    if (!state->hello) {
#ifdef VARDR_PERSISTENT
        /* HELLO slots carry optional seconds/count policy, never job deadlines. */
        if (p->type != HELLO || p->sequence || p->lease > 86400 ||
            p->hard > INT64_MAX || memcmp(p->binding, nonce, 32)) fail();
        state->idle_seconds = p->lease; state->maximum = p->hard;
        state->work_end = state->grant_end = UINT64_MAX;
        idle(state, now);
#else
        if (p->type != HELLO || p->sequence || p->lease <= now || p->hard <= p->lease ||
            p->hard - p->lease != REPORT_RUNWAY || p->hard > now + 604800 * NS ||
            memcmp(p->binding, nonce, 32)) fail();
        state->work_end = p->lease; state->grant_end = p->hard;
        uint64_t ending = state->lease;
        idle(state, now);
        if (ending < state->lease) state->lease = state->hard = ending;
#endif
        state->hello = 1;
    } else if (p->type == LEASE) {
        if (p->lease <= now || p->lease > now + 10 * NS || p->hard < p->lease ||
            p->hard > now + 86400 * NS || p->hard > state->work_end) fail();
        if (state->armed) {
            if (p->sequence != state->sequence || memcmp(state->binding, p->binding, 32) ||
                p->hard > state->hard) fail();
        } else {
#ifdef VARDR_PERSISTENT
            if (state->sequence >= INT64_MAX || (state->maximum &&
                state->sequence >= state->maximum) || p->sequence != state->sequence + 1) fail();
#else
            if (state->sequence >= MAX_ATTEMPTS || p->sequence != state->sequence + 1) fail();
#endif
            state->sequence = p->sequence;
            memcpy(state->binding, p->binding, 32);
        }
        state->hard = p->hard; state->lease = p->lease;
        state->armed = 1; state->done = 0;
    } else if (p->type == DONE && state->armed && !state->done) {
        if (p->sequence != state->sequence || memcmp(state->binding, p->binding, 32) ||
            p->lease || p->hard) fail();
        state->armed = 0; state->done = 1;
        idle(state, now);
    } else fail();
}
static void publish(const unsigned char nonce[32]) {
    int dir = open("/run/vardr-worker-ready", O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    if (dir < 0 || fstat(dir, &st) || st.st_uid != OWNER || st.st_gid != OWNER ||
        (st.st_mode & 0777) != 0700) fail();
    int fd = openat(dir, "owner.json", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0400);
    if (fd < 0) fail();
    char hex[65];
    for (int i = 0; i < 32; i++) snprintf(hex + i * 2, 3, "%02x", nonce[i]);
    char out[1024];
    int n = snprintf(out, sizeof(out),
        "{\"schema\":\"" READY_SCHEMA "\",\"owner_nonce\":\"%s\","
        "\"owner_pid\":1,\"owner_uid\":10000,\"runner_uid\":10001,"
        "\"capabilities\":{\"effective\":\"0000000000000000\",\"permitted\":\"0000000000000000\","
        "\"inheritable\":\"0000000000000000\",\"ambient\":\"0000000000000000\","
        "\"bounding\":\"0000000000000000\"},\"no_new_privs\":true}\n", hex);
    if (n < 0 || (size_t)n >= sizeof(out) || write(fd, out, (size_t)n) != n || fsync(fd)) fail();
    if (fstat(fd, &st) || st.st_uid != OWNER || st.st_gid != OWNER ||
        (st.st_mode & 0777) != 0400 || st.st_nlink != 1) fail();
    close(fd); close(dir);
}
int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1 || getpid() != 1 || getppid() != 0 || getuid() != 0 || geteuid() != 0) fail();
    prepare_environment();
    errno = 0;
    if (getpwuid(OWNER) != NULL || errno != 0) fail();
    errno = 0;
    if (getgrgid(OWNER) != NULL || errno != 0) fail();
    struct __user_cap_data_struct data[2]; caps(data);
    uint32_t initial = (1u << CAP_SETUID) | (1u << CAP_SETGID) | (1u << CAP_SETPCAP);
    if (data[0].effective != initial || data[0].permitted != initial || data[0].inheritable ||
        data[1].effective || data[1].permitted || data[1].inheritable) fail();
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)) fail();
    for (int cap = 0; cap < 64; cap++) {
        int b = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
        if (b < 0 && errno == EINVAL) break;
        if (b < 0 || b != (cap < 32 && (initial & (1u << cap)) ? 1 : 0) ||
            prctl(PR_CAPBSET_DROP, cap, 0, 0, 0)) fail();
    }
    int pair[2], one = 1;
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) ||
        setsockopt(pair[0], SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)) ||
        setsockopt(pair[1], SOL_SOCKET, SO_PASSCRED, &one, sizeof(one))) fail();
    unsigned char nonce[32];
    if (getrandom(nonce, sizeof(nonce), 0) != (ssize_t)sizeof(nonce)) fail();
    uint64_t startup = now_ns() + 120 * NS;
    pid_t child = fork();
    if (child < 0) fail();
    if (child == 0) {
        if (close(pair[0])) fail();
        if (setsid() < 0) fail();
        credentials(RUNNER);
        if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)) fail();
        if (pair[1] != 3) {
            if (dup2(pair[1], 3) != 3 || close(pair[1])) fail();
        }
        if (fcntl(3, F_SETFD, 0)) fail();
        int empty = open("/dev/null", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        struct stat input;
        if (empty < 0 || fstat(empty, &input) || !S_ISCHR(input.st_mode) ||
            dup2(empty, STDIN_FILENO) != STDIN_FILENO) fail();
        if (empty != STDIN_FILENO && close(empty)) fail();
        if (fcntl(STDIN_FILENO, F_SETFD, 0)) fail();
        close_inherited();
        struct packet boot = { .magic = MAGIC, .type = BOOT };
        send_packet(3, &boot);
        char *command[] = {"python", "-I", "-m", "vardrrunner.managed_worker", NULL};
        execve("/usr/local/bin/python", command, child_env);
        fail();
    }
    if (close(pair[1])) fail();
    for (size_t i = 0; i < env_count; i++) {
        explicit_bzero(child_env[i], strlen(child_env[i])); free(child_env[i]);
    }
    credentials(OWNER);
    if (clearenv()) fail();
    struct sigaction action = { .sa_handler = stopped };
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL) ||
        sigaction(SIGHUP, &action, NULL)) fail();
    int booted = 0;
    struct protocol state = { .lease = startup, .hard = startup,
        .work_end = UINT64_MAX, .grant_end = UINT64_MAX };
    while (1) {
#ifdef VARDR_PERSISTENT
        if (state.eof_end && now_ns() >= state.eof_end) fail();
#endif
        if (stopping || now_ns() >= state.lease || now_ns() >= state.hard || now_ns() >= state.grant_end) fail();
        int status;
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) {
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0 && (!state.armed || state.done)) _exit(0);
            fail();
        }
        if (waited < 0 && errno != EINTR) fail();
        struct pollfd poller = { .fd = pair[0], .events = POLLIN };
        int n = poll(&poller, 1, 20);
        if (n < 0) { if (errno == EINTR) continue; fail(); }
        if (!n) continue;
        if (!(poller.revents & (POLLIN | POLLHUP))) fail();
        struct packet p;
        int terminal_eof = (poller.revents & POLLHUP) && (!state.armed || state.done);
        if (!receive(pair[0], child, RUNNER, terminal_eof, &p)) {
            /* POLLIN may accompany EOF before the exact child is waitable.
             * Only waitpid above can establish success; deadlines stay armed. */
#ifdef VARDR_PERSISTENT
            eof_wait(&state, now_ns());
#endif
            struct timespec pause = { .tv_nsec = 20000000 };
            nanosleep(&pause, NULL); continue;
        }
#ifdef VARDR_PERSISTENT
        if (state.eof_end) fail();
#endif
        if (now_ns() >= state.lease || now_ns() >= state.hard) fail();
        if (!booted) {
            unsigned char zero[32] = {0};
            if (p.type != BOOT || p.sequence || p.lease || p.hard || memcmp(p.binding, zero, 32) ||
                getsid(child) == getsid(0) || getsid(child) != child) fail();
            booted = 1;
            verify_zero(); publish(nonce);
            struct packet ready = { .magic = MAGIC, .type = READY };
            memcpy(ready.binding, nonce, 32); send_packet(pair[0], &ready);
            continue;
        }
        accept_packet(&state, &p, nonce, now_ns());
        p.type = ACK; send_packet(pair[0], &p);
    }
}
