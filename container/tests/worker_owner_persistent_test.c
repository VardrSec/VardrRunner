/* Pure bounded state tests; never invokes the PID1/credential bootstrap. */
#define VARDR_PERSISTENT 1
#define main worker_owner_entrypoint
#include "../worker_owner.c"
#undef main

static void check(int condition) { if (!condition) _exit(1); }
static const unsigned char nonce[32] = {42};

static struct protocol started(uint64_t seconds, uint64_t maximum) {
    struct protocol state = { .lease = 120 * NS, .hard = 120 * NS,
        .work_end = UINT64_MAX, .grant_end = UINT64_MAX };
    struct packet p = { .magic = MAGIC, .type = HELLO,
        .lease = seconds, .hard = maximum };
    memcpy(p.binding, nonce, 32);
    accept_packet(&state, &p, nonce, 0);
    check(state.hello && !state.armed && !state.sequence);
    check(state.maximum == maximum && state.idle_seconds == seconds);
    return state;
}
static struct packet lease(uint64_t sequence, uint64_t now) {
    struct packet p = { .magic = MAGIC, .type = LEASE, .sequence = sequence,
        .lease = now + 5 * NS, .hard = now + 30 * NS };
    p.binding[0] = (unsigned char)sequence;
    return p;
}
static void healthy(uint64_t base, unsigned count) {
    struct protocol state = started(0, 0);
    state.sequence = base;
    for (unsigned step = 1; step <= count; step++) {
        uint64_t now = (uint64_t)step * 3600 * NS;
        check(state.lease == UINT64_MAX && !state.armed);
        struct packet p = lease(base + step, now);
        accept_packet(&state, &p, nonce, now);
        check(state.armed && state.hard == now + 30 * NS);
        p.type = DONE; p.lease = p.hard = 0;
        accept_packet(&state, &p, nonce, now + NS);
        check(!state.armed && state.done && state.lease == UINT64_MAX);
    }
}
static void refused(int change) {
    pid_t child = fork(); check(child >= 0);
    if (!child) {
        struct protocol state = started(change == 0 ? 1 : 0, change == 1 ? 1 : 0);
        struct packet p = lease(1, 0);
        if (change == 0) accept_packet(&state, &p, nonce, NS);
        if (change == 2) p.sequence = 2;
        if (change == 3) { state.sequence = INT64_MAX; p.sequence = (uint64_t)INT64_MAX + 1; }
        accept_packet(&state, &p, nonce, 0);
        if (change == 4) { p.hard++; accept_packet(&state, &p, nonce, 0); }
        if (change == 5) accept_packet(&state, &p, nonce, 5 * NS);
        p.type = DONE; p.lease = p.hard = 0;
        accept_packet(&state, &p, nonce, NS);
        p = lease(change == 6 ? 1 : 2, NS);
        accept_packet(&state, &p, nonce, NS);
        _exit(1);
    }
    int status; check(waitpid(child, &status, 0) == child);
    check(WIFEXITED(status) && WEXITSTATUS(status) == 125);
}
static void eof_deadline(void) {
    struct protocol state = started(0, 0);
    uint64_t lease_end = state.lease, hard_end = state.hard;
    eof_wait(&state, 100 * NS);
    check(state.eof_end == 105 * NS);
    eof_wait(&state, 104 * NS);
    check(state.eof_end == 105 * NS);
    check(state.lease == lease_end && state.hard == hard_end && !state.armed);
    state = started(1, 0);
    eof_wait(&state, NS / 2);
    check(state.lease == NS && state.hard == NS); /* Earlier policy still wins. */
}
static void eof_refused(int change) {
    pid_t child = fork(); check(child >= 0);
    if (!child) {
        struct protocol state = started(0, 0);
        if (change == 0) { eof_wait(&state, 0); eof_wait(&state, 5 * NS); }
        if (change == 1) eof_wait(&state, UINT64_MAX - 5 * NS + 1);
        if (change == 2) { state.armed = 1; eof_wait(&state, 0); }
        eof_wait(&state, 0);
        struct packet p = lease(1, NS);
        if (change == 4) { p.type = HELLO; p.sequence = p.lease = p.hard = 0; }
        accept_packet(&state, &p, nonce, NS); /* No frame revives an EOF channel. */
        _exit(1);
    }
    int status; check(waitpid(child, &status, 0) == child);
    check(WIFEXITED(status) && WEXITSTATUS(status) == 125);
}
int main(void) {
    healthy(0, 40); /* Beyond both old operational limits, without sleeping. */
    healthy(UINT64_C(9007199254740992), 2);
    healthy((uint64_t)INT64_MAX - 1, 1);
    for (int change = 0; change < 7; change++) refused(change);
    eof_deadline();
    for (int change = 0; change < 5; change++) eof_refused(change);
    return 0;
}
