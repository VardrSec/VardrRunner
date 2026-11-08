/* Bounded protocol state tests; no PID1 bootstrap, credentials or tools run. */
#define main worker_owner_entrypoint
#include "../worker_owner.c"
#undef main

static void check(int condition) { if (!condition) _exit(1); }
static const unsigned char nonce[32] = {42};

static struct protocol started(void) {
    struct protocol state = { .lease = 120 * NS, .hard = 120 * NS,
        .work_end = UINT64_MAX, .grant_end = UINT64_MAX };
    struct packet p = { .magic = MAGIC, .type = HELLO,
        .lease = 900 * NS, .hard = (900 + 150) * NS };
    memcpy(p.binding, nonce, 32);
    accept_packet(&state, &p, nonce, 0);
    check(state.hello && state.lease == 60 * NS && state.hard == 60 * NS);
    return state;
}

static struct packet lease(uint64_t sequence) {
    struct packet p = { .magic = MAGIC, .type = LEASE, .sequence = sequence,
        .lease = 5 * NS, .hard = 30 * NS };
    p.binding[0] = (unsigned char)sequence;
    return p;
}

static void healthy_sequences(void) {
    struct protocol state = started();
    for (uint64_t sequence = 1; sequence <= MAX_ATTEMPTS; sequence++) {
        struct packet p = lease(sequence);
        accept_packet(&state, &p, nonce, 0);
        check(state.armed && !state.done && state.sequence == sequence);
        p.type = DONE; p.lease = p.hard = 0;
        accept_packet(&state, &p, nonce, 0);
        check(!state.armed && state.done && state.lease == 60 * NS);
        check(state.work_end == 900 * NS && state.grant_end == 1050 * NS);
    }
}

static void refused(int change) {
    pid_t child = fork(); check(child >= 0);
    if (!child) {
        struct protocol state = started();
        struct packet p = lease(1);
        if (change == 0) p.sequence = 2; /* skipped first epoch */
        else {
            accept_packet(&state, &p, nonce, 0);
            if (change == 1) p.hard++; /* no active hard-ceiling widening */
            else {
                p.type = DONE; p.lease = p.hard = 0;
                accept_packet(&state, &p, nonce, 0);
                if (change == 2) p.type = LEASE, p.lease = 5 * NS, p.hard = 30 * NS;
                else if (change == 3) { /* duplicate DONE stays invalid */ }
                else if (change == 4) {
                    state.sequence = MAX_ATTEMPTS; p = lease(MAX_ATTEMPTS + 1);
                } else if (change == 5) {
                    p = lease(2); accept_packet(&state, &p, nonce, 60 * NS);
                }
            }
        }
        accept_packet(&state, &p, nonce, 0);
        _exit(1);
    }
    int status; check(waitpid(child, &status, 0) == child);
    check(WIFEXITED(status) && WEXITSTATUS(status) == 125);
}

int main(void) {
    healthy_sequences();
    for (int i = 0; i < 6; i++) refused(i);
    struct protocol state = started();
    state.work_end = 40 * NS;
    struct packet p = lease(1);
    accept_packet(&state, &p, nonce, 0);
    p.type = DONE; p.lease = p.hard = 0;
    accept_packet(&state, &p, nonce, 0);
    check(state.lease == 40 * NS && state.hard == 40 * NS);
    return 0;
}
