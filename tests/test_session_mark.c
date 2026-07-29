/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (C) 2025 Avinash H. Duduskar
 *
 * Unit tests for session_mark_alloc.
 *
 * Two properties carry the revocation design and both have a measured
 * counterpart in `make test-packet-flow`:
 *
 *   - ids never repeat. I4 shows that handing a new session an id a stale
 *     conntrack entry still carries resurrects the flows the previous
 *     holder's close revoked.
 *   - 0 is never issued. The gate reads an empty session slice as "not
 *     admitted by any session" and accepts unconditionally, which is what
 *     carries the SSH connection (I3).
 *
 * The counter lives at a fixed path in /run, so these tests run inside a
 * private mount namespace with a tmpfs over /run/authnft. tests/session_mark_test.sh
 * sets that up; running this binary directly would mutate the host's counter.
 */

#include "authnft.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define COUNTER "/run/authnft/session-mark-counter"

static int failures;

#define FAIL(fmt, ...) do { \
    fprintf(stderr, "[FAIL] %s: " fmt "\n", __func__, ##__VA_ARGS__); \
    failures++; \
} while (0)

static void reset_counter(void) { unlink(COUNTER); }

static void write_counter(unsigned long v) {
    FILE *f = fopen(COUNTER, "w");
    if (!f) { perror("fopen"); exit(2); }
    fprintf(f, "%lu\n", v);
    fclose(f);
}

static void test_starts_at_one_never_zero(void)
{
    reset_counter();
    uint32_t first = session_mark_alloc(NULL);
    if (first != 1)
        FAIL("first id was %u, expected 1", first);
    if (first == 0)
        FAIL("issued the reserved id 0");
}

static void test_monotonic_no_repeats(void)
{
    reset_counter();
    uint32_t seen[512];
    for (int i = 0; i < 512; i++) {
        seen[i] = session_mark_alloc(NULL);
        if (seen[i] == 0) { FAIL("allocation %d returned 0", i); return; }
        if (i > 0 && seen[i] <= seen[i - 1])
            FAIL("id %u followed %u: not monotonic", seen[i], seen[i - 1]);
    }
    /* Monotonic already implies distinct, but assert it directly: a
     * regression that returned a constant would satisfy neither, and this
     * says which property broke. */
    for (int i = 0; i < 512; i++)
        for (int j = i + 1; j < 512; j++)
            if (seen[i] == seen[j]) {
                FAIL("id %u issued twice (positions %d and %d)", seen[i], i, j);
                return;
            }
}

static void test_fits_the_slice(void)
{
    reset_counter();
    uint32_t id = session_mark_alloc(NULL);
    if (id & AUTHNFT_MARK_ADMIN)
        FAIL("id %#x has bits outside the session slice", id);
    if ((id & AUTHNFT_MARK_MASK) != id)
        FAIL("id %#x does not survive masking", id);
}

static void test_refuses_at_exhaustion(void)
{
    /* Wrapping would hand a live session an id a stale conntrack entry may
     * still carry. Refusing denies a login; wrapping silently un-revokes
     * someone else's flows. */
    reset_counter();
    write_counter(AUTHNFT_MARK_MAX - 1);
    uint32_t last = session_mark_alloc(NULL);
    if (last != AUTHNFT_MARK_MAX)
        FAIL("expected the final id %u, got %u", AUTHNFT_MARK_MAX, last);

    uint32_t past = session_mark_alloc(NULL);
    if (past != 0)
        FAIL("issued %u past exhaustion instead of refusing", past);

    /* And it stays refused rather than wrapping to 1 on the next call. */
    uint32_t again = session_mark_alloc(NULL);
    if (again != 0)
        FAIL("issued %u on a second call past exhaustion", again);
}

static void test_garbage_counter_does_not_repeat(void)
{
    /* A truncated or corrupt counter must not silently restart at 1 while
     * conntrack still holds entries from the ids already issued. strtoul
     * yields 0 for garbage, so this pins that the file is not trusted into
     * reissuing low ids after a high water mark. */
    reset_counter();
    write_counter(5000);
    uint32_t before = session_mark_alloc(NULL);
    FILE *f = fopen(COUNTER, "w");
    if (f) { fputs("not-a-number\n", f); fclose(f); }
    uint32_t after = session_mark_alloc(NULL);
    if (after != 0 && after <= before)
        FAIL("after a corrupt counter, reissued %u which is <= %u", after, before);
}

static void test_concurrent_allocations_are_unique(void)
{
    /* Two logins racing must not read the same value and both take it.
     * Without flock they do, and that is the id reuse I4 measures. */
    enum { KIDS = 8, PER_KID = 64 };
    reset_counter();

    int pipes[KIDS][2];
    for (int k = 0; k < KIDS; k++) {
        if (pipe(pipes[k]) != 0) { perror("pipe"); exit(2); }
        pid_t pid = fork();
        if (pid < 0) { perror("fork"); exit(2); }
        if (pid == 0) {
            close(pipes[k][0]);
            for (int i = 0; i < PER_KID; i++) {
                uint32_t id = session_mark_alloc(NULL);
                if (write(pipes[k][1], &id, sizeof(id)) != sizeof(id)) _exit(3);
            }
            close(pipes[k][1]);
            _exit(0);
        }
        close(pipes[k][1]);
    }

    static char taken[AUTHNFT_MARK_MAX > 65536 ? 65536 : 16];
    memset(taken, 0, sizeof(taken));
    int total = 0;
    for (int k = 0; k < KIDS; k++) {
        uint32_t id;
        while (read(pipes[k][0], &id, sizeof(id)) == sizeof(id)) {
            total++;
            if (id == 0) { FAIL("child %d got 0", k); continue; }
            if (id < sizeof(taken)) {
                if (taken[id]) FAIL("id %u issued to two callers", id);
                taken[id] = 1;
            }
        }
        close(pipes[k][0]);
    }
    for (int k = 0; k < KIDS; k++) wait(NULL);

    if (total != KIDS * PER_KID)
        FAIL("expected %d ids, collected %d", KIDS * PER_KID, total);
}

int main(void)
{
    test_starts_at_one_never_zero();
    test_monotonic_no_repeats();
    test_fits_the_slice();
    test_refuses_at_exhaustion();
    test_garbage_counter_does_not_repeat();
    test_concurrent_allocations_are_unique();

    reset_counter();
    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("session_mark: all tests passed\n");
    return 0;
}
