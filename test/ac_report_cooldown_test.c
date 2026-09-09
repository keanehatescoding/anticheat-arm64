/*
 * ac_report_cooldown_test.c -- regression test for #9: a flaky/unreachable
 * report endpoint must not stall the monitor loop multiplicatively.
 *
 * Exercises the two bounds ac_report() relies on, both pure enough to run
 * anywhere `make ci` does (no sockets, no sleeping through a real
 * cooldown):
 *   - ac_report_remaining_ms(): the shared absolute connect budget behind
 *     the per-address attempt timeout,
 *   - ac_report_backoff_active(): the consecutive-failure circuit breaker
 *     predicate, plus the note_failure()/note_success() counter wiring.
 *
 * Pulls anticheat_daemon.c in as-is (renaming its main() out of the way)
 * to test the real helpers, not duplicated copies.
 *
 * Build: make ac-report-cooldown-test
 */
#define main ac_daemon_unused_main
#include "../src/anticheat_daemon.c"
#undef main

static int failures;

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s\n", msg); \
        failures++; \
    } else { \
        fprintf(stderr, "PASS: %s\n", msg); \
    } \
} while (0)

static struct timespec mkts(time_t sec, long nsec)
{
    struct timespec ts;

    ts.tv_sec = sec;
    ts.tv_nsec = nsec;
    return ts;
}

int main(void)
{
    /* remaining-ms arithmetic, including the sub-second borrow */
    {
        struct timespec d = mkts(10, 0);
        struct timespec n = mkts(7, 500000000L);

        CHECK(ac_report_remaining_ms(&d, &n) == 2500,
              "2.5s of budget left measures as 2500ms");
    }
    {
        struct timespec d = mkts(5, 0);
        struct timespec n = mkts(4, 999000000L);

        CHECK(ac_report_remaining_ms(&d, &n) == 1,
              "1ms of budget left measures as 1ms, not 1000ms");
    }
    {
        struct timespec d = mkts(5, 0);
        struct timespec n = mkts(5, 0);

        CHECK(ac_report_remaining_ms(&d, &n) == 0,
              "an exactly-met deadline measures as 0ms");
    }
    {
        struct timespec d = mkts(5, 0);
        struct timespec n = mkts(9, 0);

        CHECK(ac_report_remaining_ms(&d, &n) < 0,
              "an exceeded deadline measures negative");
    }

    /* breaker predicate: untripped below the threshold, whatever the clock */
    {
        struct timespec now = mkts(100, 0);
        struct timespec until = mkts(160, 0);

        CHECK(!ac_report_backoff_active(0, &now, &until),
              "zero failures never backs off");
        CHECK(!ac_report_backoff_active(AC_REPORT_FAIL_THRESHOLD - 1,
                                        &now, &until),
              "threshold-1 failures never backs off");
    }

    /* breaker predicate: tripped only while the cooldown still has time */
    {
        struct timespec until = mkts(160, 0);
        struct timespec before = mkts(159, 999000000L);
        struct timespec at = mkts(160, 0);
        struct timespec after = mkts(161, 0);

        CHECK(ac_report_backoff_active(AC_REPORT_FAIL_THRESHOLD,
                                       &before, &until),
              "threshold failures back off inside the cooldown");
        CHECK(ac_report_backoff_active(AC_REPORT_FAIL_THRESHOLD + 5,
                                       &before, &until),
              "further failures keep the backoff active");
        CHECK(!ac_report_backoff_active(AC_REPORT_FAIL_THRESHOLD,
                                        &at, &until),
              "an exactly-elapsed cooldown no longer backs off");
        CHECK(!ac_report_backoff_active(AC_REPORT_FAIL_THRESHOLD,
                                        &after, &until),
              "an elapsed cooldown no longer backs off");
    }

    /* counter wiring: failure increments, success resets */
    {
        ac_report_consec_fail = 0;
        ac_report_note_failure();
        CHECK(ac_report_consec_fail == 1,
              "one failure increments the consecutive count");
        ac_report_note_success();
        CHECK(ac_report_consec_fail == 0,
              "a success resets the consecutive count");
        CHECK(ac_report_cooldown_until.tv_sec == 0,
              "a success clears the cooldown deadline");
    }

    /* counter wiring: the threshold-th failure arms a future deadline */
    {
        struct timespec now;

        ac_report_consec_fail = AC_REPORT_FAIL_THRESHOLD - 1;
        ac_report_note_failure();
        CHECK(ac_report_consec_fail == AC_REPORT_FAIL_THRESHOLD,
              "the threshold-th failure lands exactly on the threshold");
        clock_gettime(CLOCK_MONOTONIC, &now);
        CHECK(ac_report_backoff_active(ac_report_consec_fail, &now,
                                       &ac_report_cooldown_until),
              "tripping the threshold activates the backoff right away");
        ac_report_note_success();   /* leave no test pollution behind */
    }

    /* counter wiring: a failure after an expired cooldown re-arms a fresh
     * one instead of leaving later reports on the synchronous path */
    {
        struct timespec now;

        ac_report_consec_fail = AC_REPORT_FAIL_THRESHOLD;
        clock_gettime(CLOCK_MONOTONIC, &now);
        ac_report_cooldown_until.tv_sec = now.tv_sec - 1;   /* expired */
        ac_report_cooldown_until.tv_nsec = now.tv_nsec;
        CHECK(!ac_report_backoff_active(ac_report_consec_fail, &now,
                                        &ac_report_cooldown_until),
              "an expired cooldown admits one more delivery attempt");
        ac_report_note_failure();   /* that attempt fails too */
        clock_gettime(CLOCK_MONOTONIC, &now);
        CHECK(ac_report_backoff_active(ac_report_consec_fail, &now,
                                       &ac_report_cooldown_until),
              "a post-expiry failure re-arms the backoff right away");
        ac_report_note_success();   /* leave no test pollution behind */
    }

    /* the constants must actually bound the stall they claim to bound:
     * one loneliest report can burn resolve + connect + send + read
     * timeouts back to back, so the cooldown has to outlast all four. */
    CHECK(AC_REPORT_FAIL_THRESHOLD >= 1,
          "the failure threshold is positive");
    CHECK(AC_REPORT_COOLDOWN_SEC > 4 * AC_REPORT_TIMEOUT_SEC,
          "the cooldown outlasts one worst-case report's timeouts");
    CHECK(AC_REPORT_CONNECT_BUDGET_MS == AC_REPORT_TIMEOUT_SEC * 1000,
          "the connect budget equals one report timeout, shared");

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    fprintf(stderr, "all checks passed\n");
    return 0;
}
