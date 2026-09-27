/*
 * daemon_reporting_test.c -- regression tests for #108, #109, #110
 * (daemon event/report reliability):
 *
 *  #108: check_modules_periodic() must report a persistent hidden
 *        module once (rising edge), not at LOG_CRIT on every 10s tick.
 *        Proves hidden_modules_rising_edge() reports the transition,
 *        clears on confirmed-clean, and leaves its state untouched on
 *        an inconclusive walk (-1, see #76).
 *  #109: the monitor loop must notice el.dropped growth between
 *        drains. Proves ring_drop_delta() reports newly-dropped events
 *        and survives a counter reset, so a ring overflow can't
 *        silently lose PTRACE/SYSCALL_HOOK events.
 *  #110: ac_report() must treat 429/503 (and any non-2xx) as failed
 *        delivery instead of resetting the circuit breaker, and must
 *        honor Retry-After as the backoff. Proves
 *        ac_report_delivered(), ac_parse_retry_after(), and the
 *        failure/backoff wiring -- including end to end, driving the
 *        real ac_report() against a loopback server that answers 429
 *        (then 200), so the old "any response bytes mean success"
 *        behavior would fail the assertions.
 *
 * Pulls anticheat_daemon.c in as-is (renaming its main() out of the way)
 * to test the real helpers, not duplicated copies.
 *
 * Build: make daemon-reporting-test
 */
#define main ac_daemon_unused_main
#include "../src/anticheat_daemon.c"
#undef main

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>

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

/* One ac_report() exchange against a loopback server answering a canned
 * HTTP response: binds 127.0.0.1:0, forks a child that accepts a single
 * connection, reads the request best-effort, sends `response`, and
 * exits; the parent points AC_REPORT_URL/AC_REPORT_KEY at the listener
 * and calls the real ac_report(). Returns 0 when the exchange itself
 * ran (assertions on the daemon's resulting state are the caller's). */
static int run_report_exchange(const char *response)
{
    int ls;
    struct sockaddr_in sin;
    socklen_t slen = sizeof(sin);
    char url[64];
    pid_t pid;
    int st;

    ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0)
        return -1;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = 0;
    if (bind(ls, (struct sockaddr *)&sin, sizeof(sin)) < 0 ||
        listen(ls, 1) < 0 ||
        getsockname(ls, (struct sockaddr *)&sin, &slen) < 0) {
        close(ls);
        return -1;
    }
    snprintf(url, sizeof(url), "127.0.0.1:%u",
             (unsigned)ntohs(sin.sin_port));

    pid = fork();
    if (pid < 0) {
        close(ls);
        return -1;
    }
    if (pid == 0) {
        int cs;
        char tmp[2048];
        size_t sent = 0, len = strlen(response);

        cs = accept(ls, NULL, NULL);
        if (cs >= 0) {
            /* Best-effort request drain: the daemon sends first and
             * reads second, so one blocking read can't deadlock. */
            (void)read(cs, tmp, sizeof(tmp));
            while (sent < len) {
                ssize_t w = send(cs, response + sent, len - sent,
                                 MSG_NOSIGNAL);

                if (w <= 0)
                    break;
                sent += (size_t)w;
            }
            close(cs);
        }
        close(ls);
        _exit(0);
    }
    close(ls);
    setenv("AC_REPORT_URL", url, 1);
    setenv("AC_REPORT_KEY", "testkey", 1);
    ac_report("ALERT", "daemon_reporting_test probe");
    unsetenv("AC_REPORT_URL");
    unsetenv("AC_REPORT_KEY");
    waitpid(pid, &st, 0);
    return (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 0 : -1;
}

int main(void)
{
    /* #108: rising edge on the hidden-module count */
    {
        long last = 0;

        CHECK(!hidden_modules_rising_edge(0, &last) && last == 0,
              "#108: clean walk with clean state reports nothing");
        CHECK(hidden_modules_rising_edge(1, &last) && last == 1,
              "#108: first hidden module reports");
        CHECK(!hidden_modules_rising_edge(1, &last) && last == 1,
              "#108: persistent hidden module does not re-report");
        CHECK(hidden_modules_rising_edge(2, &last) && last == 2,
              "#108: a growing hidden count re-reports");
        CHECK(!hidden_modules_rising_edge(1, &last) && last == 1,
              "#108: a shrinking-but-nonzero count lowers the watermark "
              "silently");
        CHECK(hidden_modules_rising_edge(2, &last) && last == 2,
              "#108: regrowth past the lowered watermark reports again");
        CHECK(!hidden_modules_rising_edge(0, &last) && last == 0,
              "#108: confirmed-clean re-arms");
        CHECK(hidden_modules_rising_edge(1, &last) && last == 1,
              "#108: a new hidden module after clean reports again");
    }

    /* #108: inconclusive walks leave the edge untouched (#76) */
    {
        long last = 3;

        CHECK(!hidden_modules_rising_edge(-1, &last) && last == 3,
              "#108: inconclusive walk reports nothing and keeps state");
        CHECK(!hidden_modules_rising_edge(3, &last) && last == 3,
              "#108: same count after inconclusive still suppressed");
        CHECK(!hidden_modules_rising_edge(-1, &last) && last == 3,
              "#108: repeated inconclusive walks stay silent");
    }

    /* #109: drop-delta gate */
    {
        unsigned int last = 0;

        CHECK(ring_drop_delta(0, &last) == 0 && last == 0,
              "#109: no drops means no delta");
        CHECK(ring_drop_delta(5, &last) == 5 && last == 5,
              "#109: fresh drops report their count");
        CHECK(ring_drop_delta(5, &last) == 0 && last == 5,
              "#109: an unchanged counter stays silent");
        CHECK(ring_drop_delta(8, &last) == 3 && last == 8,
              "#109: growth reports only the delta");
        CHECK(ring_drop_delta(2, &last) == 2 && last == 2,
              "#109: a counter reset (module reload) reports the "
              "current value, not a wrapped-around huge delta");
    }

    /* #110: delivery verdict boundary */
    CHECK(ac_report_delivered(12, 200),
          "#110: 200 with a body counts as delivered");
    CHECK(ac_report_delivered(12, 201),
          "#110: 201 counts as delivered");
    CHECK(!ac_report_delivered(12, 429),
          "#110: 429 counts as failed, not delivered");
    CHECK(!ac_report_delivered(12, 503),
          "#110: 503 counts as failed, not delivered");
    CHECK(!ac_report_delivered(12, 500),
          "#110: 500 counts as failed, not delivered");
    CHECK(!ac_report_delivered(12, 400),
          "#110: 400 counts as failed, not delivered");
    CHECK(!ac_report_delivered(12, -1),
          "#110: an unparseable status counts as failed");
    CHECK(!ac_report_delivered(0, 200),
          "#110: an empty read counts as failed even with a 2xx code");
    CHECK(!ac_report_delivered(-1, 200),
          "#110: a failed read counts as failed even with a 2xx code");

    /* #110: Retry-After parsing (delta-seconds only) */
    CHECK(ac_parse_retry_after(NULL) == -1,
          "#110: no response means no Retry-After");
    CHECK(ac_parse_retry_after("HTTP/1.1 200 OK\r\n\r\n") == -1,
          "#110: a response without the header parses to absent");
    CHECK(ac_parse_retry_after(
              "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 5\r\n\r\n")
          == 5,
          "#110: Retry-After: 5 parses to 5");
    CHECK(ac_parse_retry_after(
              "HTTP/1.1 503 Service Unavailable\r\nretry-after: 120\r\n\r\n")
          == 120,
          "#110: the header name matches case-insensitively");
    CHECK(ac_parse_retry_after(
              "HTTP/1.1 429 Too Many Requests\r\nRetry-After:   7  \r\n\r\n")
          == 7,
          "#110: surrounding whitespace is tolerated");
    CHECK(ac_parse_retry_after(
              "HTTP/1.1 429 Too Many Requests\r\nRetry-After: abc\r\n\r\n")
          == -1,
          "#110: a non-numeric Retry-After parses to absent");
    CHECK(ac_parse_retry_after(
              "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 0\r\n\r\n")
          == -1,
          "#110: Retry-After: 0 parses to absent (retry now is not a "
          "backoff)");
    CHECK(ac_parse_retry_after(
              "HTTP/1.1 503 Service Unavailable\r\n"
              "Retry-After: Fri, 01 Jan 2027 00:00:00 GMT\r\n\r\n") == -1,
          "#110: HTTP-date Retry-After falls back to absent");
    CHECK(ac_parse_retry_after(
              "HTTP/1.1 503 Service Unavailable\r\n"
              "Retry-After: 999999999\r\n\r\n")
          == AC_REPORT_RETRY_AFTER_MAX_SEC,
          "#110: a huge Retry-After clamps instead of suppressing "
          "reporting indefinitely");
    CHECK(ac_parse_retry_after(
              "HTTP/1.1 503 Service Unavailable\r\n"
              "X-Retry-After: 5\r\nRetry-After: 9\r\n\r\n") == 9,
          "#110: the real header wins over a prefixed lookalike");

    /* #110: a present hint arms the backoff even below the
     * consecutive-failure threshold; without one the threshold still
     * applies. */
    {
        struct timespec now;

        ac_report_consec_fail = 0;
        ac_report_cooldown_until = mkts(0, 0);
        ac_report_note_failure_with_retry_after(120);
        CHECK(ac_report_consec_fail == AC_REPORT_FAIL_THRESHOLD,
              "#110: a hinted failure raises the count to the threshold "
              "so the armed backoff actually suppresses");
        clock_gettime(CLOCK_MONOTONIC, &now);
        CHECK(ac_report_backoff_active(ac_report_consec_fail, &now,
                                       &ac_report_cooldown_until),
              "#110: a Retry-After hint arms the backoff immediately");
        CHECK(ac_report_remaining_ms(&ac_report_cooldown_until, &now) >
              100 * 1000L,
              "#110: the armed backoff honors the 120s hint, not the "
              "60s default");
        ac_report_note_success();
    }
    {
        struct timespec now;

        ac_report_consec_fail = 0;
        ac_report_cooldown_until = mkts(0, 0);
        ac_report_note_failure_with_retry_after(-1);
        CHECK(ac_report_consec_fail == 1,
              "#110: an unhinted failure still increments the count");
        clock_gettime(CLOCK_MONOTONIC, &now);
        CHECK(!ac_report_backoff_active(ac_report_consec_fail, &now,
                                        &ac_report_cooldown_until),
              "#110: without a hint a lone failure still needs the "
              "threshold to back off");
        ac_report_note_success();   /* leave no test pollution behind */
    }

    /* #110, end to end: a 429 must count as a failure (the old code
     * reset the breaker on any response bytes), and a 200 must still
     * count as success. */
    {
        struct timespec now;

        ac_report_consec_fail = 0;
        ac_report_cooldown_until = mkts(0, 0);
        CHECK(run_report_exchange(
                  "HTTP/1.1 429 Too Many Requests\r\n"
                  "Content-Type: application/json\r\n"
                  "Content-Length: 0\r\n"
                  "Connection: close\r\n"
                  "Retry-After: 2\r\n\r\n") == 0,
              "#110: the 429 exchange itself ran");
        CHECK(ac_report_consec_fail == AC_REPORT_FAIL_THRESHOLD,
              "#110: a 429 response counts toward the breaker "
              "(old code reset it to 0) and the hint trips it");
        clock_gettime(CLOCK_MONOTONIC, &now);
        CHECK(ac_report_backoff_active(ac_report_consec_fail, &now,
                                       &ac_report_cooldown_until),
              "#110: the 429's Retry-After arms the backoff");

        /* The armed backoff would skip the network entirely, so clear
         * it before proving the 200 path still resets the counter --
         * a 200 treated as failure would re-increment from here. */
        ac_report_note_success();
        CHECK(run_report_exchange(
                  "HTTP/1.1 200 OK\r\n"
                  "Content-Type: application/json\r\n"
                  "Content-Length: 0\r\n"
                  "Connection: close\r\n\r\n") == 0,
              "#110: the 200 exchange itself ran");
        CHECK(ac_report_consec_fail == 0,
              "#110: a 200 response still resets consecutive failures");
        CHECK(ac_report_cooldown_until.tv_sec == 0,
              "#110: a 200 response clears the cooldown deadline");
    }

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    fprintf(stderr, "all checks passed\n");
    return 0;
}
