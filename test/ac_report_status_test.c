/*
 * ac_report_status_test.c -- regression test for #57: ac_report() must
 * decide HTTP delivery success/failure by parsing the response status
 * line, not by scanning the whole raw response for " 200"/" 201"
 * substrings (which a header like "Content-Length: 200" on an actual
 * error response could satisfy).
 *
 * Also covers a coderabbit finding on the #57 fix itself: the strict
 * status-line parser must reject a malformed line like "HTTP/1.1 +200 OK"
 * (a leading sign on the status code, which plain sscanf("%d") would
 * still happily parse as a real 200) rather than reporting it as success.
 *
 * Pulls anticheat_daemon.c in as-is (renaming its main() out of the way)
 * to test the real ac_http_status_code(), not a duplicated copy.
 *
 * Build: make ac-report-status-test
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

int main(void)
{
    /* well-formed lines */
    CHECK(ac_http_status_code("HTTP/1.1 200 OK\r\n") == 200,
          "200 OK parses to 200");
    CHECK(ac_http_status_code("HTTP/1.1 201 Created\r\n") == 201,
          "201 Created parses to 201");
    CHECK(ac_http_status_code("HTTP/1.1 404 Not Found\r\n") == 404,
          "404 Not Found parses to 404");
    CHECK(ac_http_status_code("HTTP/1.0 500 Internal Server Error\r\n") == 500,
          "HTTP/1.0 500 parses to 500");

    /* the original #57 bug: a substring match on the raw response would
     * have found " 200" inside this header on a real 404 response */
    CHECK(ac_http_status_code(
              "HTTP/1.1 404 Not Found\r\nContent-Length: 200\r\n\r\n") == 404,
          "404 with a 'Content-Length: 200' header still parses to 404, "
          "not 200");

    /* the coderabbit finding on the #57 fix: a leading sign must not be
     * accepted as part of a valid 3-digit status code */
    CHECK(ac_http_status_code("HTTP/1.1 +200 OK\r\n") == -1,
          "a leading '+' on the status code is rejected, not parsed as 200");
    CHECK(ac_http_status_code("HTTP/1.1 -50 OK\r\n") == -1,
          "a leading '-' on the status code is rejected");

    /* other malformed lines must fail closed (-1), not be silently
     * misparsed into some in-range code */
    CHECK(ac_http_status_code("HTTP/1.1 2000 OK\r\n") == -1,
          "a four-digit status code is rejected");
    CHECK(ac_http_status_code("HTTP/2 200 OK\r\n") == -1,
          "a status line missing the minor version is rejected");
    CHECK(ac_http_status_code("garbage 200 not a status line\r\n") == -1,
          "a response not starting with 'HTTP/' is rejected");
    CHECK(ac_http_status_code("") == -1, "an empty response is rejected");

    /* a second coderabbit finding on the #57 fix: a non-space byte glued
     * directly onto the three status-code digits (no delimiter) must not
     * be silently accepted as if that byte weren't there */
    CHECK(ac_http_status_code("HTTP/1.1 200X OK\r\n") == -1,
          "a non-space suffix glued onto the status code is rejected");
    CHECK(ac_http_status_code("HTTP/1.1 200") == 200,
          "a status code with no reason phrase or trailing CRLF "
          "(end-of-buffer right after the code) is still accepted");
    CHECK(ac_http_status_code("HTTP/1.1 200\r\n") == 200,
          "a status code immediately followed by CRLF (empty reason "
          "phrase) is still accepted");

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    fprintf(stderr, "all checks passed\n");
    return 0;
}
