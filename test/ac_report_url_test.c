/*
 * ac_report_url_test.c -- regression test for #67: AC_REPORT_URL must
 * accept a "unix:///path/to/socket" destination (AF_UNIX SOCK_STREAM)
 * as an alternative to the existing "host:port" plain-TCP form, without
 * changing how the existing TCP form is parsed.
 *
 * Exercises ac_report_parse_url() directly -- pure string parsing, no
 * socket needed -- so this can run anywhere `make ci` does. The actual
 * AF_UNIX connect()/send()/recv() path this feeds into is exercised
 * against a real server/ac_server.py instance in server/test_server.sh's
 * --unix-socket block instead, the same split ac_report_status_test.c
 * already uses for the HTTP status-line parser vs. the real wire format.
 *
 * Pulls anticheat_daemon.c in as-is (renaming its main() out of the way)
 * to test the real ac_report_parse_url(), not a duplicated copy.
 *
 * Build: make ac-report-url-test
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
    struct ac_report_dest dest;

    /* existing host:port form must keep working exactly as before */
    CHECK(ac_report_parse_url("example.com:8787", &dest) == 0 &&
              !dest.is_unix &&
              strcmp(dest.host, "example.com") == 0 &&
              strcmp(dest.port, "8787") == 0,
          "host:port parses to a TCP destination");

    CHECK(ac_report_parse_url("127.0.0.1:8787", &dest) == 0 &&
              !dest.is_unix &&
              strcmp(dest.host, "127.0.0.1") == 0 &&
              strcmp(dest.port, "8787") == 0,
          "literal IPv4:port parses to a TCP destination");

    /* Bracketed IPv6 literals (issue #81): the only unambiguous way to
     * express host:port for a literal containing colons. */
    CHECK(ac_report_parse_url("[::1]:8787", &dest) == 0 &&
              !dest.is_unix &&
              strcmp(dest.host, "::1") == 0 &&
              strcmp(dest.port, "8787") == 0,
          "bracketed [ipv6]:port parses to a TCP destination");

    CHECK(ac_report_parse_url("[2001:db8::1]:9000", &dest) == 0 &&
              !dest.is_unix &&
              strcmp(dest.host, "2001:db8::1") == 0 &&
              strcmp(dest.port, "9000") == 0,
          "bracketed long-form IPv6 parses to a TCP destination");

    /* A bare IPv6 literal without brackets is ambiguous with the
     * host:port split (strrchr), so it must be rejected with a hint
     * toward the bracketed form -- including the bare "::1" with no
     * port, which previously mis-split into host ":" port "1". */
    CHECK(ac_report_parse_url("::1:8787", &dest) == -1,
          "bare IPv6 host:port without brackets is rejected");
    CHECK(ac_report_parse_url("::1", &dest) == -1,
          "bare IPv6 without port is rejected");

    CHECK(ac_report_parse_url("[::1]", &dest) == -1,
          "bracketed IPv6 without :port is rejected");
    CHECK(ac_report_parse_url("[::1]:", &dest) == -1,
          "bracketed IPv6 with an empty port is rejected");
    CHECK(ac_report_parse_url("[]:8787", &dest) == -1,
          "bracketed IPv6 with an empty host is rejected");
    CHECK(ac_report_parse_url("[::1:8787", &dest) == -1,
          "IPv6 missing its closing bracket is rejected");
    CHECK(ac_report_parse_url("foo[bar]:80", &dest) == -1,
          "misplaced brackets outside [ipv6]:port are rejected");

    /* Overlong URLs (issue #81): the host:port branch must reject, not
     * truncate, mirroring the unix:// branch directly above it. */
    {
        char longhost[300];
        char longurl[sizeof(longhost) + 8];
        size_t i;

        for (i = 0; i + 1 < sizeof(longhost); i++)
            longhost[i] = 'a';
        longhost[sizeof(longhost) - 1] = '\0';
        snprintf(longurl, sizeof(longurl), "%s:8787", longhost);
        CHECK(ac_report_parse_url(longurl, &dest) == -1,
              "a host:port URL longer than the host buffer is rejected, "
              "not silently truncated");
    }
    {
        char longport[64];

        memset(longport, '1', sizeof(longport) - 1);
        longport[sizeof(longport) - 1] = '\0';
        {
            char url[sizeof(longport) + 16];

            snprintf(url, sizeof(url), "example.com:%s", longport);
            CHECK(ac_report_parse_url(url, &dest) == -1,
                  "a host:port URL with an overlong port is rejected");
        }
    }

    CHECK(ac_report_parse_url("example.com:", &dest) == -1,
          "a URL with an empty port is rejected");
    CHECK(ac_report_parse_url(":8787", &dest) == -1,
          "a URL with an empty host is rejected");

    /* HTTP Host: header formatting: bare hostnames/IPv4 pass through,
     * IPv6 literals get their brackets back (RFC 9110 authority syntax),
     * since dest.host stores the bare literal for getaddrinfo(). */
    {
        char hdr[sizeof(dest.host) + 2];

        CHECK(ac_report_parse_url("example.com:8787", &dest) == 0,
              "host header fixture parses");
        ac_report_host_header(&dest, hdr, sizeof(hdr));
        CHECK(strcmp(hdr, "example.com") == 0,
              "hostname passes through the Host header unchanged");

        CHECK(ac_report_parse_url("127.0.0.1:8787", &dest) == 0,
              "IPv4 fixture parses");
        ac_report_host_header(&dest, hdr, sizeof(hdr));
        CHECK(strcmp(hdr, "127.0.0.1") == 0,
              "IPv4 literal passes through the Host header unchanged");

        CHECK(ac_report_parse_url("[::1]:8787", &dest) == 0,
              "IPv6 fixture parses");
        ac_report_host_header(&dest, hdr, sizeof(hdr));
        CHECK(strcmp(hdr, "[::1]") == 0,
              "IPv6 literal regains brackets in the Host header");
    }

    CHECK(ac_report_parse_url("no-colon-here", &dest) == -1,
          "a URL with no colon and no unix:// prefix is rejected");

    /* the new unix:// form */
    CHECK(ac_report_parse_url("unix:///run/anticheat/ac_server.sock",
                               &dest) == 0 &&
              dest.is_unix &&
              strcmp(dest.sock_path, "/run/anticheat/ac_server.sock") == 0,
          "unix:///path parses to a unix-socket destination");

    CHECK(ac_report_parse_url("unix:///run/anticheat/ac_server.sock",
                               &dest) == 0 &&
              strcmp(dest.host, "localhost") == 0,
          "unix-socket destination gets a fixed \"localhost\" Host: "
          "header placeholder");

    /* a relative-looking path is still just whatever follows the
     * prefix -- ac_report_parse_url() doesn't require a leading slash,
     * matching how the daemon has no other opinion on filesystem
     * layout (e.g. AC_BASELINE_DIR) */
    CHECK(ac_report_parse_url("unix://relative.sock", &dest) == 0 &&
              dest.is_unix &&
              strcmp(dest.sock_path, "relative.sock") == 0,
          "unix:// with a relative-looking path is still accepted");

    CHECK(ac_report_parse_url("unix://", &dest) == -1,
          "unix:// with an empty path is rejected");

    {
        /* sizeof(dest.sock_path) mirrors sizeof(sun_path) -- build a
         * path exactly at, and one past, that bound. */
        char toolong[600];
        size_t cap = sizeof(dest.sock_path);
        char url[7 + sizeof(toolong)];
        size_t i;

        for (i = 0; i + 1 < sizeof(toolong); i++)
            toolong[i] = 'a';
        toolong[cap] = '\0';   /* exactly `cap` bytes, i.e. one too long
                                   for a NUL-terminated sun_path */
        snprintf(url, sizeof(url), "unix://%s", toolong);
        CHECK(ac_report_parse_url(url, &dest) == -1,
              "a unix socket path at sizeof(sun_path) (no room for the "
              "NUL) is rejected, not silently truncated");

        toolong[cap - 1] = '\0';   /* exactly cap - 1 bytes: the longest
                                       path that still fits */
        snprintf(url, sizeof(url), "unix://%s", toolong);
        CHECK(ac_report_parse_url(url, &dest) == 0 && dest.is_unix &&
                  strlen(dest.sock_path) == cap - 1,
              "a unix socket path at exactly the longest length that "
              "fits is accepted");
    }

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    fprintf(stderr, "all checks passed\n");
    return 0;
}
