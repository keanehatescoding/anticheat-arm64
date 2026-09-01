/*
 * baseline_test.c -- regression test for #51: baseline_save_record() must
 * not clobber another (inode, offset) segment's record already saved to
 * the same path's baseline file. Reproduces the bug directly against the
 * daemon's real baseline_* functions (no kernel/mock scan needed -- they
 * are pure file I/O), by simulating a library with two executable
 * PT_LOAD segments: same inode/path, two different file offsets.
 *
 * Pulls anticheat_daemon.c in as-is (renaming its main() out of the way)
 * rather than re-implementing the record format, so this test breaks if
 * the real functions regress, not just if a duplicated copy does.
 *
 * Build: make baseline-test
 */
#define main ac_daemon_unused_main
#include "../src/anticheat_daemon.c"
#undef main

#include <assert.h>

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
    char tmpdir[] = "/tmp/ac_baseline_test_XXXXXX";
    char blpath[PATH_MAX];
    struct ac_baseline_rec recs[AC_BASELINE_MAX_RECORDS];
    char hex[65];
    int n;

    if (!mkdtemp(tmpdir)) {
        perror("mkdtemp");
        return 1;
    }
    setenv("AC_BASELINE_DIR", tmpdir, 1);
    ac_mkdir_baselines();

    baseline_path_for("/usr/lib/libmultiseg.so", blpath);

    /* Segment 1: inode 42, file offset 0x1000 */
    CHECK(baseline_save_record(blpath, 42, 0x1000, 0x2000,
                                "1111111111111111111111111111111111111111111111111111111111111111") == 0,
          "save segment 1");

    /* Segment 2: same inode/path, different file offset -- this is the
     * multi-PT_LOAD-executable-segment case from #51. Before the fix,
     * fopen(blpath, "w") here truncated segment 1's line away. */
    CHECK(baseline_save_record(blpath, 42, 0x5000, 0x1000,
                                "2222222222222222222222222222222222222222222222222222222222222222") == 0,
          "save segment 2");

    n = baseline_load_records(blpath, recs);
    CHECK(n == 2, "both segments' records survive in the baseline file");

    CHECK(baseline_find_record(recs, n, 42, 0x1000, hex) &&
          strncmp(hex, "1111", 4) == 0,
          "segment 1's record is still intact after segment 2 was saved");
    CHECK(baseline_find_record(recs, n, 42, 0x5000, hex) &&
          strncmp(hex, "2222", 4) == 0,
          "segment 2's record is present");

    /* Re-saving segment 1 (e.g. after a legitimate update) replaces only
     * its own record, still without touching segment 2's. */
    CHECK(baseline_save_record(blpath, 42, 0x1000, 0x2000,
                                "3333333333333333333333333333333333333333333333333333333333333333") == 0,
          "re-save segment 1");
    n = baseline_load_records(blpath, recs);
    CHECK(n == 2, "record count unchanged after re-saving an existing segment");
    CHECK(baseline_find_record(recs, n, 42, 0x1000, hex) &&
          strncmp(hex, "3333", 4) == 0,
          "segment 1's record was updated in place");
    CHECK(baseline_find_record(recs, n, 42, 0x5000, hex) &&
          strncmp(hex, "2222", 4) == 0,
          "segment 2's record is untouched by re-saving segment 1");

    /* A segment nobody ever saved a baseline for is correctly reported
     * as absent, not confused with an unrelated offset's record. */
    CHECK(!baseline_find_record(recs, n, 42, 0x9000, hex),
          "an offset with no saved record is not found");

    if (failures) {
        fprintf(stderr, "%d check(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "all checks passed\n");
    return 0;
}
