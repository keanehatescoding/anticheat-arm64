/*
 * baseline_test.c -- regression test for #51: baseline_save_record() must
 * not clobber another (inode, offset) segment's record already saved to
 * the same path's baseline file. Reproduces the bug directly against the
 * daemon's real baseline_* functions (no kernel/mock scan needed -- they
 * are pure file I/O), by simulating a library with two executable
 * PT_LOAD segments: same inode/path, two different file offsets.
 *
 * Also covers two coderabbit findings on the #51 fix itself:
 *   - baseline_find_record() must treat a size mismatch at the same
 *     (inode, offset) as an incompatible baseline, not a content diff.
 *   - baseline_load_records() must tell a legacy pre-#51 3-field record
 *     apart from "nothing saved", so callers can point the operator at
 *     re-running --save instead of reporting it identically to "never
 *     baselined".
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
    int n, legacy;

    if (!mkdtemp(tmpdir)) {
        perror("mkdtemp");
        return 1;
    }
    setenv("AC_BASELINE_DIR", tmpdir, 1);
    ac_mkdir_baselines();

    baseline_path_for("/usr/lib/libmultiseg.so", blpath);

    /* Segment 1: inode 42, file offset 0x1000, size 0x2000 */
    CHECK(baseline_save_record(blpath, 42, 0x1000, 0x2000,
                                "1111111111111111111111111111111111111111111111111111111111111111") == 0,
          "save segment 1");

    /* Segment 2: same inode/path, different file offset -- this is the
     * multi-PT_LOAD-executable-segment case from #51. Before the fix,
     * fopen(blpath, "w") here truncated segment 1's line away. */
    CHECK(baseline_save_record(blpath, 42, 0x5000, 0x1000,
                                "2222222222222222222222222222222222222222222222222222222222222222") == 0,
          "save segment 2");

    n = baseline_load_records(blpath, recs, &legacy);
    CHECK(n == 2, "both segments' records survive in the baseline file");
    CHECK(!legacy, "no legacy-format lines flagged for a fresh file");

    CHECK(baseline_find_record(recs, n, 42, 0x1000, 0x2000, hex) &&
          strncmp(hex, "1111", 4) == 0,
          "segment 1's record is still intact after segment 2 was saved");
    CHECK(baseline_find_record(recs, n, 42, 0x5000, 0x1000, hex) &&
          strncmp(hex, "2222", 4) == 0,
          "segment 2's record is present");

    /* Same (inode, offset) as segment 1, but a different size (e.g. the
     * file at this path was rebuilt) -- must NOT match segment 1's
     * record and be hashed against a stale digest. */
    CHECK(!baseline_find_record(recs, n, 42, 0x1000, 0x9999, hex),
          "a size mismatch at a known (inode, offset) is not treated as a match");

    /* Re-saving segment 1 (e.g. after a legitimate update) replaces only
     * its own record, still without touching segment 2's. */
    CHECK(baseline_save_record(blpath, 42, 0x1000, 0x2000,
                                "3333333333333333333333333333333333333333333333333333333333333333") == 0,
          "re-save segment 1");
    n = baseline_load_records(blpath, recs, &legacy);
    CHECK(n == 2, "record count unchanged after re-saving an existing segment");
    CHECK(baseline_find_record(recs, n, 42, 0x1000, 0x2000, hex) &&
          strncmp(hex, "3333", 4) == 0,
          "segment 1's record was updated in place");
    CHECK(baseline_find_record(recs, n, 42, 0x5000, 0x1000, hex) &&
          strncmp(hex, "2222", 4) == 0,
          "segment 2's record is untouched by re-saving segment 1");

    /* A segment nobody ever saved a baseline for is correctly reported
     * as absent, not confused with an unrelated offset's record. */
    CHECK(!baseline_find_record(recs, n, 42, 0x9000, 0x1000, hex),
          "an offset with no saved record is not found");

    /* Two distinct file-backed VMAs can legitimately share a starting
     * file offset while covering different lengths (the same region
     * mapped twice at different addresses) -- coderabbit finding on the
     * prior fix: saving the second must not evict the first's record
     * just because they share (inode, offset). */
    CHECK(baseline_save_record(blpath, 99, 0x2000, 0x1000,
                                "5555555555555555555555555555555555555555555555555555555555555555") == 0,
          "save a same-(inode,offset), size-0x1000 mapping");
    CHECK(baseline_save_record(blpath, 99, 0x2000, 0x3000,
                                "6666666666666666666666666666666666666666666666666666666666666666") == 0,
          "save a same-(inode,offset), size-0x3000 mapping");
    n = baseline_load_records(blpath, recs, &legacy);
    CHECK(n == 4, "both same-(inode,offset) different-size records are kept");
    CHECK(baseline_find_record(recs, n, 99, 0x2000, 0x1000, hex) &&
          strncmp(hex, "5555", 4) == 0,
          "the size-0x1000 mapping's own record is found");
    CHECK(baseline_find_record(recs, n, 99, 0x2000, 0x3000, hex) &&
          strncmp(hex, "6666", 4) == 0,
          "the size-0x3000 mapping's own record is found, not evicted by the other");

    /* A pre-#51 baseline file (single "start size hex" line, no
     * inode/offset) is recognized as legacy rather than silently
     * yielding zero records indistinguishable from "never baselined". */
    {
        char legacy_path[PATH_MAX];
        FILE *f;

        baseline_path_for("/usr/lib/liblegacy.so", legacy_path);
        f = fopen(legacy_path, "w");
        CHECK(f != NULL, "create a synthetic legacy-format baseline file");
        if (f) {
            fprintf(f, "%llx %llx %s\n", 0x1000ULL, 0x2000ULL,
                    "4444444444444444444444444444444444444444444444444444444444444444");
            fclose(f);
        }
        n = baseline_load_records(legacy_path, recs, &legacy);
        CHECK(n == 0, "a legacy 3-field line yields no usable records");
        CHECK(legacy, "a legacy 3-field line is flagged via out_legacy");
    }

    if (failures) {
        fprintf(stderr, "%d check(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "all checks passed\n");
    return 0;
}
