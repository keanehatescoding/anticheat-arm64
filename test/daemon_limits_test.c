/*
 * daemon_limits_test.c -- regression tests for #83 and #85: the daemon
 * must not silently trust numeric limits at its edges.
 *
 * #83: pid_of_comm() silently dropped every match past its `max`, so
 * `protect --comm` partially protected and still reported success. It
 * must now count every match and return the true total, letting the
 * caller (cmd_protect()) warn loudly when the total exceeds what one
 * invocation can hold.
 *
 * #85: both GET_EVENTS drain loops iterated el.count verbatim, trusting
 * a module-supplied count against a fixed AC_MAX_EVENTS stack array.
 * ac_clamp_event_count() must bound it, including the past-INT_MAX
 * case the old `(int)el.count` cast turned into a silent no-op.
 *
 * Pulls anticheat_daemon.c in as-is (renaming its main() out of the
 * way) to test the real functions, not duplicated copies.
 *
 * Build: make daemon-limits-test
 */
#define main ac_daemon_unused_main
#include "../src/anticheat_daemon.c"
#undef main

#include <assert.h>
#include <limits.h>
#include <signal.h>
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

/* Spawn `count` children exec'ing `path` (basename `name`), all sleeping.
 * Returns 0 on success with child pids in `kids`, -1 on spawn failure
 * (already-started children are reaped before returning). */
static int spawn_sleepers(const char *path, const char *name,
                          pid_t *kids, int count)
{
    int i, started = 0;

    for (i = 0; i < count; i++) {
        pid_t pid = fork();

        if (pid < 0)
            break;
        if (pid == 0) {
            execl(path, name, "60", (char *)NULL);
            _exit(127);   /* exec failed -- never returns otherwise */
        }
        kids[started++] = pid;
    }
    if (started < count) {
        for (i = 0; i < started; i++) {
            kill(kids[i], SIGKILL);
            waitpid(kids[i], NULL, 0);
        }
        return -1;
    }
    return 0;
}

static void reap_sleepers(pid_t *kids, int count)
{
    int i;

    for (i = 0; i < count; i++) {
        kill(kids[i], SIGKILL);
        waitpid(kids[i], NULL, 0);
    }
}

/* Poll pid_of_comm() until all `want` matches are visible (exec takes a
 * moment after fork), then return the count. Gives up after ~5s. */
static int wait_for_matches(const char *name, int *pids, int max, int want)
{
    int i, n = 0;

    for (i = 0; i < 50; i++) {
        n = pid_of_comm(name, pids, max);
        if (n >= want)
            break;
        usleep(100000);
    }
    return n;
}

int main(void)
{
    /* ---- #85: ac_clamp_event_count() ---- */
    {
        int clamped = -1;

        CHECK(ac_clamp_event_count(0, &clamped) == 0 && !clamped,
              "count 0 passes through unclamped");
        CHECK(ac_clamp_event_count(1, &clamped) == 1 && !clamped,
              "small count passes through unclamped");
        CHECK(ac_clamp_event_count(AC_MAX_EVENTS, &clamped) == AC_MAX_EVENTS &&
                  !clamped,
              "exactly AC_MAX_EVENTS passes through unclamped");
        CHECK(ac_clamp_event_count(AC_MAX_EVENTS + 1, &clamped) ==
                  AC_MAX_EVENTS && clamped,
              "AC_MAX_EVENTS+1 clamps and reports it");
        /* The old `(int)el.count` loop bound turned any count past
         * INT_MAX into a negative -- silently processing nothing with
         * no diagnostic. The clamp must catch those too. */
        CHECK(ac_clamp_event_count((unsigned int)INT_MAX + 1u, &clamped) ==
                  AC_MAX_EVENTS && clamped,
              "INT_MAX+1 clamps instead of casting negative");
        CHECK(ac_clamp_event_count(UINT_MAX, &clamped) == AC_MAX_EVENTS &&
                  clamped,
              "UINT_MAX clamps instead of casting negative");
    }

    /* ---- #83: pid_of_comm() counts past `max` ---- */
    {
        char tmpdir[] = "/tmp/ac_daemon_limits_XXXXXX";
        char binpath[PATH_MAX];
        char name[64];
        pid_t kids[8];
        int pids[32];
        int small[2];
        const int NKIDS = 5;
        int n, i, ok;

        assert(NKIDS <= (int)(sizeof(kids) / sizeof(kids[0])));
        if (!mkdtemp(tmpdir)) {
            perror("mkdtemp");
            return 1;
        }
        /* Unique basename per run, so stray system processes can never
         * join the match set. Short enough for comm matching too, so
         * both pid_identifies_as() paths (exe basename and comm
         * fallback) agree on these pids. */
        snprintf(name, sizeof(name), "ac83t%d", (int)getpid());
        snprintf(binpath, sizeof(binpath), "%s/%s", tmpdir, name);
        {
            char cp[PATH_MAX * 2 + 16];

            snprintf(cp, sizeof(cp), "cp /bin/sleep '%s'", binpath);
            if (system(cp) != 0) {
                fprintf(stderr, "FAIL: cannot stage sleeper binary\n");
                return 1;
            }
            chmod(binpath, 0755);
        }
        if (spawn_sleepers(binpath, name, kids, NKIDS) != 0) {
            fprintf(stderr, "FAIL: cannot spawn sleepers\n");
            return 1;
        }

        /* Full-size buffer first: all children must be found. */
        n = wait_for_matches(name, pids, 32, NKIDS);
        CHECK(n == NKIDS, "all spawned sleepers are found with room to spare");

        /* The #83 case: max smaller than the match set. Before the fix
         * this returned 2 (the cap), hiding the other 3 from the
         * caller; it must now return the true total. */
        small[0] = small[1] = -1;
        n = pid_of_comm(name, small, 2);
        CHECK(n == NKIDS,
              "pid_of_comm returns the true match total past max");
        CHECK(small[0] > 0 && small[1] > 0 && small[0] != small[1],
              "the first max matches are still stored");

        /* Every stored pid must actually be one of ours. */
        ok = 1;
        for (i = 0; i < 2; i++) {
            int j, found = 0;

            for (j = 0; j < NKIDS; j++)
                if (small[i] == kids[j])
                    found = 1;
            if (!found)
                ok = 0;
        }
        CHECK(ok, "stored pids are exactly the spawned sleepers");

        reap_sleepers(kids, NKIDS);
        unlink(binpath);
        rmdir(tmpdir);
    }

    if (failures) {
        fprintf(stderr, "%d check(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "all checks passed\n");
    return 0;
}
