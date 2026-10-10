/*
 * SPDX-License-Identifier: MIT
 *
 * test/ptracer_nominate_test.c -- live test helper for the
 * prctl(PR_SET_PTRACER) crash-reporter exemption (issue #116).
 *
 * Prints its own pid as PID, then blocks on a line from stdin so the
 * driver (test.sh) can protect it first. Once unblocked it plays the
 * Breakpad pattern: fork a helper child, nominate (or not) that child as
 * ptracer, and have the child PTRACE_ATTACH to the parent, PEEKDATA a
 * known word, process_vm_readv the same word, then detach. Each case
 * prints one line:
 *
 *   RESULT <case> allowed   child attached and read memory both ways
 *   RESULT <case> denied    child's attach failed, or it was SIGKILLed
 *                           by the module's kill policy
 *   RESULT <case> partial   attach worked but a memory read didn't
 *
 * Cases, in order: nominated (expect allowed), none (never nominated,
 * expect denied), any (PR_SET_PTRACER_ANY, expect denied), cleared
 * (nominated then cleared with 0, expect denied). Ends with DONE.
 *
 * If Yama's ptrace_scope is 3 (no attach at all, even for root) the
 * nominated case can't pass regardless of this module, so it prints
 * SKIP and exits instead.
 *
 * Needs root and the module loaded -- see test.sh.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PR_SET_PTRACER
# define PR_SET_PTRACER 0x59616d61
#endif
#ifndef PR_SET_PTRACER_ANY
# define PR_SET_PTRACER_ANY ((unsigned long)-1)
#endif

/* Same address in parent and forked child, so the child can name it in
 * the parent's address space directly. */
static volatile long ac_marker = 0x5ac0ffee;

enum nominate { NOM_CHILD, NOM_NONE, NOM_ANY, NOM_CLEARED };

static int yama_scope(void)
{
    FILE *f = fopen("/proc/sys/kernel/yama/ptrace_scope", "r");
    int v = 0;

    if (!f)
        return 0;
    if (fscanf(f, "%d", &v) != 1)
        v = 0;
    fclose(f);
    return v;
}

/* Child side: 0 = attached and read both ways, 1 = attach denied,
 * 2 = attached but a memory read failed or returned the wrong word. */
static int child_probe(pid_t parent)
{
    struct iovec local, remote;
    long word = 0;
    int st, rc = 0;

    if (ptrace(PTRACE_ATTACH, parent, NULL, NULL) != 0)
        return 1;
    while (waitpid(parent, &st, __WALL) < 0)
        if (errno != EINTR)
            break;

    errno = 0;
    word = ptrace(PTRACE_PEEKDATA, parent, (void *)&ac_marker, NULL);
    if (errno || word != ac_marker)
        rc = 2;

    word = 0;
    local.iov_base = &word;
    local.iov_len = sizeof(word);
    remote.iov_base = (void *)&ac_marker;
    remote.iov_len = sizeof(word);
    if (process_vm_readv(parent, &local, 1, &remote, 1, 0) != sizeof(word) ||
        word != ac_marker)
        rc = 2;

    ptrace(PTRACE_DETACH, parent, NULL, NULL);
    return rc;
}

static const char *run_case(enum nominate how)
{
    int go[2];
    pid_t child;
    int st;
    char c = 0;

    if (pipe(go) != 0)
        return "error";
    child = fork();
    if (child < 0)
        return "error";
    if (child == 0) {
        close(go[1]);
        /* wait until the parent has (or hasn't) nominated us */
        if (read(go[0], &c, 1) != 1)
            _exit(3);
        _exit(child_probe(getppid()));
    }
    close(go[0]);

    /* The real prctl fails with EINVAL when Yama isn't built in; the
     * module records the nomination either way (see ac_prctl_pre()). */
    switch (how) {
    case NOM_CHILD:
        prctl(PR_SET_PTRACER, (unsigned long)child, 0, 0, 0);
        break;
    case NOM_NONE:
        break;
    case NOM_ANY:
        prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
        break;
    case NOM_CLEARED:
        prctl(PR_SET_PTRACER, (unsigned long)child, 0, 0, 0);
        prctl(PR_SET_PTRACER, 0UL, 0, 0, 0);
        break;
    }
    if (write(go[1], "g", 1) != 1)
        c = 0;
    close(go[1]);

    while (waitpid(child, &st, 0) < 0)
        if (errno != EINTR)
            return "error";

    /* reset for the next case */
    prctl(PR_SET_PTRACER, 0UL, 0, 0, 0);

    if (WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL)
        return "denied";
    if (!WIFEXITED(st))
        return "error";
    switch (WEXITSTATUS(st)) {
    case 0: return "allowed";
    case 1: return "denied";
    case 2: return "partial";
    default: return "error";
    }
}

int main(void)
{
    static const struct { const char *name; enum nominate how; } cases[] = {
        { "nominated", NOM_CHILD },
        { "none", NOM_NONE },
        { "any", NOM_ANY },
        { "cleared", NOM_CLEARED },
    };
    char line[16];
    size_t i;

    printf("PID %d\n", getpid());
    fflush(stdout);
    if (!fgets(line, sizeof(line), stdin))
        return 1;

    if (yama_scope() >= 3) {
        printf("SKIP yama ptrace_scope=3 forbids all attaches\n");
        return 0;
    }
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        printf("RESULT %s %s\n", cases[i].name, run_case(cases[i].how));
        fflush(stdout);
    }
    printf("DONE\n");
    fflush(stdout);
    return 0;
}
