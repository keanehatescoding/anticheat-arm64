/*
 * integrity_scan_test.c -- regression tests for #114 (daemon half):
 *
 *  - scan_kprobes_stream() must count kprobes on syscall entries that
 *    are not the module's own, and must not count the module's own, a
 *    disarmed/gone probe, or a probe somewhere unrelated.
 *  - scan_ftrace_stream() must pick the IPMODIFY and direct-call flags
 *    out of an enabled_functions line without being fooled by the same
 *    letters elsewhere on it (the trampoline text, continuation lines).
 *  - collect_unlisted_modules() must report a module that is live in
 *    /sys/module but absent from the kernel-side walk, and must not
 *    report built-in entries, modules still loading, or text-less ones.
 *
 * Pulls anticheat_daemon.c in as-is (renaming its main() out of the way)
 * to test the real helpers, not duplicated copies.
 *
 * Build: make integrity-scan-test
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

static FILE *text_stream(const char *text)
{
    FILE *f = fmemopen((void *)text, strlen(text), "r");

    if (!f) {
        perror("fmemopen");
        exit(1);
    }
    return f;
}

static void test_kprobes(void)
{
    struct ac_kprobe_scan k;
    FILE *f;

    /* Exactly what the module registers, plus probes that are none of
     * this check's business. */
    f = text_stream(
        "ffff800080123450  k  __arm64_sys_ptrace+0x0    \n"
        "ffff800080123460  k  __arm64_compat_sys_ptrace+0x0    \n"
        "ffff800080123470  r  __arm64_sys_execve+0x0    \n"
        "ffff800080123480  r  __arm64_sys_prctl+0x0    \n"
        "ffff800080123490  r  kernel_clone+0x0    \n"
        "ffff8000801234a0  k  vfs_read+0x0    [FTRACE]\n"
        "ffff8000801234b0  k  some_fn+0x10  some_mod \n");
    scan_kprobes_stream(f, &k);
    fclose(f);
    CHECK(k.foreign == 0,
          "kprobes: the module's own probes and non-syscall probes are not foreign");

    f = text_stream(
        "ffff800080123450  k  __arm64_sys_ptrace+0x0    \n"
        "ffff800080123458  k  __arm64_sys_openat+0x0    \n"
        "ffff800080123470  r  __arm64_sys_execve+0x0    \n");
    scan_kprobes_stream(f, &k);
    fclose(f);
    CHECK(k.foreign == 1, "kprobes: a probe on another syscall entry is foreign");
    CHECK(strcmp(k.first, "k __arm64_sys_openat+0x0") == 0,
          "kprobes: the foreign probe is named");

    /* A second probe on a symbol the module also probes is somebody
     * else's: the module registers one. */
    f = text_stream(
        "ffff800080123450  k  __arm64_sys_ptrace+0x0    \n"
        "ffff800080123450  k  __arm64_sys_ptrace+0x0    \n");
    scan_kprobes_stream(f, &k);
    fclose(f);
    CHECK(k.foreign == 1, "kprobes: a duplicate on one of our symbols is foreign");

    /* Wrong type or a mid-function offset is not ours either. */
    f = text_stream(
        "ffff800080123450  r  __arm64_sys_ptrace+0x0    \n"
        "ffff800080123474  r  __arm64_sys_execve+0x4    \n"
        "ffff800080123500  k  invoke_syscall+0x0    \n"
        "ffff800080123600  k  __do_sys_openat+0x8    \n");
    scan_kprobes_stream(f, &k);
    fclose(f);
    CHECK(k.foreign == 4,
          "kprobes: type/offset mismatches and the dispatch path count as foreign");

    f = text_stream(
        "ffff800080123458  k  __arm64_sys_openat+0x0    [DISABLED]\n"
        "ffff800080123468  k  __arm64_sys_read+0x0    [GONE]\n"
        "garbage\n"
        "\n");
    scan_kprobes_stream(f, &k);
    fclose(f);
    CHECK(k.foreign == 0,
          "kprobes: disarmed, gone and malformed lines are ignored");
}

static void test_ftrace(void)
{
    struct ac_ftrace_scan t;
    FILE *f;

    f = text_stream(
        "vfs_read (1) R I     \ttramp: 0xffff800001234000 (klp_ftrace_handler+0x0/0x1b0) ->ftrace_regs_caller+0x0/0x60\n"
        "__arm64_sys_openat (1)             \ttramp: 0xffff800001235000 (Individual_fn+0x0/0x10)\n"
        "__arm64_sys_read (1) R   D   M \ttramp: 0xffff800001236000\n"
        "\tdirect-->bpf_trampoline_123+0x0/0x100\n"
        "__arm64_sys_kill (2) R I     \ttramp: 0xffff800001237000 (DIRECT_fn+0x0/0x10)\n"
        "do_el0_svc [mod] (1)   I   O   \n");
    scan_ftrace_stream(f, &t);
    fclose(f);
    CHECK(t.traced == 4, "ftrace: counts every traced syscall entry, and only those");
    CHECK(t.direct == 1,
          "ftrace: direct flag read from the flag columns, not the trampoline text");
    CHECK(t.ipmodify == 2,
          "ftrace: IPMODIFY flag read from the flag columns, not the trampoline text");
    CHECK(strcmp(t.first_ipmodify, "__arm64_sys_kill") == 0,
          "ftrace: the first IPMODIFY entry is named");

    f = text_stream("");
    scan_ftrace_stream(f, &t);
    fclose(f);
    CHECK(t.traced == 0 && t.ipmodify == 0, "ftrace: an empty list is clean");
}

static void put_file(const char *dir, const char *rel, const char *text)
{
    char path[PATH_MAX];
    FILE *f;

    snprintf(path, sizeof(path), "%s/%s", dir, rel);
    f = fopen(path, "w");
    if (!f || fputs(text, f) == EOF || fclose(f) == EOF) {
        perror(path);
        exit(1);
    }
}

static void make_dir(const char *dir, const char *rel)
{
    char path[PATH_MAX];

    snprintf(path, sizeof(path), "%s/%s", dir, rel);
    if (mkdir(path, 0700) < 0) {
        perror(path);
        exit(1);
    }
}

/* A fake /sys/module/<name>: `state` NULL means no initstate file (a
 * built-in), `text` 0 means no .text section. */
static void fake_module(const char *dir, const char *name, const char *state,
                        int text)
{
    char rel[PATH_MAX];

    make_dir(dir, name);
    if (state) {
        snprintf(rel, sizeof(rel), "%s/initstate", name);
        put_file(dir, rel, state);
    }
    snprintf(rel, sizeof(rel), "%s/sections", name);
    make_dir(dir, rel);
    if (text) {
        snprintf(rel, sizeof(rel), "%s/sections/.text", name);
        put_file(dir, rel, "0x0\n");
    }
}

static void set_kernel_list(const char *const *names, unsigned int n)
{
    unsigned int i;

    kmod_count = 0;
    for (i = 0; i < n; i++)
        snprintf(kmod_names[kmod_count++], AC_MOD_NAME_LEN, "%s", names[i]);
}

static void test_sysfs_modules(void)
{
    static const char *const listed[] = { "ext4", "anticheat" };
    static char out[AC_MAX_UNLISTED][AC_MOD_NAME_LEN];
    char dir[] = "/tmp/ac_integrity_scan_XXXXXX";
    char cmd[PATH_MAX + 16];
    long n;

    if (!mkdtemp(dir)) {
        perror("mkdtemp");
        exit(1);
    }
    fake_module(dir, "ext4", "live\n", 1);
    fake_module(dir, "anticheat", "live\n", 1);
    fake_module(dir, "kernel", NULL, 0);          /* built-in: parameters only */
    fake_module(dir, "loading_mod", "coming\n", 1);
    fake_module(dir, "going_mod", "going\n", 1);
    fake_module(dir, "data_only", "live\n", 0);   /* nothing executable */

    set_kernel_list(listed, 2);
    n = collect_unlisted_modules(dir, out, AC_MAX_UNLISTED);
    CHECK(n == 0,
          "sysfs: listed, built-in, loading, unloading and text-less entries are not unlisted");

    fake_module(dir, "rootkit", "live\n", 1);
    n = collect_unlisted_modules(dir, out, AC_MAX_UNLISTED);
    CHECK(n == 1 && strcmp(out[0], "rootkit") == 0,
          "sysfs: a live module missing from the kernel list is reported by name");

    /* The same directory against an empty kernel list: three live
     * modules, a cap of two -> out of step, not "two hidden". */
    set_kernel_list(listed, 0);
    CHECK(collect_unlisted_modules(dir, out, 2) == -1,
          "sysfs: more candidates than the cap is inconclusive");
    CHECK(collect_unlisted_modules(dir, out, 3) == 3,
          "sysfs: exactly the cap is still a result");

    CHECK(collect_unlisted_modules("/nonexistent/ac_integrity_scan", out,
                                   AC_MAX_UNLISTED) == -1,
          "sysfs: an unreadable directory is inconclusive");

    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
    if (system(cmd) != 0)
        fprintf(stderr, "warning: could not remove %s\n", dir);
}

int main(void)
{
    test_kprobes();
    test_ftrace();
    test_sysfs_modules();

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    fprintf(stderr, "all checks passed\n");
    return 0;
}
