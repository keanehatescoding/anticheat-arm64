/*
 * implicit_layer_scan_test.c -- fixture tests for ac_scan_active_implicit_layers()
 * (issue #112, scan half).
 *
 * Each case builds throwaway manifest directories, starts a real child
 * process (sleep) with a controlled environment, and runs the real scan
 * against it. The scan reads the child's /proc/<pid>/environ, so this
 * exercises the whole path: environ parsing, search-list construction
 * (XDG, HOME, Flatpak, VK_IMPLICIT_LAYER_PATH, VK_ADD_IMPLICIT_LAYER_PATH),
 * the /proc/<pid>/root and /proc/<pid>/cwd resolution, manifest parsing,
 * and disable_environment filtering.
 *
 * Assertions are made by unique layer name (TST_*), never by total count,
 * so layers that happen to be installed on the host (the default search
 * path always includes /usr/share and /etc) cannot affect the result.
 *
 * Pulls anticheat_daemon.c in as-is (renaming its main() out of the way)
 * to test the real code, not duplicated copies.
 *
 * Build: make implicit-layer-scan-test
 */
#define main ac_daemon_unused_main
#include "../src/anticheat_daemon.c"
#undef main

#include <ftw.h>
#include <sys/wait.h>

/* Fixture paths are short and built into PATH_MAX buffers; the compiler
 * cannot prove that, and the daemon suppresses the same warning for the
 * same reason where it joins directory and file names. */
#pragma GCC diagnostic ignored "-Wformat-truncation"

static int failures;

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s\n", msg); \
        failures++; \
    } else { \
        fprintf(stderr, "PASS: %s\n", msg); \
    } \
} while (0)

static char root[PATH_MAX];

static void mkpath(const char *path)
{
    char tmp[PATH_MAX];
    char *p;

    snprintf(tmp, sizeof(tmp), "%s", path);
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
                perror(tmp);
                exit(2);
            }
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
        perror(tmp);
        exit(2);
    }
}

/* Absolute path under the fixture root. */
static const char *rp(const char *rel)
{
    static char buf[8][PATH_MAX];
    static int i;
    char *b = buf[i++ % 8];

    snprintf(b, PATH_MAX, "%s/%s", root, rel);
    return b;
}

/* Writes a manifest for layer `name` at root/<dir>/<file>. `disable_var`
 * adds a disable_environment entry when non-NULL. */
static void manifest(const char *dir, const char *file, const char *name,
                     const char *disable_var)
{
    char path[PATH_MAX];
    FILE *f;

    mkpath(rp(dir));
    snprintf(path, sizeof(path), "%s/%s", rp(dir), file);
    f = fopen(path, "w");
    if (!f) {
        perror(path);
        exit(2);
    }
    fprintf(f, "{\"file_format_version\":\"1.0.0\",\"layer\":{\"name\":\"%s\","
               "\"type\":\"GLOBAL\",\"library_path\":\"/opt/tst/%s.so\","
               "\"api_version\":\"1.3.0\",\"implementation_version\":\"1\","
               "\"description\":\"fixture\"", name, name);
    if (disable_var)
        fprintf(f, ",\"disable_environment\":{\"%s\":\"1\"}", disable_var);
    fprintf(f, "}}\n");
    fclose(f);
}

/* Starts `sleep` in `cwd` (NULL = inherit) with exactly the given
 * NULL-terminated environment, and waits until the exec has happened so
 * /proc/<pid>/environ describes the new image. */
static pid_t spawn(const char *cwd, ...)
{
    char *envp[32];
    int n = 0, i;
    va_list ap;
    const char *s;
    pid_t pid;

    va_start(ap, cwd);
    while (n < 31 && (s = va_arg(ap, const char *)) != NULL)
        envp[n++] = strdup(s);
    va_end(ap);
    envp[n] = NULL;

    pid = fork();
    if (pid == 0) {
        char *argv[] = { "sleep", "60", NULL };

        if (cwd && chdir(cwd) != 0)
            _exit(126);
        execve("/usr/bin/sleep", argv, envp);
        execve("/bin/sleep", argv, envp);
        _exit(127);
    }
    for (i = 0; i < n; i++)
        free(envp[i]);
    for (i = 0; i < 200; i++) {
        char path[64], comm[32] = "";
        FILE *f;

        snprintf(path, sizeof(path), "/proc/%d/comm", pid);
        f = fopen(path, "r");
        if (f) {
            if (fgets(comm, sizeof(comm), f) && strncmp(comm, "sleep", 5) == 0) {
                fclose(f);
                return pid;
            }
            fclose(f);
        }
        usleep(10 * 1000);
    }
    fprintf(stderr, "spawn: child never exec'd sleep\n");
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    exit(2);
}

static void reap(pid_t pid)
{
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
}

static struct ac_implicit_layer g_out[AC_MAX_IMPLICIT_LAYERS];

/* Scan `pid`; returns the scan's return value, results left in g_out. */
static int scan(pid_t pid)
{
    memset(g_out, 0, sizeof(g_out));
    return ac_scan_active_implicit_layers(pid, g_out, AC_MAX_IMPLICIT_LAYERS);
}

static int count_named(int n, const char *name)
{
    int i, c = 0;

    for (i = 0; i < n; i++)
        if (strcmp(g_out[i].name, name) == 0)
            c++;
    return c;
}

static int has(int n, const char *name)
{
    return count_named(n, name) > 0;
}

static int rm_cb(const char *p, const struct stat *sb, int flag, struct FTW *w)
{
    (void)sb; (void)flag; (void)w;
    (void)remove(p);
    return 0;
}

static void cleanup(void)
{
    if (root[0])
        nftw(root, rm_cb, 16, FTW_DEPTH | FTW_PHYS);
}

/* Environment string "NAME=<root>/rel" into a reusable slot. */
static const char *envp_path(const char *name, const char *rel)
{
    static char buf[8][PATH_MAX + 64];
    static int i;
    char *b = buf[i++ % 8];

    snprintf(b, sizeof(buf[0]), "%s=%s", name, rp(rel));
    return b;
}

#define LAYER_DIR "vulkan/implicit_layer.d"

int main(void)
{
    char tmpl[] = "/tmp/ac_implicit_scan_XXXXXX";
    char home_env[PATH_MAX + 16];
    pid_t pid;
    int n;

    if (!mkdtemp(tmpl)) {
        perror("mkdtemp");
        return 2;
    }
    snprintf(root, sizeof(root), "%s", tmpl);
    atexit(cleanup);

    /* An empty HOME keeps the default search list off the real user's
     * ~/.config and ~/.local/share in cases that don't set it. */
    mkpath(rp("emptyhome"));
    snprintf(home_env, sizeof(home_env), "HOME=%s", rp("emptyhome"));

    /* --- XDG_DATA_HOME / XDG_CONFIG_HOME ------------------------------ */
    manifest("xdh/" LAYER_DIR, "a.json", "TST_XDG_DATA_HOME", NULL);
    manifest("xch/" LAYER_DIR, "a.json", "TST_XDG_CONFIG_HOME", NULL);
    pid = spawn(NULL, home_env, envp_path("XDG_DATA_HOME", "xdh"),
                envp_path("XDG_CONFIG_HOME", "xch"), NULL);
    n = scan(pid);
    CHECK(n >= 0, "default search: scan is conclusive");
    CHECK(has(n, "TST_XDG_DATA_HOME"), "XDG_DATA_HOME/vulkan/implicit_layer.d is scanned");
    CHECK(has(n, "TST_XDG_CONFIG_HOME"), "XDG_CONFIG_HOME/vulkan/implicit_layer.d is scanned");
    {
        int i, ok = 0;

        for (i = 0; i < n; i++)
            if (strcmp(g_out[i].name, "TST_XDG_DATA_HOME") == 0 &&
                strcmp(g_out[i].library_path, "/opt/tst/TST_XDG_DATA_HOME.so") == 0)
                ok = 1;
        CHECK(ok, "the manifest's library_path is reported intact");
    }
    reap(pid);

    /* --- XDG_DATA_DIRS / XDG_CONFIG_DIRS (every entry, deduplicated) -- */
    manifest("dd1/" LAYER_DIR, "a.json", "TST_DD1", NULL);
    manifest("dd2/" LAYER_DIR, "a.json", "TST_DD2", NULL);
    manifest("cd1/" LAYER_DIR, "a.json", "TST_CD1", NULL);
    {
        char dd[PATH_MAX * 3], cd[PATH_MAX];

        snprintf(dd, sizeof(dd), "XDG_DATA_DIRS=%s:%s/:%s", rp("dd1"), rp("dd1"), rp("dd2"));
        snprintf(cd, sizeof(cd), "XDG_CONFIG_DIRS=%s", rp("cd1"));
        pid = spawn(NULL, home_env, dd, cd, NULL);
    }
    n = scan(pid);
    CHECK(has(n, "TST_DD1") && has(n, "TST_DD2"),
          "every XDG_DATA_DIRS entry is scanned");
    CHECK(has(n, "TST_CD1"), "XDG_CONFIG_DIRS entries are scanned");
    CHECK(count_named(n, "TST_DD1") == 1,
          "a directory listed twice (one with a trailing slash) is scanned once");
    reap(pid);

    /* --- HOME fallback when XDG_*_HOME are unset ---------------------- */
    manifest("home1/.config/" LAYER_DIR, "a.json", "TST_HOME_CONFIG", NULL);
    manifest("home1/.local/share/" LAYER_DIR, "a.json", "TST_HOME_DATA", NULL);
    pid = spawn(NULL, envp_path("HOME", "home1"), NULL);
    n = scan(pid);
    CHECK(has(n, "TST_HOME_CONFIG"), "unset XDG_CONFIG_HOME falls back to $HOME/.config");
    CHECK(has(n, "TST_HOME_DATA"), "unset XDG_DATA_HOME falls back to $HOME/.local/share");
    reap(pid);

    /* --- Flatpak user export dir -------------------------------------- */
    manifest("fpdata/flatpak/exports/share/" LAYER_DIR, "a.json", "TST_FLATPAK", NULL);
    pid = spawn(NULL, home_env, envp_path("XDG_DATA_HOME", "fpdata"), NULL);
    n = scan(pid);
    CHECK(has(n, "TST_FLATPAK"), "the Flatpak user export dir is scanned by default");
    reap(pid);

    /* --- VK_IMPLICIT_LAYER_PATH replaces the defaults ----------------- */
    manifest("vip", "a.json", "TST_VIP_DIRECT", NULL);
    manifest("vip/" LAYER_DIR, "a.json", "TST_VIP_SUFFIXED", NULL);
    pid = spawn(NULL, home_env, envp_path("VK_IMPLICIT_LAYER_PATH", "vip"),
                envp_path("XDG_DATA_HOME", "xdh"),
                envp_path("XDG_CONFIG_HOME", "xch"),
                envp_path("XDG_DATA_DIRS", "dd1"), NULL);
    n = scan(pid);
    CHECK(n >= 0, "VK_IMPLICIT_LAYER_PATH: scan is conclusive");
    CHECK(has(n, "TST_VIP_DIRECT"),
          "VK_IMPLICIT_LAYER_PATH entries are manifest directories used as-is");
    CHECK(!has(n, "TST_VIP_SUFFIXED"),
          "no implicit_layer.d suffix is appended to VK_IMPLICIT_LAYER_PATH entries");
    CHECK(!has(n, "TST_XDG_DATA_HOME") && !has(n, "TST_XDG_CONFIG_HOME") &&
          !has(n, "TST_DD1"),
          "VK_IMPLICIT_LAYER_PATH replaces the XDG default locations");
    reap(pid);

    pid = spawn(NULL, home_env, envp_path("VK_IMPLICIT_LAYER_PATH", "vip"),
                envp_path("XDG_DATA_HOME", "fpdata"), NULL);
    n = scan(pid);
    CHECK(!has(n, "TST_FLATPAK"),
          "VK_IMPLICIT_LAYER_PATH also excludes the Flatpak export dirs");
    reap(pid);

    /* --- empty VK_IMPLICIT_LAYER_PATH is still a replacement ---------- */
    pid = spawn(NULL, home_env, "VK_IMPLICIT_LAYER_PATH=",
                envp_path("XDG_DATA_HOME", "xdh"), NULL);
    n = scan(pid);
    CHECK(n >= 0, "empty VK_IMPLICIT_LAYER_PATH: scan is conclusive");
    CHECK(!has(n, "TST_XDG_DATA_HOME"),
          "an empty VK_IMPLICIT_LAYER_PATH still replaces (disables) the defaults");
    reap(pid);

    /* --- VK_ADD_IMPLICIT_LAYER_PATH is additive, but only without VIP - */
    manifest("addvip", "a.json", "TST_ADD", NULL);
    pid = spawn(NULL, home_env, envp_path("VK_ADD_IMPLICIT_LAYER_PATH", "addvip"),
                envp_path("XDG_DATA_HOME", "xdh"), NULL);
    n = scan(pid);
    CHECK(has(n, "TST_ADD"), "VK_ADD_IMPLICIT_LAYER_PATH adds its directories");
    CHECK(has(n, "TST_XDG_DATA_HOME"),
          "VK_ADD_IMPLICIT_LAYER_PATH keeps the default locations");
    reap(pid);

    pid = spawn(NULL, home_env, envp_path("VK_IMPLICIT_LAYER_PATH", "vip"),
                envp_path("VK_ADD_IMPLICIT_LAYER_PATH", "addvip"), NULL);
    n = scan(pid);
    CHECK(!has(n, "TST_ADD"),
          "VK_ADD_IMPLICIT_LAYER_PATH is ignored when VK_IMPLICIT_LAYER_PATH is set");
    reap(pid);

    /* --- direct manifest file entries --------------------------------- */
    manifest("single", "only.json", "TST_SINGLE_FILE", NULL);
    manifest("notjson", "manifest.txt", "TST_NOT_JSON", NULL);
    {
        char list[PATH_MAX * 2], path[PATH_MAX];

        snprintf(path, sizeof(path), "%s/only.json", rp("single"));
        snprintf(list, sizeof(list), "VK_IMPLICIT_LAYER_PATH=%s", path);
        pid = spawn(NULL, home_env, list, NULL);
        n = scan(pid);
        CHECK(has(n, "TST_SINGLE_FILE"),
              "a .json file named directly in VK_IMPLICIT_LAYER_PATH is a manifest");
        reap(pid);

        snprintf(path, sizeof(path), "%s/manifest.txt", rp("notjson"));
        snprintf(list, sizeof(list), "VK_IMPLICIT_LAYER_PATH=%s", path);
        pid = spawn(NULL, home_env, list, NULL);
        n = scan(pid);
        CHECK(n >= 0 && !has(n, "TST_NOT_JSON"),
              "a non-.json regular file entry is not parsed as a manifest");
        reap(pid);
    }

    /* --- relative entries resolve against the target's cwd ------------ */
    manifest("cwdbase/rel", "a.json", "TST_RELATIVE", NULL);
    pid = spawn(rp("cwdbase"), home_env, "VK_IMPLICIT_LAYER_PATH=rel", NULL);
    n = scan(pid);
    CHECK(has(n, "TST_RELATIVE"),
          "a relative VK_IMPLICIT_LAYER_PATH entry resolves via the target's cwd");
    reap(pid);

    /* --- manifest validity -------------------------------------------- */
    {
        char path[PATH_MAX];
        FILE *f;

        mkpath(rp("badmanifest"));
        snprintf(path, sizeof(path), "%s/nolib.json", rp("badmanifest"));
        f = fopen(path, "w");
        fputs("{\"layer\":{\"name\":\"TST_NO_LIBRARY\"}}\n", f);
        fclose(f);
        manifest("badmanifest", "good.json", "TST_GOOD_NEIGHBOUR", NULL);
        pid = spawn(NULL, home_env, envp_path("VK_IMPLICIT_LAYER_PATH", "badmanifest"), NULL);
        n = scan(pid);
        CHECK(!has(n, "TST_NO_LIBRARY"),
              "a manifest without library_path is skipped, not guessed at");
        CHECK(has(n, "TST_GOOD_NEIGHBOUR"),
              "a malformed neighbour does not hide a valid manifest");
        reap(pid);
    }

    /* --- disable_environment ------------------------------------------ */
    manifest("dis", "a.json", "TST_DISABLEABLE", "TST_DISABLE_VAR");
    pid = spawn(NULL, home_env, envp_path("VK_IMPLICIT_LAYER_PATH", "dis"), NULL);
    n = scan(pid);
    CHECK(has(n, "TST_DISABLEABLE"), "a layer whose disable variable is unset is active");
    reap(pid);

    pid = spawn(NULL, home_env, envp_path("VK_IMPLICIT_LAYER_PATH", "dis"),
                "TST_DISABLE_VAR=1", NULL);
    n = scan(pid);
    CHECK(n >= 0 && !has(n, "TST_DISABLEABLE"),
          "a layer whose disable variable is set in the target is inactive");
    reap(pid);

    pid = spawn(NULL, home_env, envp_path("VK_IMPLICIT_LAYER_PATH", "dis"),
                "TST_DISABLE_VAR=", NULL);
    n = scan(pid);
    CHECK(n >= 0 && !has(n, "TST_DISABLEABLE"),
          "a disable variable set to the empty string still disables the layer");
    reap(pid);

    pid = spawn(NULL, home_env, envp_path("VK_IMPLICIT_LAYER_PATH", "dis"),
                "TST_DISABLE_VAR=1", "VK_INSTANCE_LAYERS=TST_DISABLEABLE", NULL);
    n = scan(pid);
    CHECK(has(n, "TST_DISABLEABLE"),
          "naming the layer in VK_INSTANCE_LAYERS loads it despite the disable variable");
    reap(pid);

    /* --- incomplete environment data is inconclusive ------------------ */
    {
        char big[AC_ENVIRON_VAL_LEN + 200];
        size_t i, off;

        off = (size_t)snprintf(big, sizeof(big), "VK_IMPLICIT_LAYER_PATH=");
        for (i = 0; i < AC_ENVIRON_VAL_LEN + 100 && off + 2 < sizeof(big); i++)
            big[off++] = 'a';
        big[off] = '\0';
        pid = spawn(NULL, home_env, big, NULL);
        n = scan(pid);
        CHECK(n < 0,
              "a VK_IMPLICIT_LAYER_PATH too long to read is inconclusive, not 'no layers'");
        reap(pid);
    }

    /* --- an unreadable directory is inconclusive (root bypasses perms) - */
    if (geteuid() != 0) {
        manifest("locked", "a.json", "TST_LOCKED", NULL);
        chmod(rp("locked"), 0);
        pid = spawn(NULL, home_env, envp_path("VK_IMPLICIT_LAYER_PATH", "locked"), NULL);
        n = scan(pid);
        CHECK(n < 0, "an existing but unreadable directory makes the scan inconclusive");
        reap(pid);
        chmod(rp("locked"), 0755);
    } else {
        fprintf(stderr, "SKIP: unreadable-directory case (running as root)\n");
    }

    /* --- a missing directory is normal, not an error ------------------ */
    pid = spawn(NULL, home_env, envp_path("VK_IMPLICIT_LAYER_PATH", "does/not/exist"), NULL);
    n = scan(pid);
    CHECK(n == 0, "a missing VK_IMPLICIT_LAYER_PATH directory yields a conclusive empty scan");
    reap(pid);

    /* --- exactly as many manifests as the scan can hold is still fine - */
    {
        int i;
        char file[32], nm[32];

        for (i = 0; i < AC_MAX_IMPLICIT_LAYERS; i++) {
            snprintf(file, sizeof(file), "m%03d.json", i);
            snprintf(nm, sizeof(nm), "TST_FULL_%03d", i);
            manifest("full", file, nm, NULL);
        }
        pid = spawn(NULL, home_env, envp_path("VK_IMPLICIT_LAYER_PATH", "full"), NULL);
        n = scan(pid);
        CHECK(n == AC_MAX_IMPLICIT_LAYERS,
              "exactly AC_MAX_IMPLICIT_LAYERS manifests is a complete, conclusive result");
        reap(pid);
    }

    /* --- more manifests than the scan can hold ------------------------ */
    {
        int i;
        char file[32], nm[32];

        for (i = 0; i < AC_MAX_IMPLICIT_LAYERS + 6; i++) {
            snprintf(file, sizeof(file), "m%03d.json", i);
            snprintf(nm, sizeof(nm), "TST_FLOOD_%03d", i);
            manifest("flood", file, nm, NULL);
        }
        pid = spawn(NULL, home_env, envp_path("VK_IMPLICIT_LAYER_PATH", "flood"), NULL);
        n = scan(pid);
        CHECK(n < 0,
              "more manifests than the scan can hold is inconclusive, not a silently truncated result");
        reap(pid);
    }

    /* The overflow must also be caught when the extra manifests are spread
     * across directories rather than packed into one. */
    {
        char list[PATH_MAX * 2];

        snprintf(list, sizeof(list), "VK_IMPLICIT_LAYER_PATH=%s:%s", rp("full"), rp("addvip"));
        pid = spawn(NULL, home_env, list, NULL);
        n = scan(pid);
        CHECK(n < 0,
              "overflow across several directories is inconclusive too");
        reap(pid);
    }

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    fprintf(stderr, "all checks passed\n");
    return 0;
}
