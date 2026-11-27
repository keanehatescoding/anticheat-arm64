/*
 * implicit_layer_baseline_test.c -- regression tests for #112 (baseline half):
 *
 *  - an unrecognized implicit Vulkan layer is identified by (name,
 *    library_path), so a layer that keeps its name but is repointed at a
 *    different library is detected as a change.
 *  - a new layer, or one name swapped for another at the same count, is
 *    still detected.
 *  - an unchanged set, or a layer that merely disappears, is not a change.
 *  - storing a set into a baseline slot replaces it fully and clears the
 *    unused tail, so a stale id cannot mask a later change.
 *
 * Pulls anticheat_daemon.c in as-is (renaming its main() out of the way)
 * to test the real helpers, not duplicated copies.
 *
 * Build: make implicit-layer-baseline-test
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

static void set_id(struct ac_implicit_layer_id *id, const char *name,
                   const char *lib)
{
    memset(id, 0, sizeof(*id));
    snprintf(id->name, sizeof(id->name), "%s", name);
    snprintf(id->lib, sizeof(id->lib), "%s", lib);
}

int main(void)
{
    struct ac_implicit_layer_id base[2], cur[2];
    static struct ac_implicit_layer_baseline b;

    set_id(&base[0], "VK_LAYER_CUSTOM", "/opt/original.so");
    set_id(&base[1], "VK_LAYER_OTHER", "/opt/other.so");

    /* Identical set: silent. */
    memcpy(cur, base, sizeof(cur));
    CHECK(!ac_implicit_ids_have_new(cur, 2, base, 2),
          "an unchanged (name, library_path) set is not a change");

    /* Same name, different library: the case a name-only baseline misses. */
    memcpy(cur, base, sizeof(cur));
    set_id(&cur[0], "VK_LAYER_CUSTOM", "/opt/replacement.so");
    CHECK(ac_implicit_ids_have_new(cur, 2, base, 2),
          "same name with a different library_path is a change");

    /* One name swapped for another at an unchanged count. */
    memcpy(cur, base, sizeof(cur));
    set_id(&cur[1], "VK_LAYER_THIRD", "/opt/other.so");
    CHECK(ac_implicit_ids_have_new(cur, 2, base, 2),
          "one layer swapped for another at the same count is a change");

    /* New layer appearing. */
    memcpy(cur, base, sizeof(cur));
    CHECK(ac_implicit_ids_have_new(cur, 2, base, 1),
          "a layer absent from the baseline is a change");

    /* A layer disappearing is not itself a new unrecognized layer. */
    memcpy(cur, base, sizeof(cur));
    CHECK(!ac_implicit_ids_have_new(cur, 1, base, 2),
          "a layer that disappears is not a change");

    /* Order does not matter. */
    set_id(&cur[0], "VK_LAYER_OTHER", "/opt/other.so");
    set_id(&cur[1], "VK_LAYER_CUSTOM", "/opt/original.so");
    CHECK(!ac_implicit_ids_have_new(cur, 2, base, 2),
          "the same pairs in a different order are not a change");

    /* Empty sets. */
    CHECK(!ac_implicit_ids_have_new(cur, 0, base, 2),
          "an empty current set is not a change");
    CHECK(ac_implicit_ids_have_new(base, 2, cur, 0),
          "any layer against an empty baseline is a change");

    /* Store: replaces the set and clears the tail. */
    ac_implicit_baseline_store(&b, base, 2);
    CHECK(b.nunknown == 2 && !ac_implicit_ids_have_new(base, 2, b.ids, b.nunknown),
          "store records the set it is given");
    ac_implicit_baseline_store(&b, base, 1);
    CHECK(b.nunknown == 1 && b.ids[1].name[0] == '\0' && b.ids[1].lib[0] == '\0',
          "store to a smaller set clears the stale tail");
    CHECK(ac_implicit_ids_have_new(base, 2, b.ids, b.nunknown),
          "a layer dropped from the stored baseline is detected if it returns");

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    fprintf(stderr, "all checks passed\n");
    return 0;
}
