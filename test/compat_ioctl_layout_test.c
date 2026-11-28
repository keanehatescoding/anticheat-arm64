/*
 * compat_ioctl_layout_test.c -- layout contract for the 32-bit (AArch32)
 * control-device path (#80).
 *
 * The kernel module can't be built or loaded here, so this pins down the
 * parts of the compat ioctl that are plain C: the AArch32 layout of
 * AC_IOCTL_SCAN_GET (struct ac_scan_get32 must be byte-for-byte what a
 * 32-bit build of struct ac_scan_get is), that its ioctl number differs
 * from the native one (which is why ac_compat_ioctl() has to translate
 * rather than forward), and the native->compat conversion helper the
 * module calls. Pure userspace, no root, no device.
 *
 * The expected values below are the AArch32 EABI layout worked out by
 * hand (4-byte `unsigned long`, 8-byte alignment for long long); they are
 * deliberately literals, not sizeof() of the structs under test.
 */
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>

#include "../src/anticheat.h"

_Static_assert(sizeof(unsigned int) == 4, "test assumes 32-bit int");

/* AArch32 layout of struct ac_vma_info / struct ac_scan_get. */
_Static_assert(offsetof(struct ac_vma_info32, flags)   == 32,  "flags@32");
_Static_assert(offsetof(struct ac_vma_info32, is_file) == 36,  "is_file@36");
_Static_assert(offsetof(struct ac_vma_info32, path)    == 40,  "path@40");
_Static_assert(sizeof(struct ac_vma_info32)            == 168, "vma_info32");
_Static_assert(offsetof(struct ac_scan_get32, vma)     == 8,   "vma@8");
_Static_assert(sizeof(struct ac_scan_get32)            == 176, "scan_get32");

static int failures;

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        failures++; \
    } \
} while (0)

int main(void)
{
    /* On an LP64 build the native struct has an 8-byte `flags`, so its
     * size -- and therefore the ioctl number -- differs from the compat
     * one. That is the whole reason SCAN_GET can't go through
     * compat_ptr_ioctl() unchanged. (On an ILP32 build the two are
     * identical by construction.) */
    if (sizeof(unsigned long) == 8) {
        CHECK(sizeof(struct ac_scan_get) == 184);
        CHECK(AC_IOCTL_SCAN_GET != AC_IOCTL_SCAN_GET32);
    } else {
        CHECK(sizeof(struct ac_scan_get) == sizeof(struct ac_scan_get32));
        CHECK(AC_IOCTL_SCAN_GET == AC_IOCTL_SCAN_GET32);
    }
    CHECK(_IOC_NR(AC_IOCTL_SCAN_GET32) == _IOC_NR(AC_IOCTL_SCAN_GET));
    CHECK(_IOC_TYPE(AC_IOCTL_SCAN_GET32) == AC_IOCTL_MAGIC);
    CHECK(_IOC_SIZE(AC_IOCTL_SCAN_GET32) == 176);

    /* Conversion: every field carries over; flags keeps the low 32 bits. */
    {
        struct ac_vma_info n;
        struct ac_vma_info32 c;
        unsigned int i;

        memset(&n, 0, sizeof(n));
        memset(&c, 0xAA, sizeof(c));
        n.start   = 0x0000fffff7e00000ULL;
        n.end     = 0x0000fffff7f00000ULL;
        n.offset  = 0x1000;
        n.inode   = 0x123456789abcULL;
        n.flags   = (unsigned long)(AC_VM_EXEC | AC_VM_WRITE);
        if (sizeof(unsigned long) == 8)
            n.flags |= 1UL << 36;   /* arm64-only high VM bit: dropped */
        n.is_file = 1;
        strcpy(n.path, "/usr/lib/libexample.so");

        ac_vma_info_to32(&c, &n);

        CHECK(c.start == n.start);
        CHECK(c.end == n.end);
        CHECK(c.offset == n.offset);
        CHECK(c.inode == n.inode);
        CHECK(c.flags == (AC_VM_EXEC | AC_VM_WRITE));
        CHECK(c.is_file == 1);
        for (i = 0; i < AC_VMA_PATH; i++)
            CHECK(c.path[i] == n.path[i]);
    }

    if (failures) {
        fprintf(stderr, "compat_ioctl_layout_test: %d failure(s)\n", failures);
        return 1;
    }
    puts("compat_ioctl_layout_test: ok");
    return 0;
}
