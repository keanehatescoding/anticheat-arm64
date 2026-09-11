#!/bin/bash
# kasan_boot_test.sh -- boots a KASAN + lockdep instrumented linux-6.12
# kernel in a VM (via virtme-ng), loads the real anticheat.ko into it,
# exercises the daemon CLI plus the real (non-safe-mode) ioctl fuzz
# harness against the real /dev/anticheat, and fails if the console/
# dmesg output shows a KASAN report, a lockdep splat, or any oops/
# warning/general-protection-fault during the run.
#
# This is the "real" run test/ioctl_fuzz.c's own header comment and
# README's "ioctl fuzzing" section describe as the one that actually
# closes the kernel-assurance gap: CI's per-push dry run only proves the
# harness itself is correct against the mock, which has none of a real
# kernel's copy_from_user()/access_ok() to stress.
#
# Needs: a Linux host, ideally with KVM available (falls back to much
# slower QEMU/TCG software emulation if not -- see
# .github/workflows/kasan-boot.yml, which runs this nightly rather than
# per-push for exactly that reason: GitHub-hosted runners don't reliably
# offer /dev/kvm), virtme-ng ("pipx install virtme-ng" -- recent distros
# mark the system Python as externally-managed, so plain `pip install`
# outside a venv typically fails), qemu-system-aarch64, aarch64-linux-gnu-gcc
# when building on a non-ARM host (native build needs no cross toolchain),
# and the usual kernel
# build deps (bc flex bison libelf-dev libssl-dev dwarves).
#
# Run locally: ./scripts/kasan_boot_test.sh
# Override the fuzz run via environment: IOCTL_FUZZ_ITERATIONS=2000
# IOCTL_FUZZ_SEED=$(date +%s) ./scripts/kasan_boot_test.sh -- the fixed
# defaults below keep a bare local invocation reproducible; the nightly
# workflow passes a fresh seed each run instead, so repeated nightly
# runs accumulate coverage rather than re-fuzzing the identical sequence
# forever.
# Scratch space: the kernel tree is built under ${TMPDIR:-/tmp}; set
# TMPDIR to a disk-backed directory on hosts where /tmp is a small
# tmpfs, which a KASAN build will otherwise fill.
# Cross-arch rootfs reuse: AC_ARM64_ROOT=/path/to/arm64-chroot reuses a
# prepared Ubuntu arm64 tree instead of downloading a fresh cloud image
# every run (vng uses the dir as-is when it already exists). Needed on
# hosts without passwordless sudo, which vng's own provisioning requires.
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1
REPO_ROOT="$PWD"

IOCTL_FUZZ_ITERATIONS="${IOCTL_FUZZ_ITERATIONS:-300}"
IOCTL_FUZZ_SEED="${IOCTL_FUZZ_SEED:-20260819}"
if ! [[ "$IOCTL_FUZZ_ITERATIONS" =~ ^[1-9][0-9]*$ && "$IOCTL_FUZZ_SEED" =~ ^[0-9]+$ ]]; then
    echo "IOCTL_FUZZ_ITERATIONS must be a positive integer and IOCTL_FUZZ_SEED a non-negative integer (got ITERATIONS=$IOCTL_FUZZ_ITERATIONS SEED=$IOCTL_FUZZ_SEED)" >&2
    exit 2
fi

KVER=6.12
# ${TMPDIR:-/tmp}, not a hardcoded /tmp: the full KASAN kernel tree
# built below wants tens of GB, and on a host whose /tmp is a small
# RAM-backed tmpfs (systemd's default on several distros) that build
# both runs out of space and competes for RAM with itself. Honouring
# TMPDIR lets such a host point the build at real disk without editing
# this script; CI's disk-backed /tmp is unaffected either way.
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/ac_kasan_boot.XXXXXXXX")"
KDIR="$WORKDIR/linux-$KVER"
# Written directly here, not under $WORKDIR: the EXIT trap below deletes
# $WORKDIR on every exit path, including a mid-run cancellation (CI's
# timeout-minutes, or a local Ctrl-C) -- a log that only reached its
# final home via a post-vng `cp` would be lost in exactly the cases
# where the partial output matters most for diagnosis.
# PID suffix so concurrent invocations (local run + CI, future parallel
# matrix) don't overwrite each other's console log mid-write.
CONSOLE_LOG="$REPO_ROOT/kasan-console-$$.log"

cleanup() {
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "== fetching linux-$KVER =="
# Download to a file with retries rather than piping straight into tar:
# a real HTTP/2 PROTOCOL_ERROR from cdn.kernel.org has been observed
# mid-transfer in practice, and curl's default retry logic doesn't cover
# it (only clear-cut connect/timeout failures). Piping a retried request
# into a live pipe is also a correctness risk on its own -- a retry
# re-emits the full file from byte 0, landing after whatever partial
# bytes the failed first attempt already wrote, corrupting the archive
# instead of just failing loudly.
curl -fsSL --retry 5 --retry-delay 3 --retry-all-errors \
    -o "$WORKDIR/linux-$KVER.tar.xz" \
    "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$KVER.tar.xz"
tar -xJf "$WORKDIR/linux-$KVER.tar.xz" -C "$WORKDIR"
rm -f "$WORKDIR/linux-$KVER.tar.xz"

echo "== configuring: defconfig + KASAN/lockdep debug fragment =="
# ARM64-only project (x86-64 lives in the sibling anticheat_x86-64
# repo): always build an arm64 tree. On a non-ARM host that means
# cross-compiling (needs aarch64-linux-gnu-gcc); natively on ARM64 the
# empty prefix is a plain native build. Exported so every make below --
# including the module/daemon builds further down -- inherits it.
KARCH=arm64
CROSS_COMPILE=
case "$(uname -m)" in
    aarch64|arm64) ;;
    *)             CROSS_COMPILE=aarch64-linux-gnu- ;;
esac
export ARCH="$KARCH" CROSS_COMPILE
make -C "$KDIR" defconfig

# Generic KASAN (not SW/HW tags -- this targets a plain QEMU guest with
# no MTE/tag-capable hardware involved) + full lockdep validation.
# CONFIG_FRAME_WARN=0 because KASAN's redzones legitimately inflate stack
# frame sizes past the default warning threshold; that's expected
# instrumentation overhead, not a bug in this module's own code.
#
# scripts/config, not scripts/kconfig/merge_config.sh: the same tool
# ci.yml's own module job already uses (for MODULE_SIG/MODULE_SIG_SHA256)
# and has a real, verified-working track record in this exact CI
# environment. merge_config.sh's own internal `make ... alldefconfig`
# step failed here ("No rule to make target 'alldefconfig'") on a real
# run -- not worth chasing when there's already a proven alternative.
"$KDIR/scripts/config" --file "$KDIR/.config" \
    --enable KASAN \
    --enable KASAN_GENERIC \
    --enable KASAN_INLINE \
    --enable LOCKDEP \
    --enable PROVE_LOCKING \
    --enable DEBUG_ATOMIC_SLEEP \
    --set-val FRAME_WARN 0
make -C "$KDIR" olddefconfig

# scripts/config --enable doesn't fail the build if a requested symbol
# silently didn't stick (e.g. a missing dependency) -- verify explicitly
# rather than discovering a plain, uninstrumented boot later via absence
# of any KASAN output at all.
for sym in CONFIG_KASAN CONFIG_KASAN_GENERIC CONFIG_LOCKDEP CONFIG_PROVE_LOCKING; do
    grep -qx "${sym}=y" "$KDIR/.config" || {
        echo "FATAL: $sym did not stick after olddefconfig -- see $KDIR/.config" >&2
        exit 1
    }
done

echo "== building the kernel (full build, not modules_prepare -- this is slow) =="
make -C "$KDIR" -j"$(nproc)" all

echo "== building anticheat.ko against this tree =="
make -C "$REPO_ROOT" KDIR="$KDIR" module
test -s "$REPO_ROOT/anticheat.ko"

# Positive control for the module walk. The gate below is a dmesg grep
# for sanitizer findings, which only ever proves the walk didn't *fault*
# -- an ac_module_sane() that rejected every candidate unconditionally
# would sail through it while silently disabling the hidden-module
# detector entirely. A real CI run showed exactly that blind spot:
# "0 modules in kernel list", because the walk skips THIS_MODULE and
# anticheat.ko was the only module loaded, so the whole detector was
# being exercised against an empty list.
#
# Loading one throwaway GPL module before anticheat gives the walk
# something it is *required* to find, turning "didn't crash" into
# "didn't crash and still works". Generated here rather than committed
# as a source file: it is scaffolding for this script alone, and
# $WORKDIR is already mapped into the guest as $GUEST_WORK.
echo "== building the positive-control module =="
mkdir -p "$WORKDIR/dummy"
cat > "$WORKDIR/dummy/ac_dummy.c" <<'DUMMY_EOF'
// SPDX-License-Identifier: GPL-2.0
/* Positive control for scripts/kasan_boot_test.sh: a module that does
 * nothing except exist, so the anticheat module walk has a non-empty
 * list to find. Deliberately trivial -- it must not itself be capable
 * of tripping the sanitizer gate.
 */
#include <linux/module.h>
#include <linux/kernel.h>

static int __init ac_dummy_init(void)
{
	pr_info("ac_dummy: positive control loaded\n");
	return 0;
}

static void __exit ac_dummy_exit(void)
{
	pr_info("ac_dummy: positive control unloaded\n");
}

module_init(ac_dummy_init);
module_exit(ac_dummy_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KASAN boot test positive control");
DUMMY_EOF
printf 'obj-m := ac_dummy.o\n' > "$WORKDIR/dummy/Makefile"
make -C "$KDIR" M="$WORKDIR/dummy" modules
test -s "$WORKDIR/dummy/ac_dummy.ko"

echo "== building userspace (daemon + ioctl_fuzz) =="
# Cross-built when the guest differs from the host: these binaries execute
# *inside* the arm64 VM below, so host-cc output (x86_64 on an x86_64 build
# machine) would die there with "cannot execute binary file". Same CC=
# override ci.yml's own aarch64 cross-build check already uses; empty on a
# native ARM64 host (plain gcc). Command-line only, deliberately not
# exported: the environment would leak into the module build above, where
# an explicit CC overrides the Makefile's own Kbuild toolchain detection.
# Remove first: switching CC (host cc vs ${CROSS_COMPILE}gcc across runs)
# doesn't invalidate make's timestamps, so a stale binary for the wrong
# arch would otherwise survive and die in the guest with "cannot execute
# binary file" -- seen in a real run, where an x86_64 ioctl_fuzz from an
# earlier host build was reused. Both are gitignored build artifacts.
rm -f "$REPO_ROOT/anticheat" "$REPO_ROOT/test/ioctl_fuzz"
make -C "$REPO_ROOT" CC="${CROSS_COMPILE}gcc" CFLAGS="-O2 -Wall -Wextra -Werror" daemon ioctl-fuzz

# Guest-side paths and rootfs (see the vng invocation below for why):
# with a --root chroot the guest cannot see host paths, so the repo and
# the payload dir are mapped to fixed guest locations via
# --rodir guestpath=hostpath, and the payload below runs from $GUEST_REPO.
# The guest paths reuse /mnt and /srv: both exist empty in the Ubuntu
# cloud image, which matters -- virtme-init's rodir setup does
# `mkdir -p` for missing mountpoints, and as guest-root mapped to the
# unprivileged host user it cannot create directories under a root-owned
# chroot (which is also what vng's own provisioning produces), so any
# path needing creation would fail the mount and hang the boot.
GUEST_REPO="/mnt"
GUEST_WORK="/srv"
# Fresh arm64 chroot per run under $WORKDIR (auto-removed by the EXIT
# trap); set AC_ARM64_ROOT to reuse a prepared tree instead.
ROOTDIR="${AC_ARM64_ROOT:-$WORKDIR/arm64-root}"
ROOT_RELEASE="noble"

echo "== writing in-VM payload =="
PAYLOAD="$WORKDIR/in_vm_payload.sh"
cat > "$PAYLOAD" <<PAYLOAD_EOF
#!/bin/bash
# Runs as root inside the guest. $GUEST_REPO/$GUEST_WORK here are the
# *guest-side* paths mapped by the vng invocation's --rodir flags below.
#
# -x only, deliberately not -e: this module's own CLI legitimately
# returns nonzero for informational-not-broken outcomes (ENODEV when
# kprobe-based syscall-table discovery doesn't land one, a nonzero
# hidden-module/hook count when the detector fires, etc.) -- confirmed
# against real runs, where treating those as fatal aborted the payload
# before the real ioctl fuzz run or the dmesg dump ever executed. That
# matches this script's own stated pass/fail philosophy below: the
# dmesg grep is the gate, not any individual command's exit code (same
# reasoning ioctl_fuzz.c's own header comment already gives for why its
# exit code isn't the fuzz-harness gate either). Only insmod/rmmod get
# an explicit fatal check -- those failing means the payload itself is
# broken, not that the module reported something.
set -x
cd "$GUEST_REPO" || exit 1

# Loaded before anticheat so it is already in the kernel's module list
# when the walk runs, and stays loaded across the fuzz run below.
insmod $GUEST_WORK/dummy/ac_dummy.ko || { echo "AC_KASAN_BOOT: insmod ac_dummy failed"; exit 1; }

insmod ./anticheat.ko ac_verbose=1 || { echo "AC_KASAN_BOOT: insmod failed"; exit 1; }
sleep 0.3

./anticheat status
echo "AC_KASAN_BOOT: status exited \$?"

# Same smoke sequence diag.sh already uses interactively: protect a
# throwaway child, exercise the read paths, unprotect, before moving on
# to the actual fuzz stress below.
sleep 300 &
V=\$!
./anticheat protect --pid "\$V"
echo "AC_KASAN_BOOT: protect exited \$?"
sleep 0.3
./anticheat list
echo "AC_KASAN_BOOT: list exited \$?"
./anticheat events
echo "AC_KASAN_BOOT: events exited \$?"
./anticheat syscalls
echo "AC_KASAN_BOOT: syscalls exited \$?"
./anticheat scan --pid \$\$
echo "AC_KASAN_BOOT: scan exited \$?"
# The positive-control assertion. Emitted as a marker line because the
# host-side gate's only view into the guest is the console log.
MODS_OUT=\$(./anticheat modules 2>&1)
MODS_RC=\$?
echo "\$MODS_OUT"
echo "AC_KASAN_BOOT: modules exited \$MODS_RC"
if echo "\$MODS_OUT" | grep -qE '^[[:space:]]+ac_dummy[[:space:]]'; then
    echo "AC_KASAN_BOOT: POSITIVE CONTROL OK (module walk found ac_dummy)"
else
    echo "AC_KASAN_BOOT: POSITIVE CONTROL FAILED (module walk did not find ac_dummy)"
fi
./anticheat vmcheck
echo "AC_KASAN_BOOT: vmcheck exited \$?"
./anticheat unprotect --pid "\$V"
echo "AC_KASAN_BOOT: unprotect exited \$?"
kill "\$V" 2>/dev/null

echo "AC_KASAN_BOOT: running the real ioctl fuzz harness (full pointer-corruption fuzzing, no safe-pointers-only)"
./test/ioctl_fuzz $IOCTL_FUZZ_ITERATIONS $IOCTL_FUZZ_SEED
echo "AC_KASAN_BOOT: ioctl_fuzz exited \$? (informational -- see its own header comment on why this isn't the pass/fail gate)"

rmmod anticheat || { echo "AC_KASAN_BOOT: rmmod failed"; exit 1; }
rmmod ac_dummy || { echo "AC_KASAN_BOOT: rmmod ac_dummy failed"; exit 1; }

# vng's --exec channel only carries this script's own stdout/stderr, not
# the guest kernel's printk/dmesg ring buffer -- confirmed against a real
# run, where the captured console log contained this script's own trace
# and nothing else, meaning the BUG:/KASAN:/lockdep grep below was
# silently checking an empty haystack. Dump the ring buffer explicitly so
# it actually reaches $CONSOLE_LOG via the host-side tee.
echo "AC_KASAN_BOOT: dumping kernel ring buffer"
dmesg

echo "AC_KASAN_BOOT: payload complete"
PAYLOAD_EOF
chmod +x "$PAYLOAD"

echo "== booting via virtme-ng =="
# --memory bumped from vng's own default: KASAN's shadow memory roughly
# doubles effective memory pressure, and a too-small guest failing to
# boot at all would otherwise look identical to a genuine hang.
#
# `|| true`: vng's own exit code isn't the pass/fail signal here (same
# reasoning as the ioctl_fuzz harness's own exit code below) -- under
# `set -e`/pipefail a nonzero here would abort the script immediately,
# before the real grep-based checks below ever run. tee already writes
# $CONSOLE_LOG directly at its final ($REPO_ROOT) location as output
# arrives, so a cancellation partway through still leaves a real partial
# log on disk -- see the CONSOLE_LOG assignment above for why that's not
# just under $WORKDIR.
#
# --arch arm64, always: this is now an ARM64-only tree (see the KARCH
# block above), so the kernel just built under $KDIR is always an arm64
# tree regardless of host. vng infers the target arch from the *host*
# machine when --arch is omitted, not from the kernel tree it's handed --
# confirmed against a real run on an x86_64 runner, where the omission
# made it try (and fail: "cannot find qemu for x86_64") to boot with
# qemu-system-x86_64, which this script never installs. Note the value is
# `arm64`, not `aarch64`: vng takes Debian-style arch names (amd64, arm64,
# armhf, ...) -- `aarch64` is rejected with "unsupported architecture"
# and the guest never boots, which then surfaces misleadingly as the
# "payload never reported completion" FAIL below.
#
# --force-9p: vng prefers virtiofs for the guest root whenever a
# virtiofsd binary exists on the host, booting with root=ROOTFS
# rootfstype=virtiofs. The kernel built above is a plain defconfig plus
# the KASAN/lockdep fragment, and arm64 defconfig has CONFIG_VIRTIO_FS
# unset with CONFIG_FUSE_FS=m -- so that root simply cannot be mounted:
# "VFS: Cannot open root device \"ROOTFS\" ... error -19", then a panic
# in prepare_namespace() before init ever runs. Confirmed on a real run
# on a host with /usr/bin/virtiofsd installed. CI never hit this only
# because GitHub runners ship no virtiofsd and vng therefore fell back
# to 9p, which arm64 defconfig does build in (CONFIG_9P_FS=y,
# CONFIG_NET_9P_VIRTIO=y). Forcing 9p makes every host take the
# transport this kernel can actually mount, and makes a local run match
# CI's exactly. (Enabling FUSE_FS=y/VIRTIO_FS=y in the fragment above
# would be the faster-but-divergent alternative: virtiofs beats 9p under
# TCG, at the cost of local and CI runs no longer booting alike.)
#
# --verbose: this is what puts the *kernel console* into $CONSOLE_LOG.
# virtme only wires the console to the caller's stdout when fds 0/1/2
# are all reopenable via /proc/self/fd; the `| tee` below makes fd 1 a
# pipe, which fails that check (O_RDWR on a pipe), so without --verbose
# virtme takes its fallback path and sends the console to /dev/null,
# capturing only the payload's own stdout. That is not a theoretical
# loss: a boot that panics before the payload runs then leaves a
# completely empty log, while the FAIL below still tells the reader to
# go read it -- observed exactly once, and it cost a full rebuild to
# diagnose. With --verbose the fallback uses a stdio chardev for the
# console instead, so console and payload output both reach the tee.
#
# --append kasan_multi_shot: KASAN's report_enabled() (mm/kasan/report.c)
# is one-shot by default -- after the first report it silently drops
# every later one. For a 300-iteration fuzz run that means one early
# finding masks everything the rest of the run would have caught, and
# the grep below would report a single bug where there may be several.
#
# --root/--root-release: --arch on a non-ARM host additionally requires a
# chroot ("--arch used without --root", same never-boots outcome).
# $ROOTDIR doesn't exist on a fresh run, so vng provisions it from
# Ubuntu's arm64 cloud image for $ROOT_RELEASE (needs sudo, same as the
# CI job's apt step); an existing dir (see AC_ARM64_ROOT above) is used
# as-is. --rodir guestpath=hostpath maps the repo and payload dir to the
# fixed guest paths the payload runs from -- bare --rodir paths must live
# inside the chroot and are rejected otherwise.
vng --arch arm64 --root "$ROOTDIR" --root-release "$ROOT_RELEASE" \
    --force-9p --verbose --append kasan_multi_shot \
    --rodir "$GUEST_REPO=$REPO_ROOT" --rodir "$GUEST_WORK=$WORKDIR" \
    --run "$KDIR" --memory 3072M --exec "$GUEST_WORK/in_vm_payload.sh" 2>&1 | tee "$CONSOLE_LOG" || true

if ! grep -q "AC_KASAN_BOOT: payload complete" "$CONSOLE_LOG"; then
    echo "FAIL: payload never reported completion -- boot, insmod, or the in-VM script likely crashed/hung before finishing. See $CONSOLE_LOG." >&2
    exit 1
fi

echo "== checking captured console output for KASAN/lockdep/oops findings =="
# Pass/fail is this grep, not the ioctl_fuzz harness's own exit code --
# consistent with that harness's own header comment: its exit code only
# reflects whether *userspace* survived, not the kernel.
if grep -qE 'BUG:|KASAN:|WARNING:|Call Trace:|INFO: possible circular locking dependency|INFO: suspicious RCU usage|general protection fault|Oops:' "$CONSOLE_LOG"; then
    echo "FAIL: kernel-side finding detected in the console log above." >&2
    exit 1
fi

# Second gate, independent of the sanitizer grep above. That grep can
# only fail a walk that faults; it passes a walk that quietly finds
# nothing, which is what a regression in ac_module_sane()'s accept
# conditions would produce. Checked in both directions: an explicit
# FAILED marker, and an absent OK marker (payload died before reaching
# the assertion, ac_dummy never loaded, guest never booted) -- so the
# gate cannot be satisfied by the check simply not running.
if grep -q 'AC_KASAN_BOOT: POSITIVE CONTROL FAILED' "$CONSOLE_LOG"; then
    echo "FAIL: module walk did not find ac_dummy. The walk ran without faulting," >&2
    echo "      but found nothing it was required to find -- the hidden-module" >&2
    echo "      detector is disabled, not merely quiet. See the console log above." >&2
    exit 1
fi
if ! grep -q 'AC_KASAN_BOOT: POSITIVE CONTROL OK' "$CONSOLE_LOG"; then
    echo "FAIL: positive-control marker absent from the console log. The payload" >&2
    echo "      did not reach the module-walk assertion, so a clean sanitizer" >&2
    echo "      grep above proves nothing. See the console log above." >&2
    exit 1
fi

echo "PASS: kernel survived the real ioctl fuzz harness + CLI exercise under KASAN+lockdep with no findings"
echo "      (module walk verified against a live positive control)"
