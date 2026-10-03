#!/bin/bash
# test-local.sh -- run this repo's tests on a developer machine, picking
# the right path for the host architecture. Also what the git hooks in
# .githooks/ call (enable them with `make hooks`).
#
#   scripts/test-local.sh --lint    seconds: shellcheck plus a -Werror daemon
#                                   build, native and aarch64 (pre-commit)
#   scripts/test-local.sh --quick   `make ci`: userspace build, mock suite,
#                                   lint, aarch64 cross-build (no root)
#   scripts/test-local.sh --module  the real-module test only:
#                                     aarch64 host -> build anticheat.ko for
#                                       the running kernel and run ./test.sh
#                                       as root (via pkexec)
#                                     x86_64 host  -> boot the arm64 KASAN VM
#                                       (scripts/kasan_boot_test.sh) under
#                                       QEMU and run the module tests there
#   scripts/test-local.sh --all     --quick, then --module (the default)
#
# The x86_64 path keeps its kernel build and arm64 rootfs in
# ${AC_KASAN_CACHE:-~/.cache/anticheat-kasan}: the first run builds a
# KASAN kernel (~30 min, ~20 GB), later runs only rebuild what changed and
# boot it (a few minutes). The rootfs is a one-time root-owned extract of
# Ubuntu's arm64 cloud image, done through pkexec.
#
# Environment:
#   AC_KASAN_CACHE         cache dir for the x86_64 path (see above)
#   IOCTL_FUZZ_ITERATIONS  fuzz iterations in the VM (default 50, as CI's
#                          short seed; the nightly uses 300)
#   AC_REQUIRE_WARM_CACHE  =1: on x86_64, skip --module with a notice
#                          instead of starting a cold ~30 min kernel build
#                          (the pre-push hook sets this)
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1
REPO_ROOT="$PWD"

MODE=all
case "${1:-}" in
    ""|--all) MODE=all ;;
    --lint)   MODE=lint ;;
    --quick)  MODE=quick ;;
    --module) MODE=module ;;
    -h|--help) sed -n '2,31p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "usage: $0 [--lint|--quick|--module|--all]" >&2; exit 2 ;;
esac

say() { printf '\033[1;34m[test-local]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[test-local]\033[0m %s\n' "$*" >&2; exit 1; }

run_lint() {
    say "shellcheck + -Werror daemon build (native and aarch64)"
    if command -v shellcheck >/dev/null 2>&1; then
        git ls-files '*.sh' '.githooks/*' | xargs shellcheck
    else
        say "warning: shellcheck not installed -- skipping shell checks"
    fi
    # rm between builds: make doesn't track CC/CFLAGS (same as `make ci`)
    rm -f anticheat
    if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
        make -s CC=aarch64-linux-gnu-gcc CFLAGS="-O2 -Wall -Wextra -Werror" daemon
        rm -f anticheat
    fi
    make -s CFLAGS="-O2 -Wall -Wextra -Werror" daemon
}

run_quick() {
    say "make ci (userspace build, mock suite, lint, aarch64 cross-build)"
    make ci
}

need() {
    local missing=()
    for t in "$@"; do command -v "$t" >/dev/null 2>&1 || missing+=("$t"); done
    [ ${#missing[@]} -eq 0 ] || die "missing tools: ${missing[*]}"
}

run_module_native() {
    need pkexec make gcc
    local kbuild
    kbuild="/lib/modules/$(uname -r)/build"
    [ -d "$kbuild" ] || die "no kernel headers at $kbuild (install the headers package for $(uname -r))"
    say "aarch64 host: building anticheat.ko for $(uname -r) and the test helpers"
    make all
    say "running ./test.sh as root (pkexec) -- this loads the module into the running kernel"
    pkexec "$REPO_ROOT/test.sh"
}

# Same rootfs vng would provision itself (virtme_ng/run.py create_root():
# Ubuntu's <release>-server-cloudimg-<arch>-root.tar.xz), but extracted
# through pkexec rather than vng's hardcoded sudo. Downloaded as the user
# first, so only the extract needs root.
ensure_arm64_root() {
    local root="$1" release=noble tarball
    [ -d "$root/etc" ] && return 0
    tarball="$AC_KASAN_CACHE/$release-server-cloudimg-arm64-root.tar.xz"
    if [ ! -s "$tarball" ]; then
        say "downloading the Ubuntu $release arm64 rootfs (one-time)"
        curl -fSL --retry 5 --retry-delay 3 --retry-all-errors -o "$tarball.part" \
            "https://cloud-images.ubuntu.com/$release/current/$release-server-cloudimg-arm64-root.tar.xz"
        mv "$tarball.part" "$tarball"
    fi
    say "extracting the arm64 rootfs to $root as root (pkexec, one-time)"
    # shellcheck disable=SC2016  # $1/$2 are expanded by the root shell
    pkexec /bin/sh -c 'mkdir -p "$1" && tar -xJf "$2" -C "$1"' sh "$root" "$tarball" ||
        die "rootfs extract failed"
    [ -d "$root/etc" ] || die "rootfs extract left no $root/etc"
    rm -f "$tarball"
}

run_module_vm() {
    need qemu-system-aarch64 vng aarch64-linux-gnu-gcc curl flock make
    AC_KASAN_CACHE="${AC_KASAN_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/anticheat-kasan}"
    mkdir -p "$AC_KASAN_CACHE"
    if [ "${AC_REQUIRE_WARM_CACHE:-0}" = 1 ] && [ ! -f "$AC_KASAN_CACHE/linux-6.12/vmlinux" ]; then
        say "x86_64 host: no cached KASAN kernel in $AC_KASAN_CACHE yet; skipping the VM run."
        say "  Build it once (~30 min): scripts/test-local.sh --module"
        return 0
    fi
    ensure_arm64_root "$AC_KASAN_CACHE/arm64-root"
    say "x86_64 host: booting the arm64 KASAN VM under QEMU (cache: $AC_KASAN_CACHE)"
    export AC_KASAN_CACHE AC_ARM64_ROOT="$AC_KASAN_CACHE/arm64-root"
    IOCTL_FUZZ_ITERATIONS="${IOCTL_FUZZ_ITERATIONS:-50}" ./scripts/kasan_boot_test.sh
}

run_module() {
    case "$(uname -m)" in
        aarch64|arm64) run_module_native ;;
        x86_64)        run_module_vm ;;
        *)             die "unsupported host architecture $(uname -m) (expected aarch64 or x86_64)" ;;
    esac
}

case "$MODE" in
    lint)   run_lint ;;
    quick)  run_quick ;;
    module) run_module ;;
    all)    run_quick; run_module ;;
esac
say "done ($MODE)"
