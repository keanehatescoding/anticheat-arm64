#!/bin/sh
# dkms-build.sh — DKMS build entry point for the anticheat kernel module.
#
# Why this exists (see issue #36): dkms.conf's MAKE[0] invokes Kbuild
# directly (`make -C ${kernel_source_dir} M=... modules`) and never goes
# through this repo's top-level Makefile, so the Makefile's clang/LLVM vs
# gcc autodetection (Makefile:36-93) never runs for any DKMS-based install
# (scripts/dkms-install.sh, the AUR/.deb/.rpm packages). On a target
# kernel built with clang, a DKMS build would silently default to gcc and
# fail at insmod with "Invalid module format" — exactly the failure the
# Makefile logic was written to avoid.
#
# This script ports that logic to the DKMS path: it inspects the *target*
# kernel's own .config (the first argument, DKMS's ${kernel_source_dir})
# for CONFIG_CC_IS_CLANG / CONFIG_AS_IS_LLVM / CONFIG_LD_IS_LLD and
# forwards the matching LLVM=1 or CC=clang to Kbuild. Explicit LLVM= or
# CC= in the environment always wins over autodetection (same rule as the
# Makefile: lets an admin override a mixed or unusual toolchain by hand).
#
# Usage (invoked by dkms.conf, not by hand):
#   dkms-build.sh <kernel_source_dir> <build_dir>
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <kernel_source_dir> <build_dir>" >&2
    exit 2
fi

KDIR="$1"
BUILD="$2"

LLVM_ARG=""
CC_ARG=""

# Explicit environment overrides win — same rule as the Makefile.
if [ -n "${LLVM-}" ] || [ -n "${CC-}" ]; then
    [ -n "${LLVM-}" ] && LLVM_ARG="LLVM=${LLVM}"
    [ -n "${CC-}" ] && CC_ARG="CC=${CC}"
else
    KCONFIG="${KDIR}/.config"
    if [ -r "$KCONFIG" ]; then
        if grep -q '^CONFIG_CC_IS_CLANG=y' "$KCONFIG" 2>/dev/null; then
            if grep -q '^CONFIG_AS_IS_LLVM=y' "$KCONFIG" 2>/dev/null && \
               grep -q '^CONFIG_LD_IS_LLD=y' "$KCONFIG" 2>/dev/null; then
                LLVM_ARG="LLVM=1"
            else
                # Mixed toolchain (clang CC with GNU as/ld): full
                # LLVM=1 would pick the wrong binutils, so pass CC
                # alone — same distinction as the Makefile.
                CC_ARG="CC=clang"
            fi
        fi
    else
        # No readable target .config. Unlike the Makefile there is no
        # /proc/version fallback here on purpose: /proc/version describes
        # the *running* kernel, while DKMS routinely builds for some other
        # installed kernel (postinst hook, AUTOINSTALL on upgrade), so the
        # host string says nothing about the target. Default to gcc and
        # say so loudly; a clang-kernel user with stripped headers must
        # export LLVM=1 (full LLVM) or CC=clang (mixed) explicitly.
        echo "dkms-build.sh: warning: ${KCONFIG} not readable -- defaulting to gcc; if the target kernel was built with clang, export LLVM=1 or CC=clang (see dkms.conf)" >&2
    fi
fi

# shellcheck disable=SC2086
exec make -C "$KDIR" M="$BUILD" $LLVM_ARG $CC_ARG modules
