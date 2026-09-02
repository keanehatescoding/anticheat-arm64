# kernel-anticheat: kernel module + userspace daemon
#
#   make            build both
#   make module     build anticheat.ko only
#   make daemon     build the userspace binary only
#   make clean
#   sudo make install         (binary -> /usr/local/sbin, module -> /lib/modules/.../extra)
#   sudo make uninstall
#   make install-deck         (SteamOS / immutable distros — see below)
#   make uninstall-deck
#
# Kernel module build requires linux headers for the running kernel:
#   /lib/modules/$(uname -r)/build
#
# For a distro with automatic kernel-update rebuilds and Secure Boot signing,
# use DKMS instead of `make install` — see scripts/dkms-install.sh.
#
# `install`/`uninstall` write to /usr/local and /lib/modules, which is fine
# on a normal distro but is read-only (or wiped on the next OTA update) on
# SteamOS and other immutable/atomic-image systems. `install-deck` instead
# stages everything under a user-writable directory and loads the module
# with plain `insmod` (which only needs a valid .ko for the running kernel,
# unlike `modprobe`, which needs /lib/modules to be writable and depmod'd).
# This does NOT survive a kernel update by itself — rebuild and reload after
# one, since DKMS's auto-rebuild-on-kernel-postinst hook assumes a distro
# where /lib/modules is writable.

KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build
PWD  := $(shell pwd)
CC   ?= gcc
CFLAGS ?= -O2 -Wall -Wextra
LDFLAGS ?=
DECK_PREFIX ?= $(HOME)/.local/share/anticheat

# If the running kernel was built with clang/LLVM, build the module with
# the same toolchain (Kbuild flags are not compatible with gcc).
ifeq ($(shell grep -q '^CONFIG_CC_IS_CLANG=y' $(KDIR)/.config 2>/dev/null && echo 1 || echo 0),1)
LLVM := 1
endif

obj-m += anticheat.o
anticheat-objs := src/anticheat_module.o src/sha256.o

all: module daemon

module:
	$(MAKE) -C $(KDIR) M=$(PWD) LLVM=$(LLVM) modules

daemon: src/anticheat_daemon.c src/sha256.c src/sha256.h src/anticheat.h
	$(CC) $(CFLAGS) -o anticheat src/anticheat_daemon.c src/sha256.c $(LDFLAGS)

mock: test/libmock_anticheat.so

test/libmock_anticheat.so: test/mock_anticheat.c src/anticheat.h
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $< -ldl $(LDFLAGS)

# real (non-mock) live test helper: proves ac_ioctl() rechecks
# CAP_SYS_ADMIN by opening /dev/anticheat as root, dropping privileges,
# and confirming the ioctl is rejected. Needs the module loaded and root
# to run -- see test.sh.
priv-drop-test: test/priv_drop_test

test/priv_drop_test: test/priv_drop_test.c src/anticheat.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# render-hook live test helper: self-hooks vkQueuePresentKHR in its own
# process (harmless -- the patched bytes are never called) so `scan
# --check-hooks` has a real, known-tampered target to detect. Needs root
# to run the scan against it (uses the device) -- see test.sh.
render-hook-test: test/render_hook_test

test/render_hook_test: test/render_hook_test.c src/anticheat.h
	$(CC) $(CFLAGS) -o $@ $< -ldl $(LDFLAGS)

# mount-namespace live test helper: dlopen()s an explicit path inside a
# private mount namespace test.sh sets up, so the render-hook check's
# /proc/<pid>/root/ resolution can be proven against a real target whose
# view of a path differs from the host's. Needs root (mount namespaces,
# the module) -- see test.sh.
mount-ns-test: test/mount_ns_probe

test/mount_ns_probe: test/mount_ns_probe.c
	$(CC) $(CFLAGS) -o $@ $< -ldl $(LDFLAGS)

# anon-exec/JIT-allowlist live test helper: on SIGUSR1, maps one new
# anonymous executable page in itself (the same signal a JIT or injected
# shellcode produces) so the --jit allowlist's severity-downgrade path
# can be proven against a real, controllable growth event. Needs root to
# run the scan against it -- see test.sh.
anon-exec-test: test/anon_exec_test

test/anon_exec_test: test/anon_exec_test.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# thread-exit-migration live test helper: single leader thread + one
# worker, protected by the leader's tid, then the leader alone exits via
# pthread_exit() while the worker keeps running -- exercises
# ac_exit_pre()'s registry-migration path (ac_replace_prot_task()). Needs
# root and the module loaded -- see test.sh.
thread-exit-migration-test: test/thread_exit_migration_test

test/thread_exit_migration_test: test/thread_exit_migration_test.c src/anticheat.h
	$(CC) $(CFLAGS) -pthread -o $@ $< $(LDFLAGS)

# thread-spawn-after-protect live test helper: a pthread_create() by an
# already-protected thread must not get its own registry slot -- exercises
# ac_clone_ret()'s CLONE_THREAD dedup (guards against duplicate registry
# entries / AC_PROT_MAX exhaustion). Needs root and the module loaded --
# see test.sh.
thread-spawn-after-protect-test: test/thread_spawn_after_protect_test

test/thread_spawn_after_protect_test: test/thread_spawn_after_protect_test.c src/anticheat.h
	$(CC) $(CFLAGS) -pthread -o $@ $< $(LDFLAGS)

# ioctl fuzz harness: hammers every AC_IOCTL_* with malformed sizes,
# boundary values, and null/wild/unmapped pointers -- the actual attack
# surface any local process holding an open fd can reach. Against the
# mock this only proves the harness itself doesn't crash (see its own
# header comment); the real run is against a loaded module, as root,
# watching dmesg -- see README's "ioctl fuzzing" section.
ioctl-fuzz: test/ioctl_fuzz

test/ioctl_fuzz: test/ioctl_fuzz.c src/anticheat.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# baseline-file unit test (#51): pulls anticheat_daemon.c in directly (no
# kernel/mock scan involved -- baseline_save_record()/baseline_load_records()/
# baseline_find_record() are pure file I/O) and proves a second (inode,
# offset) segment saved to the same path's baseline file doesn't clobber
# the first. See test/baseline_test.c.
baseline-test: test/baseline_test
	./test/baseline_test

test/baseline_test: test/baseline_test.c src/anticheat_daemon.c src/sha256.c src/sha256.h src/anticheat.h
	$(CC) $(CFLAGS) -o $@ test/baseline_test.c src/sha256.c $(LDFLAGS)

# run the daemon CLI against the userspace mock (no kernel module, no root)
test-mock: mock daemon
	./test/mock_test.sh

# CI entry point: rebuild all userspace with warnings-as-errors and run the
# full no-root test suite.  (The kernel module build needs real kernel
# headers and is exercised separately in CI against a prepared kernel tree.)
ci:
	$(MAKE) clean
	$(MAKE) CFLAGS="-O2 -Wall -Wextra -Werror" daemon mock baseline-test
	./test/mock_test.sh

clean:
	@if [ -d $(KDIR) ]; then $(MAKE) -C $(KDIR) M=$(PWD) clean; fi
	rm -f anticheat test/libmock_anticheat.so test/priv_drop_test test/render_hook_test test/mount_ns_probe test/anon_exec_test test/thread_exit_migration_test test/thread_spawn_after_protect_test test/ioctl_fuzz test/baseline_test

install: all
	install -D -m 0755 anticheat /usr/local/sbin/anticheat
	install -D -m 0644 anticheat.ko /lib/modules/$(KVER)/extra/anticheat.ko
	install -d -m 0755 /var/lib/anticheat/baselines
	depmod -a
	@echo "installed. load with: sudo modprobe anticheat  (or insmod ./anticheat.ko)"

uninstall:
	rm -f /usr/local/sbin/anticheat
	rm -f /lib/modules/$(KVER)/extra/anticheat.ko
	depmod -a

# SteamOS / immutable-distro install: everything lives under $(DECK_PREFIX)
# (default: ~/.local/share/anticheat), which survives OTA image updates
# because it's in the user's home, not the read-only system image. No
# /lib/modules write, no depmod — the module is loaded directly by path.
install-deck: all
	install -D -m 0755 anticheat $(DECK_PREFIX)/bin/anticheat
	install -D -m 0644 anticheat.ko $(DECK_PREFIX)/anticheat.ko
	install -d -m 0755 $(DECK_PREFIX)/baselines
	@echo "installed under $(DECK_PREFIX)"
	@echo "load with: sudo insmod $(DECK_PREFIX)/anticheat.ko"
	@echo "run the daemon with: sudo AC_BASELINE_DIR=$(DECK_PREFIX)/baselines $(DECK_PREFIX)/bin/anticheat start"

uninstall-deck:
	rm -rf $(DECK_PREFIX)

.PHONY: all module daemon mock test-mock priv-drop-test render-hook-test mount-ns-test thread-exit-migration-test thread-spawn-after-protect-test ioctl-fuzz baseline-test ci clean install uninstall install-deck uninstall-deck
