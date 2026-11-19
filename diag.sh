#!/bin/bash
# diag.sh — root diagnostics for the anticheat module (run: sudo ./diag.sh)
# Shows which kprobes registered, the resolved text bounds, the syscall
# table discovery result, and the failing commands' real output.
set -u
cd "$(dirname "$0")" || exit 1

[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

# Everything this run creates, and only that, is torn down from the EXIT
# trap (issue #93): a mid-script exit must not leave the module loaded, the
# victim alive, or its protection registered -- and a module that was
# already loaded when we started is somebody's live anticheat, holding
# protected-process registrations and the boot-time syscall baseline, so it
# is never unloaded here.
LOADED_BY_US=0
P=""
V=""
C=""
CHILD_PIDFILE=""

# cleanup is invoked via trap below; shellcheck cannot always see that
# shellcheck disable=SC2317,SC2329
cleanup() {
    [ -n "$V" ] && ./anticheat unprotect --pid "$V" >/dev/null 2>&1
    [ -n "$P" ] && kill "$P" 2>/dev/null
    # The victim wrapper was spawned under job control, so $V is also its
    # process-group id: signalling -$V reaches the wrapper AND its sleep
    # child in one shot, even if we are interrupted before the pidfile below
    # was read (when $C would still be empty). One signal is not enough,
    # though: a TERM that lands between the victim's fork and exec can be
    # swallowed by the shell handler it inherited from this script, and the
    # wrapper then goes on to start its sleep child. So keep signalling the
    # group until it is empty (kill fails once no member is left; bash reaps
    # the exited leader itself), with a KILL as the backstop.
    if [ -n "$V" ]; then
        for _ in $(seq 1 40); do
            kill -TERM -- "-$V" 2>/dev/null || break
            sleep 0.05
        done
        kill -KILL -- "-$V" 2>/dev/null
    fi
    [ -n "$CHILD_PIDFILE" ] && rm -f "$CHILD_PIDFILE"
    if [ "$LOADED_BY_US" -eq 1 ]; then
        sleep 0.2
        rmmod anticheat 2>/dev/null
    fi
}

trap cleanup EXIT

echo "== environment =="
echo "kernel: $(uname -r) $(uname -v)"
echo "yama ptrace_scope: $(cat /proc/sys/kernel/yama/ptrace_scope)"
echo "kptr_restrict:     $(cat /proc/sys/kernel/kptr_restrict)"
free -m | head -2

echo
echo "== load module (verbose) =="
if [ -d /sys/module/anticheat ]; then
    echo "note: anticheat is already loaded; diagnosing it in place and leaving it loaded" >&2
    echo "      (not reloaded with ac_verbose=1, so the init log below may be sparse or stale)" >&2
else
    # Claim ownership BEFORE insmod runs: a SIGTERM while insmod is in
    # flight, or right after it returns, must still reach rmmod in cleanup.
    # (rmmod on a module that never loaded just fails quietly.) If insmod
    # itself fails, nothing of ours is loaded -- the kernel rolls a failed
    # load back -- so drop the claim: cleanup then must not rmmod, which
    # could otherwise unload a copy somebody else loaded in the meantime.
    LOADED_BY_US=1
    insmod ./anticheat.ko ac_verbose=1 || { LOADED_BY_US=0; echo "INSMOD FAILED"; exit 1; }
    sleep 0.3
fi

echo
echo "== dmesg: module init =="
dmesg | tail -80 | grep -iE "anticheat|probe|kprobe|syscall|text bounds" | tail -25

echo
echo "== status =="
./anticheat status

echo
echo "== control: root ptrace on a NON-protected process =="
sleep 300 & P=$!
timeout 2 strace -p $P -e trace=none >/dev/null 2>&1; rc=$?
kill $P 2>/dev/null
P=""
echo "strace -p non-protected rc=$rc   (0 = attach worked, 124 = hung/timed out)"

echo
echo "== protected process + attach =="
# mktemp, not a fixed /tmp/ac_diag_child path: a predictable name in
# world-writable /tmp is a symlink-race hazard for a script run as root.
# Checked and trap-cleaned rather than assumed to succeed: this runs
# under `set -u` only (no `set -e`), so an unchecked mktemp/cat failure
# here wouldn't abort the script -- it would silently continue with an
# empty pidfile path or an empty $C, producing a diagnostic run that
# looks like it worked but didn't actually test fork inheritance.
CHILD_PIDFILE="$(mktemp)" || { echo "mktemp failed"; exit 1; }
# Job control (set -m) makes bash itself put the wrapper in its own process
# group (PGID == $V) at fork time, from the parent side -- so the group
# exists the moment `V=$!` is set, with no dependency on the child getting
# far enough to call setsid() itself. Cleanup can then kill the wrapper and
# its child together via `kill -- -$V`, independent of when (or whether) the
# child pid is read below. Turned back off straight after the spawn so the
# rest of the script gets no job-status noise.
set -m
bash -c 'sleep 300 & echo $! > "$1"; wait' _ "$CHILD_PIDFILE" & V=$!
set +m
./anticheat protect --pid $V
sleep 0.5
C=$(cat "$CHILD_PIDFILE")
if [ -z "$C" ]; then
    echo "warning: could not read child pid from $CHILD_PIDFILE" >&2
fi
rm -f "$CHILD_PIDFILE"
echo "victim=$V child=$C"
timeout 2 strace -p $V -e trace=none >/dev/null 2>&1; rc=$?
echo "strace -p protected rc=$rc"
echo "list:"
./anticheat list

echo
echo "== events (should contain FORK + PTRACE-DENIED) =="
./anticheat events; echo "events rc=$?"

echo
echo "== syscalls =="
./anticheat syscalls; echo "rc=$?"

echo
echo "== kallsyms cross-check (root) =="
grep -E " (__arm64_sys_read|__arm64_sys_write|sys_call_table)$" /proc/kallsyms

echo
echo "== dmesg: after load (discovery diagnostics) =="
dmesg | tail -60 | grep -iE "anticheat" | tail -12

echo
echo "== scan (RWX) — expect diagnostics on failure =="
./anticheat scan --pid $$; echo "scan rc=$?"

echo
echo "== modules =="
./anticheat modules; echo "rc=$?"

echo
echo "== dmesg: post-attempt =="
dmesg | tail -30 | grep -iE "anticheat|probe|kprobe|ptrace|kill" | tail -15

echo "== done =="
