#!/bin/bash
# diag.sh — root diagnostics for the anticheat module (run: sudo ./diag.sh)
# Shows which kprobes registered, the resolved text bounds, the syscall
# table discovery result, and the failing commands' real output.
set -u
cd "$(dirname "$0")" || exit 1

[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

# Serialize concurrent diagnostic runs (issue thread): module loading,
# diagnostics, protection checks and cleanup must not overlap, otherwise one
# run can unload the module while another is still using it.
# AC_DIAG_LOCKFILE exists only so test/diag_test.py can run unprivileged;
# the default is what a real run uses.
LOCKFILE="${AC_DIAG_LOCKFILE:-/run/anticheat-diag.lock}"
exec 9>"$LOCKFILE" || { echo "lock open failed"; exit 1; }
flock -x 9 || { echo "lock failed"; exit 1; }

# Everything this run creates, and only that, is torn down from the EXIT
# trap (issue #93): a mid-script exit must not leave the module loaded, the
# victim alive, or its protection registered -- and a module that was
# already loaded when we started is somebody's live anticheat, holding
# protected-process registrations and the boot-time syscall baseline, so it
# is never unloaded here.
LOADED_BY_US=0
MODULE_INSTANCE=""
P=""
V=""
C=""
CHILD_PIDFILE=""

# cleanup is invoked via trap below; shellcheck cannot always see that
# shellcheck disable=SC2317,SC2329
cleanup() {
    rc=$?
    if [ -n "$V" ]; then
        if ! ./anticheat unprotect --pid "$V" >/dev/null 2>&1; then
            echo "warning: unprotect --pid $V failed; cleanup not yet confirmed" >&2
        fi
    fi
    if [ -n "$P" ]; then
        kill "$P" 2>/dev/null
        kill -CONT "$P" 2>/dev/null
        wait "$P" 2>/dev/null
        P=""
    fi
    if [ -n "$V" ]; then
        # The victim wrapper was spawned under job control, so $V is also its
        # process-group id: signalling -$V reaches the wrapper AND its sleep
        # child in one shot, even if we are interrupted before the pidfile
        # was read (when $C is still empty) -- no pgrep/pidfile lookup, and no
        # window where a recycled pid could be signalled. One signal is not
        # enough, though: a TERM that lands between the victim's fork and exec
        # can be swallowed by the shell handler it inherited from this
        # script, and the wrapper then goes on to start its sleep child. So
        # keep signalling the group until it is empty (kill fails once no
        # member is left), CONT-ing it each round in case it is stopped, with
        # a KILL as the backstop. Signalling $V itself first covers the case
        # where the group does not exist yet or job control was unavailable.
        kill "$V" 2>/dev/null
        kill -CONT "$V" 2>/dev/null
        for _ in $(seq 1 40); do
            kill -TERM -- "-$V" 2>/dev/null || break
            kill -CONT -- "-$V" 2>/dev/null
            sleep 0.05
        done
        kill -KILL -- "-$V" 2>/dev/null
        wait "$V" 2>/dev/null
    fi
    [ -n "$CHILD_PIDFILE" ] && rm -f "$CHILD_PIDFILE"
    CHILD_PIDFILE=""
    if [ "$LOADED_BY_US" -eq 1 ]; then
        sleep 0.2
        # Normally the instance recorded right after insmod must still be the
        # one loaded. If we were interrupted before it could be recorded
        # (during or just after insmod) identity cannot be verified: the
        # module was absent when we started and we hold the diag lock, so
        # unload whatever is present now -- and nothing if it never appeared.
        _unload=0
        if [ -n "$MODULE_INSTANCE" ]; then
            _current_instance="$(stat -c '%d:%i' /sys/module/anticheat 2>/dev/null || true)"
            if [ "$_current_instance" = "$MODULE_INSTANCE" ]; then
                _unload=1
            else
                echo "warning: anticheat module was replaced during this run; not unloading" >&2
            fi
        elif [ -d /sys/module/anticheat ]; then
            _unload=1
        fi
        if [ "$_unload" -eq 1 ] && ! rmmod anticheat 2>/dev/null; then
            echo "error: rmmod anticheat failed; module may still be loaded" >&2
            [ "$rc" -eq 0 ] && rc=1
        fi
    fi
    exec 9>&- 2>/dev/null || true
    exit "$rc"
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
    # Claim ownership BEFORE insmod runs: a SIGTERM while insmod is in flight,
    # or right after it returns but before the instance is recorded below,
    # must still reach the unload in cleanup. If insmod itself fails the
    # kernel rolls the load back, so drop the claim: cleanup must not unload
    # a copy somebody else loaded in the meantime.
    LOADED_BY_US=1
    if insmod ./anticheat.ko ac_verbose=1; then
        MODULE_INSTANCE="$(stat -c '%d:%i' /sys/module/anticheat 2>/dev/null || true)"
        sleep 0.3
    else
        LOADED_BY_US=0
        echo "INSMOD FAILED"
        exit 1
    fi
fi

echo
echo "== dmesg: module init =="
dmesg | tail -80 | grep -iE "anticheat|probe|kprobe|syscall|text bounds" | tail -25

echo
echo "== status =="
./anticheat status

echo
echo "== control: root ptrace on a NON-protected process =="
sleep 300 9>&- & P=$!
timeout 2 strace -p $P -e trace=none >/dev/null 2>&1; rc=$?
kill "$P" 2>/dev/null
kill -CONT "$P" 2>/dev/null
wait "$P" 2>/dev/null
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
# exists the moment `V=$!` is set and cleanup can kill the wrapper and its
# child together via `kill -- -$V`, independent of when (or whether) the
# child pid is read below. Turned back off straight after the spawn. Fd 9
# (the diag lock) is closed for the child so it can never outlive the run
# holding the lock.
set -m
bash -c 'trap "kill %1 2>/dev/null" EXIT TERM INT; sleep 300 & echo $! > "$1"; wait' _ "$CHILD_PIDFILE" 9>&- & V=$!
set +m
./anticheat protect --pid $V
sleep 0.5
C=$(cat "$CHILD_PIDFILE")
if [ -z "$C" ]; then
    echo "warning: could not read child pid from $CHILD_PIDFILE" >&2
fi
rm -f "$CHILD_PIDFILE"
CHILD_PIDFILE=""
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
