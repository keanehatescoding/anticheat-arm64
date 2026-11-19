#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Isolated diag.sh regression tests. Run: python3 test/diag_test.py.

Uses Bash command stubs, never root, a kernel module, ptrace, or host signals.
Only the script's module-existence check is redirected to a fixture directory;
all other tests and the diagnostic script itself run unchanged.
"""
import os
from pathlib import Path
import shutil
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

# BASH_ENV installs stubs before diag.sh starts. Background jobs are short-lived
# stubs too: kill records its arguments without sending any signals to the host.
STUBS = r'''
record() { printf '%s\n' "$*" >> "$CASE_DIR/calls"; }
id() { record "id $*"; echo "$TEST_UID"; }
[() {
    if builtin [ "$#" -eq 3 ] && builtin [ "$1" = -d ] &&
       builtin [ "$2" = /sys/module/anticheat ]; then
        builtin [ "$TEST_LOADED" = 1 ]; return
    fi
    builtin [ "$@"
}
uname() { record "uname $*"; echo fixture; }
free() { echo fixture; }
dmesg() { echo 'anticheat probe fixture'; }
grep() {
    if builtin [ "${2:-}" = /proc/kallsyms ]; then return 0; fi
    command grep "$@"
}
insmod() {
    record "insmod $*"
    case "$TEST_FAILURE" in
        insmod) return 1 ;;
        during-insmod) exit 73 ;;
    esac
}
rmmod() { record "rmmod $*"; return "$TEST_RMMOD_RC"; }
sleep() {
    if builtin [ "$1" = 0.5 ] && builtin [ "$TEST_FAILURE" = before-child-read ]; then
        exit 73
    fi
    # Ensure the wrapper writes the pidfile before the parent reads it.
    if builtin [ "$1" = 0.5 ]; then
        for ((i=0; i<100; i++)); do
            builtin [ -s "$CASE_DIR/child.pid" ] && return 0
            command sleep 0.001
        done
        return 1
    fi
    return 0
}
mktemp() {
    record mktemp
    builtin [ "$TEST_FAILURE" = mktemp ] && return 1
    : > "$CASE_DIR/child.pid"
    echo "$CASE_DIR/child.pid"
}
bash() {
    # Model the wrapper's child pid without creating a long-lived process.
    echo 987654 > "$CASE_DIR/child.pid"
}
timeout() {
    record "timeout $*"
    builtin [ "$TEST_FAILURE" = control ] && exit 73
    return 124
}
kill() {
    record "kill $*"
    # Exercise both a group disappearing after TERM and the KILL backstop.
    if builtin [ "${1:-}" = -TERM ]; then
        builtin [ "$TEST_STUBBORN" = 1 ]; return
    fi
    return 0
}
'''

CLI = r'''#!/bin/bash
printf 'cli %s\n' "$*" >> "$CASE_DIR/calls"
# A diagnostic command failing must still allow the final cleanup.
if [ "$TEST_FAILURE" = cli ]; then exit 1; fi
'''


def run_case(**options):
    with tempfile.TemporaryDirectory(prefix="ac-diag-test-") as directory:
        case = Path(directory)
        shutil.copyfile(ROOT / "diag.sh", case / "diag.sh")
        (case / "stubs").write_text(STUBS)
        (case / "anticheat").write_text(CLI)
        (case / "anticheat").chmod(0o755)
        env = dict(os.environ, CASE_DIR=directory, BASH_ENV=str(case / "stubs"),
                   TEST_UID="0", TEST_LOADED="0", TEST_FAILURE="",
                   TEST_STUBBORN="0", TEST_RMMOD_RC="0")
        env.update(options)
        result = subprocess.run(["bash", str(case / "diag.sh")], env=env,
                                text=True, capture_output=True, timeout=10)
        calls = (case / "calls").read_text().splitlines()
        assert not (case / "child.pid").exists(), (result, calls)
        return result, calls


def module_calls(calls):
    return [call for call in calls if call.startswith(("insmod ", "rmmod "))]


def assert_victim_cleanup(calls, terms=1):
    protect = next(call for call in calls if call.startswith("cli protect --pid "))
    victim = protect.split()[-1]
    unprotect = f"cli unprotect --pid {victim}"
    assert calls.count(unprotect) == 1, calls
    assert calls.count(f"kill -TERM -- -{victim}") == terms, calls
    assert calls.count(f"kill -KILL -- -{victim}") == 1, calls
    assert calls.index(unprotect) < calls.index(f"kill -TERM -- -{victim}"), calls
    return unprotect


def test_non_root():
    result, calls = run_case(TEST_UID="1000")
    assert result.returncode == 1, result
    assert result.stdout.strip() == "run with sudo", result
    assert calls == ["id -u"], calls


def test_fresh_module():
    result, calls = run_case()
    assert result.returncode == 0 and "== done ==" in result.stdout, result
    assert module_calls(calls) == ["insmod ./anticheat.ko ac_verbose=1", "rmmod anticheat"], calls
    unprotect = assert_victim_cleanup(calls)
    assert calls.index(unprotect) < calls.index("rmmod anticheat"), calls
    # Control process is killed once, then P is cleared before EXIT cleanup.
    control = next(call.split()[4] for call in calls if call.startswith("timeout "))
    assert calls.count(f"kill {control}") == 1, calls


def test_existing_module():
    result, calls = run_case(TEST_LOADED="1")
    assert result.returncode == 0 and "== done ==" in result.stdout, result
    assert not module_calls(calls), calls
    assert "leaving it loaded" in result.stderr, result
    assert "sparse or stale" in result.stderr, result
    assert_victim_cleanup(calls)


def test_load_failure():
    result, calls = run_case(TEST_FAILURE="insmod")
    assert result.returncode == 1 and "INSMOD FAILED" in result.stdout, result
    assert module_calls(calls) == ["insmod ./anticheat.ko ac_verbose=1"], calls
    assert not any(call.startswith("cli ") for call in calls), calls


def test_early_exits():
    for failure in ("during-insmod", "control", "mktemp", "before-child-read"):
        for loaded in ("0", "1"):
            if loaded == "1" and failure == "during-insmod":
                continue
            result, calls = run_case(TEST_FAILURE=failure, TEST_LOADED=loaded)
            assert result.returncode == (1 if failure == "mktemp" else 73), (failure, result)
            expected = [] if loaded == "1" else ["insmod ./anticheat.ko ac_verbose=1", "rmmod anticheat"]
            assert module_calls(calls) == expected, (failure, calls)
            assert "== done ==" not in result.stdout, result
            if failure == "before-child-read":
                assert_victim_cleanup(calls)
            else:
                assert not any(call.startswith("cli unprotect") for call in calls), calls
            if failure == "control":
                control = next(call.split()[4] for call in calls if call.startswith("timeout "))
                assert calls.count(f"kill {control}") == 1, calls


def test_stubborn_group():
    result, calls = run_case(TEST_STUBBORN="1")
    assert result.returncode == 0, result
    assert_victim_cleanup(calls, terms=40)
    assert calls[-1] == "rmmod anticheat", calls


def test_diagnostic_failures():
    result, calls = run_case(TEST_FAILURE="cli", TEST_RMMOD_RC="1")
    assert result.returncode == 0 and "== done ==" in result.stdout, result
    assert_victim_cleanup(calls)
    assert calls[-1] == "rmmod anticheat", calls



def test_named_process_helpers():
    # Load just the changed helpers; sourcing mock_test.sh would run its full
    # daemon suite. Exercise their real /proc and process behavior in isolation.
    source = (ROOT / "test/mock_test.sh").read_text()
    helpers = "\n".join(re.search(rf"^{name}\(\) \{{.*?^\}}", source,
                                  re.MULTILINE | re.DOTALL).group()
                        for name in ("ac_spawn_named_copy", "ac_kill_spawn"))
    with tempfile.TemporaryDirectory(prefix="ac-named-test-") as directory:
        script = helpers + r'''
set -eu
AC_TESTBIN_DIR=$1
AC_SPAWNPID=""
cleanup_test() {
    if [ -n "$AC_SPAWNPID" ]; then ac_kill_spawn "$AC_SPAWNPID" || :; fi
}
trap cleanup_test EXIT
for name in ac69-exe-match-longname-test ac69deleted; do
    ac_spawn_named_copy "$name"
    pid=$AC_SPAWNPID
    [ "$(readlink "/proc/$pid/exe")" = "$AC_TESTBIN_DIR/$name" ]
    [ "$(cat "/proc/$pid/comm")" = "${name:0:15}" ]
    # Wait for the sleep child so teardown is verified for both processes.
    child=""
    for _ in $(seq 1 50); do
        child=$(pgrep -P "$pid") || :
        [ -n "$child" ] && break
        sleep 0.01
    done
    [ -n "$child" ]
    rm "$AC_TESTBIN_DIR/$name"
    [ "$(readlink "/proc/$pid/exe")" = "$AC_TESTBIN_DIR/$name (deleted)" ]
    ac_kill_spawn "$pid" || :
    ! kill -0 "$pid" 2>/dev/null
    # A dead child may briefly remain as a zombie until init reaps it.
    state=$(awk '{print $3}' "/proc/$child/stat" 2>/dev/null) || state=""
    [ -z "$state" ] || [ "$state" = Z ]
    AC_SPAWNPID=""
done
'''
        result = subprocess.run(["bash", "-c", script, "helpers", directory],
                                text=True, capture_output=True, timeout=10)
        assert result.returncode == 0, result


if __name__ == "__main__":
    for test in (test_non_root, test_fresh_module, test_existing_module,
                 test_load_failure, test_early_exits, test_stubborn_group,
                 test_diagnostic_failures, test_named_process_helpers):
        test()
        print(f"PASS {test.__name__}")
