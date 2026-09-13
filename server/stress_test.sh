#!/bin/bash
# stress_test.sh -- sustained concurrent load against a real ac_server.py
# instance: $STRESS_CONCURRENCY workers hammering /report in parallel for
# $STRESS_DURATION seconds, verifying the server survives (no crash, no
# unexpected errors) and that no successfully-201'd report goes missing
# from the DB beyond what Store's per-client_id retention cap trims on
# purpose -- something test_server.sh's short, mostly-sequential suite
# doesn't exercise. Complements test_ratelimiter_unit.py: that one
# proves RateLimiter._buckets doesn't grow unboundedly in isolation; this
# one proves the server as a whole holds up under real concurrent
# ThreadingHTTPServer + one-SQLite-connection-per-request load.
#
# No root, no kernel module -- pure HTTP against a throwaway SQLite DB,
# same as test_server.sh. Deliberately NOT part of the fast per-push CI
# job (see .github/workflows/stress.yml) -- this is meant to run for
# minutes, not seconds.
#
# Override via environment: STRESS_DURATION=1800 STRESS_CONCURRENCY=50
# ./server/stress_test.sh for a real extended soak run locally.
set -u

cd "$(dirname "$0")" || exit 1

DURATION="${STRESS_DURATION:-90}"
CONCURRENCY="${STRESS_CONCURRENCY:-20}"
# A zero/negative/non-numeric value here wouldn't fail loudly -- $end
# below could equal or precede "now", so every worker's while-loop would
# run zero times and this script would still report success on zero
# actual load, and `seq 1 "$CONCURRENCY"` with a bad value fails
# unpredictably rather than cleanly. Reject both explicitly up front.
if ! [[ "$DURATION" =~ ^[1-9][0-9]*$ && "$CONCURRENCY" =~ ^[1-9][0-9]*$ ]]; then
    printf 'STRESS_DURATION and STRESS_CONCURRENCY must be positive integers (got DURATION=%s CONCURRENCY=%s)\n' \
        "$DURATION" "$CONCURRENCY" >&2
    exit 2
fi
# Passed to the server explicitly rather than inherited from
# ac_server.py's own default, because the durability check below has to
# reason about it: Store.add_report() trims each client_id's rows to the
# newest $CAP on every insert (#60), so a worker that sends more than
# $CAP reports will legitimately find fewer rows than it sent. Leaving
# this implicit is exactly how that check went stale -- at the 90s/20
# worker defaults no worker reaches 1000 reports and it never fired, but
# a 300s/30-worker dispatch run has every worker sending ~2600 and every
# one of them "failing" a durability check that was really just watching
# retention work as designed. Kept enabled (not set to 0) so the trim's
# DELETE still runs on the hot write path this test exists to stress.
CAP=1000
# How many of the oldest retained rows the durability check treats as
# retention's business rather than the server's (see below). Only
# requests the worker abandoned client-side while the server was still
# writing them can land out of sequence, and a worker has at most one
# request in flight at a time, so the real reordering window is a couple
# of rows -- 25 is slack well past that while still checking ~975 of the
# $CAP retained rows.
TRIM_MARGIN=25
PORT=18900
TESTDIR="$(mktemp -d /tmp/ac_server_stress.XXXXXXXX)"
DB="$TESTDIR/ac_server.db"
# cleanup() below always rm -rf's $TESTDIR, including server.log and every
# worker's errlog -- exactly the files needed to diagnose a failure. On
# FAIL, copy them here (relative to this script's own dir, i.e.
# server/stress-failure-artifacts/) before that happens, so CI can upload
# them as a build artifact instead of the failure reason being lost the
# moment this script exits.
ARTIFACT_DIR="$(pwd)/stress-failure-artifacts"
REPORT_KEY="stress-report-key-$$"
ADMIN_KEY="stress-admin-key-$$"
BASE="http://127.0.0.1:$PORT"
# Every curl call below uses this: without a bound, a stalled connection
# or response could block a worker past $DURATION, and the top-level
# `wait` would then block indefinitely too -- the same class of hang
# this script's cleanup()/trap handling already exists to guard against,
# just from the opposite direction (a stuck request instead of a killed
# process). --max-time was originally 5s; raised to 20s after a real run
# (30 workers, 300s, both in CI and reproduced locally) showed that value
# was too tight for this architecture under sustained 30-way contention --
# every one of those "failures" was curl code 000 (client gave up) for a
# request the server log showed as a clean 201 moments later, not a
# server-side error. 20s still firmly bounds a genuine indefinite hang;
# it just stops manufacturing false failures out of ordinary queueing
# delay under load. See the worker loop and durability check below for
# how a 000 is now told apart from an actual error.
CURL_CONNECT_TIMEOUT=2
CURL_MAX_TIME=20
CURL_TIMEOUT=(--connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME")

FAIL=0
pass() { printf '  \033[1;32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[1;31mFAIL\033[0m  %s\n' "$*"; FAIL=1; }

SERVER_PID=""
WORKER_PIDS=""
# shellcheck disable=SC2317,SC2329
cleanup() {
    # Worker PIDs first: each runs its own while-loop for the full
    # $DURATION independently of the server, so on any early/abnormal
    # exit (Ctrl-C, a CI job timeout sending SIGTERM, a failure earlier
    # in this script) they must be killed explicitly -- they are NOT
    # children of $SERVER_PID and killing only that PID leaves every
    # worker's loop running for the rest of its original $DURATION,
    # orphaned, still hammering $PORT.
    # shellcheck disable=SC2086
    [ -n "$WORKER_PIDS" ] && kill $WORKER_PIDS 2>/dev/null
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
    # shellcheck disable=SC2086
    [ -n "$WORKER_PIDS" ] && wait $WORKER_PIDS 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
    if [ "$FAIL" -ne 0 ]; then
        mkdir -p "$ARTIFACT_DIR"
        cp "$TESTDIR/server.log" "$ARTIFACT_DIR/" 2>/dev/null
        cp "$TESTDIR"/worker-*.errlog "$ARTIFACT_DIR/" 2>/dev/null
    fi
    rm -rf "$TESTDIR"
}
trap cleanup EXIT
# EXIT alone does not reliably run on every signal-terminated shell in
# every context -- explicit traps make cleanup unconditional rather than
# incidental, which matters here specifically because leftover workers
# are a real, previously-hit failure mode (see the comment above), not
# a hypothetical one.
trap 'FAIL=1; cleanup; exit 130' INT
trap 'FAIL=1; cleanup; exit 143' TERM

echo "=== server stress test: $CONCURRENCY workers x ${DURATION}s ==="
echo

# Rate limit set far above anything this run could plausibly trip --
# rate-limiting correctness itself is test_server.sh's job; this run is
# about concurrency/durability, and a 429 here would just be noise
# obscuring that signal.
AC_SERVER_REPORT_KEY="$REPORT_KEY" AC_SERVER_ADMIN_KEY="$ADMIN_KEY" \
    python3 ./ac_server.py --host 127.0.0.1 --port "$PORT" --db "$DB" \
    --rate-limit 1000000 --rate-window 60 \
    --max-reports-per-client "$CAP" \
    >"$TESTDIR/server.log" 2>&1 &
SERVER_PID=$!

READY=0
for _ in $(seq 1 50); do
    if curl -s "${CURL_TIMEOUT[@]}" "$BASE/banned/x" -H "Authorization: Bearer $ADMIN_KEY" 2>/dev/null \
        | grep -q '"banned"'; then
        READY=1
        break
    fi
    sleep 0.1
done
if [ "$READY" -ne 1 ]; then
    fail "server never became ready on $BASE (port collision with another service?)"
    exit 1
fi

# Each worker hammers /report with its own client_id for the full
# duration, recording how many 201s, client-side timeouts, and other
# (genuinely unexpected) codes it saw. Result written to a file rather
# than a shared variable -- these run as separate background processes,
# nothing else crosses that boundary.
#
# curl reports "000" for %{http_code} whenever it never received a
# complete response -- both for --max-time firing (a request the server
# may well have actually completed) AND for a genuine transport failure
# like connection-refused or a reset connection (a real error, not
# ordinary load-induced latency). %{http_code} alone can't tell those
# apart; curl's own exit status can -- 28 is specifically "operation
# timeout" (this call's own --connect-timeout/--max-time firing), while
# every other nonzero exit is a real transport failure. Classified on
# that instead of the code string, so a connection failure doesn't get
# silently miscounted as the same benign "server was just slow" bucket a
# --max-time timeout belongs in.
worker() {
    local id="$1"
    local cid="stress-worker-$id-$$"
    local ok=0
    local timeouts=0
    local errors=0
    local n=0
    local bodyfile="$TESTDIR/worker-$id.lastbody"
    # $n increments on every attempt, but only a 201 proves the row is
    # committed (the handler writes before it responds), so the sequence
    # numbers that actually landed are a subset with arbitrary holes in
    # it -- a timed-out or transport-failed attempt burns an $n that may
    # legitimately have no row. The durability check needs the exact set
    # the client was told succeeded, not a range, so record it here
    # rather than trying to reconstruct it afterwards.
    local ackfile="$TESTDIR/worker-$id.acked"
    local end=$(( $(date +%s) + DURATION ))
    while [ "$(date +%s)" -lt "$end" ]; do
        n=$((n + 1))
        code=$(curl -s "${CURL_TIMEOUT[@]}" -o "$bodyfile" -w '%{http_code}' -X POST "$BASE/report" \
            -H "Authorization: Bearer $REPORT_KEY" -H 'Content-Type: application/json' \
            -d "{\"client_id\":\"$cid\",\"event_type\":\"X\",\"detail\":\"n=$n\",\"ts\":$n}")
        rc=$?
        if [ "$rc" -eq 0 ] && [ "$code" = "201" ]; then
            ok=$((ok + 1))
            printf '%d\n' "$n" >> "$ackfile"
        elif [ "$rc" -eq 28 ]; then
            timeouts=$((timeouts + 1))
            printf 'n=%d rc=%d (timeout, response unavailable)\n' "$n" "$rc" >> "$TESTDIR/worker-$id.errlog"
        else
            errors=$((errors + 1))
            # Only rc=0 means curl actually got a complete response to show
            # a body/code for; a nonzero, non-28 rc is a transport failure
            # (connection refused/reset) where $bodyfile is stale or empty
            # from a prior iteration, not useful/attributable to this one.
            {
                if [ "$rc" -eq 0 ]; then
                    printf 'n=%d rc=%d code=%s body=%s\n' "$n" "$rc" "$code" "$(head -c 300 "$bodyfile" 2>/dev/null)"
                else
                    printf 'n=%d rc=%d (transport failure, no response)\n' "$n" "$rc"
                fi
            } >> "$TESTDIR/worker-$id.errlog"
        fi
    done
    printf '%s %d %d %d\n' "$cid" "$ok" "$timeouts" "$errors" > "$TESTDIR/worker-$id.result"
}

for i in $(seq 1 "$CONCURRENCY"); do
    worker "$i" &
    WORKER_PIDS="$WORKER_PIDS $!"
done
# shellcheck disable=SC2086
wait $WORKER_PIDS
WORKER_PIDS=""  # all reaped normally -- nothing left for cleanup() to kill

echo "-- checking every worker's successful reports landed durably --"
TOTAL_OK=0
TOTAL_TIMEOUTS=0
TOTAL_ERRORS=0
DB_MISMATCH=0
for i in $(seq 1 "$CONCURRENCY"); do
    read -r CID OK TIMEOUTS ERRORS < "$TESTDIR/worker-$i.result"
    TOTAL_OK=$((TOTAL_OK + OK))
    TOTAL_TIMEOUTS=$((TOTAL_TIMEOUTS + TIMEOUTS))
    TOTAL_ERRORS=$((TOTAL_ERRORS + ERRORS))
    # Queried directly against the DB file, not the /reports API -- that
    # endpoint caps at 200 rows (see list_reports()'s default limit),
    # which a sustained run can easily exceed; a direct query has no such
    # cap and is the actual ground truth being checked here.
    #
    # Each worker's detail field is "n=<seq>", so the retained rows can be
    # matched against the exact set of sequence numbers that worker was
    # told succeeded (worker-$i.acked). That comparison is what separates
    # "trimmed on purpose" from "lost": retention only ever removes the
    # oldest rows, so an acknowledged $n missing from above the trim
    # boundary was dropped, not trimmed.
    #
    # Deliberately a set difference against the acknowledged numbers
    # rather than a contiguity test over the retained ones. $n counts
    # attempts, not successes, so a timed-out or transport-failed attempt
    # legitimately leaves its $n with no row -- a hole in the retained
    # sequence that proves nothing. Only a number the client saw a 201
    # for is owed a row.
    # Whether retention could have trimmed this client at all is decided
    # from the worker's own attempt count, never from the row count: the
    # rows are the thing under test, so "fewer rows than the cap" cannot
    # be read as "nothing was trimmed" -- losing rows at the cap produces
    # exactly that. Every iteration increments $n and lands in exactly one
    # of the three buckets, so this is the worker's final $n.
    ATTEMPTS=$((OK + TIMEOUTS + ERRORS))
    read -r DB_COUNT DB_MISSING < <(python3 - "$DB" "$CID" "$TESTDIR/worker-$i.acked" "$ATTEMPTS" "$CAP" "$TRIM_MARGIN" <<'EOF'
import os
import sqlite3
import sys

db, cid, ackfile = sys.argv[1], sys.argv[2], sys.argv[3]
attempts, cap, margin = int(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6])
con = sqlite3.connect(db)
try:
    rows = con.execute(
        "SELECT detail FROM reports WHERE client_id = ?", (cid,)
    ).fetchall()
finally:
    con.close()
stored = {int(r[0].split("=", 1)[1]) for r in rows}
# A worker that never got a single 201 writes no ack file at all.
if os.path.exists(ackfile):
    with open(ackfile) as fh:
        acked = {int(line) for line in fh if line.strip()}
else:
    acked = set()
# add_report's DELETE only fires once a client exceeds $cap rows, and a
# client cannot have more rows than the worker made attempts. So a worker
# that sent no more than $cap requests was never trimmed, and every
# acknowledged number is owed a row with no boundary to excuse it.
# Checking the whole set matters because the row-count assertions cannot
# carry this case on their own -- a timed-out attempt that committed
# anyway fills the count left by a genuinely lost row, so DB_COUNT can
# match $ok exactly while a report is missing.
if attempts <= cap:
    missing = len(acked - stored)
else:
    # At the cap, retention has trimmed, and what it trimmed is the
    # oldest rows *by rowid*, which need not be the lowest $n: an attempt
    # the worker abandoned client-side can still be committed after the
    # next one was sent. Only the bottom $margin retained rows are close
    # enough to that boundary for the distinction to matter; above them
    # the ordering has no such excuse, and an acknowledged number with no
    # row is a genuinely lost write.
    kept = sorted(stored)
    floor = kept[margin] if len(kept) > margin else kept[0]
    missing = len([n for n in acked if n >= floor and n not in stored])
print(len(stored), missing)
EOF
)
    # Retention caps what can be on disk, so the most a worker's rows can
    # ever be is $CAP -- compare against that, not against $OK, or every
    # worker in a run long enough to exceed the cap "fails" for doing
    # exactly what the cap asks. The real durability question is still
    # "did the DB lose anything the client saw succeed", just now asked
    # of the window retention actually keeps.
    #
    # Note this is a floor, not exact equality. A client-side timeout
    # (curl gave up, counted above, not in $OK) for a request the server
    # actually completed makes DB_COUNT > OK perfectly legitimately;
    # treating that as a failure was itself a bug in this check, not a
    # sign of one in the server (verified directly: every DB_COUNT > OK
    # case traced back to a 000 in that worker's timeout count, and the
    # server log showed a clean 201 for it, not an error).
    EXPECTED="$OK"
    [ "$EXPECTED" -gt "$CAP" ] && EXPECTED="$CAP"
    if [ "$DB_COUNT" -lt "$EXPECTED" ]; then
        fail "worker $i: sent $OK successful reports but DB only has $DB_COUNT rows for $CID (expected at least $EXPECTED after the $CAP-row retention cap)"
        DB_MISMATCH=1
    elif [ "$DB_COUNT" -gt "$CAP" ]; then
        # The other side of the same coin: retention must hold under
        # concurrent writes too, not just in the single-threaded unit
        # test (test_store_retention_unit.py). A trim that silently
        # stops working under load is the bug the cap exists to prevent.
        fail "worker $i: DB has $DB_COUNT rows for $CID, above the $CAP-row retention cap (trim failed under concurrent load)"
        DB_MISMATCH=1
    elif [ "$DB_MISSING" -gt 0 ]; then
        fail "worker $i: $DB_MISSING report(s) the server 201'd for $CID are missing from above the retention boundary (not explained by retention, which only trims the oldest)"
        DB_MISMATCH=1
    fi
done
[ "$DB_MISMATCH" -eq 0 ] && pass "no worker's successful reports went missing from the DB (retained window intact and within the $CAP-row cap)"

pass "sustained load: $TOTAL_OK total successful reports across $CONCURRENCY workers in ${DURATION}s"
if [ "$TOTAL_TIMEOUTS" -gt 0 ]; then
    pass "$TOTAL_TIMEOUTS request(s) exceeded the client's ${CURL_MAX_TIME}s wait under load (curl 000) -- informational, not a failure on its own; the durability check above is what proves whether any of them actually failed server-side"
fi
if [ "$TOTAL_ERRORS" -gt 0 ]; then
    fail "$TOTAL_ERRORS requests failed with an unexpected non-201, non-timeout status (rate limit was set high enough that none of this should be rate-limiting)"
else
    pass "zero unexpected-error responses during the run"
fi

if grep -q "Traceback" "$TESTDIR/server.log"; then
    fail "server logged an unhandled exception during the stress run"
else
    pass "no unhandled exceptions logged during the stress run"
fi

echo "-- confirming the server is still responsive after sustained load --"
CODE=$(curl -s "${CURL_TIMEOUT[@]}" -o /dev/null -w '%{http_code}' "$BASE/banned/x" -H "Authorization: Bearer $ADMIN_KEY")
if [ "$CODE" = "200" ]; then
    pass "server still responsive after sustained load"
else
    fail "server not responsive after sustained load (got $CODE)"
fi

echo
if [ "$FAIL" -eq 0 ]; then
    printf '\033[1;32mALL STRESS CHECKS PASSED\033[0m\n'
else
    printf '\033[1;31mSOME STRESS CHECKS FAILED\033[0m\n'
fi
exit "$FAIL"
