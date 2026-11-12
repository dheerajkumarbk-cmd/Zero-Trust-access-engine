#!/usr/bin/env bash
# isolation.sh : DEMO 2 - ISOLATION. Two sessions approve the last free slot at the same time.
# Usage: db/iga/demos/isolation.sh [DBNAME]     (default: env DB, else dwarpal_dbms)
# Prints the full transcript to stdout; redirect to docs/dbms/demo-isolation.txt if wanted.
DB="${1:-${DB:-dwarpal_dbms}}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN="$HERE/../run.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
q() { "$RUN" --db "$DB" "$@"; }

race() {   # race LEVEL
    local level="$1"
    q "$HERE/isolation_setup.sql" -q >/dev/null 2>&1 || { echo "setup failed"; exit 1; }
    echo "--- before: "; q "$HERE/isolation_holders.sql" -q -t
    # A sleeps 2 s and B 3 s between check and insert: both read count=2 before either writes,
    # and A reaches its write first.
    q "$HERE/isolation_session.sql" -v label=A -v "level=$level" -v cand=demo-iso-c1 -v delay=2 >"$TMP/A.out" 2>&1 &
    q "$HERE/isolation_session.sql" -v label=B -v "level=$level" -v cand=demo-iso-c2 -v delay=3 >"$TMP/B.out" 2>&1 &
    wait
    echo "--- session A output"; cat "$TMP/A.out"
    echo "--- session B output"; cat "$TMP/B.out"
    echo "--- after (committed state, third session): "; q "$HERE/isolation_holders.sql" -q -t
}

echo "Database: $DB    Run at: $(date '+%Y-%m-%d %H:%M:%S %Z')"
echo "Rule under test: a privileged role may have at most 3 live holders; checked inside the transaction."
echo "Fixture: 2 live holders already, so exactly one slot is free, and two sessions each try to take it."
echo
echo "================ RUN 1: READ COMMITTED (PostgreSQL default) ================"
race "READ COMMITTED"
echo
echo "================ RUN 2: SERIALIZABLE ================"
race "SERIALIZABLE"
echo
q "$HERE/isolation_cleanup.sql" -q >/dev/null 2>&1 && echo "Fixture removed."
