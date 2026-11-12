#!/usr/bin/env bash
# deadlock.sh : DEMO 3 - DEADLOCK. Two sessions lock two people in opposite order.
# Usage: db/iga/demos/deadlock.sh [DBNAME]     (default: env DB, else dwarpal_dbms)
DB="${1:-${DB:-dwarpal_dbms}}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN="$HERE/../run.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
q() { "$RUN" --db "$DB" "$@"; }

echo "Database: $DB    Run at: $(date '+%Y-%m-%d %H:%M:%S %Z')"
q "$HERE/deadlock_setup.sql" -q >/dev/null 2>&1 || { echo "setup failed"; exit 1; }
echo "--- the server waits this long on a lock before it checks for a deadlock:"
q -c "SHOW deadlock_timeout" -q
echo "--- before: both people are in department DEMO_DL_DEPT_1"
q -c "SELECT p.employee_no, d.name AS dept FROM iga.person p JOIN iga.department d USING (dept_id) WHERE p.employee_no LIKE 'DEMO-DL-%' ORDER BY 1" -q
echo
echo "Session A locks X then moves Y.  Session B locks Y then moves X.  Started together."
q "$HERE/deadlock_session.sql" -v label=A -v first=DEMO-DL-X -v second=DEMO-DL-Y >"$TMP/A.out" 2>&1 &
q "$HERE/deadlock_session.sql" -v label=B -v first=DEMO-DL-Y -v second=DEMO-DL-X >"$TMP/B.out" 2>&1 &
wait
echo "--- session A output"; cat "$TMP/A.out"
echo "--- session B output"; cat "$TMP/B.out"
echo
echo "--- after: only the session that was NOT aborted moved its person"
q -c "SELECT p.employee_no, d.name AS dept FROM iga.person p JOIN iga.department d USING (dept_id) WHERE p.employee_no LIKE 'DEMO-DL-%' ORDER BY 1" -q
q -c "SELECT p.employee_no, le.event_type, od.name AS old_dept, nd.name AS new_dept FROM iga.lifecycle_event le JOIN iga.person p USING (person_id) LEFT JOIN iga.department od ON od.dept_id = le.old_dept_id LEFT JOIN iga.department nd ON nd.dept_id = le.new_dept_id WHERE p.employee_no LIKE 'DEMO-DL-%' ORDER BY le.event_id" -q
echo
q "$HERE/deadlock_cleanup.sql" -q >/dev/null 2>&1 && echo "Fixture removed."
