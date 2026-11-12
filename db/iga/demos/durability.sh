#!/usr/bin/env bash
# durability.sh : DEMO 4 - DURABILITY (write-ahead log).  THIS SCRIPT NEVER STOPS OR RESTARTS POSTGRESQL.
# Usage: db/iga/demos/durability.sh MODE [DBNAME]     (DBNAME default: env DB, else dwarpal_dbms)
#   safe      step 1 then cleanup, no restart (what docs/dbms/demo-durability.txt contains)
#   step1     insert + commit the marker row, print LSN before/after
#   step3     after the restart: show the marker row is still there
#   cleanup   delete the marker row
#
# Full demo, done by the OWNER by hand:
#   1. db/iga/demos/durability.sh step1
#   2. Restart the service from an ADMINISTRATOR prompt (shown for reference, never executed here):
#        net stop postgresql-x64-18
#        net start postgresql-x64-18
#      (For a harsher test, end the postgres.exe process from Task Manager instead of a clean stop:
#       a clean stop writes a shutdown checkpoint, a kill forces crash recovery from the WAL.)
#   3. db/iga/demos/durability.sh step3        -> the row must still be there
#   4. db/iga/demos/durability.sh cleanup
MODE="${1:-}"
DB="${2:-${DB:-dwarpal_dbms}}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN="$HERE/../run.sh"
q() { "$RUN" --db "$DB" "$@"; }

echo "Database: $DB    Run at: $(date '+%Y-%m-%d %H:%M:%S %Z')    mode: $MODE"
case "$MODE" in
    safe)    q "$HERE/durability_step1.sql" -q && q "$HERE/durability_cleanup.sql" -q ;;
    step1)   q "$HERE/durability_step1.sql" -q ;;
    step3)   q "$HERE/durability_step3.sql" -q ;;
    cleanup) q "$HERE/durability_cleanup.sql" -q ;;
    *) echo "usage: durability.sh safe|step1|step3|cleanup [DBNAME]" >&2; exit 2 ;;
esac
