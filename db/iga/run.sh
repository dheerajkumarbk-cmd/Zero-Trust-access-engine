#!/usr/bin/env bash
# Run SQL for the iga schema as dwarpal_migrator. The password is never printed or put on a command line:
# it comes from env DWARPAL_DB_MIGRATOR_PASSWORD, else from migrator.password in db/local.properties,
# and is exported only to the psql process.
#
# Usage:
#   db/iga/run.sh FILE.sql [extra psql args]
#   db/iga/run.sh --db NAME FILE.sql      NAME: dwarpal_dbms (default) or dwarpal_dbms_restore
#   db/iga/run.sh -c "SQL"                one-off command
#   db/iga/run.sh --build                 run 01..08 in order (missing files skipped)
#   db/iga/run.sh --test                  run 10_tests.sql
# --db may be combined with any of the above (put it first). Exit code is psql's.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROPS="$SCRIPT_DIR/../local.properties"
PSQL="${PSQL:-/d/Program Files/PostgreSQL/18/bin/psql.exe}"
DB="dwarpal_dbms"

if [ "$1" = "--db" ]; then
    DB="$2"
    shift 2 || { echo "run.sh: --db needs a name" >&2; exit 2; }
fi
case "$DB" in
    dwarpal_dbms|dwarpal_dbms_restore) ;;
    *) echo "run.sh: database must be dwarpal_dbms or dwarpal_dbms_restore" >&2; exit 2 ;;
esac

if [ $# -eq 0 ]; then
    sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
    exit 2
fi

PW="${DWARPAL_DB_MIGRATOR_PASSWORD:-}"
if [ -z "$PW" ] && [ -f "$PROPS" ]; then
    PW="$(grep '^migrator\.password=' "$PROPS" | head -n 1 | cut -d= -f2- | tr -d '\r')"
fi
if [ -z "$PW" ]; then
    echo "run.sh: no password (set DWARPAL_DB_MIGRATOR_PASSWORD or migrator.password in db/local.properties)" >&2
    exit 2
fi

# psql with the connection options; the password is passed through the environment of this one process only.
run_psql() {
    PGPASSWORD="$PW" "$PSQL" -h localhost -p 5432 -U dwarpal_migrator -d "$DB" -v ON_ERROR_STOP=1 -X "$@"
}

# Resolve FILE: as given if it exists, else relative to the script directory.
resolve() {
    if [ -f "$1" ]; then printf '%s' "$1"; else printf '%s' "$SCRIPT_DIR/$1"; fi
}

case "$1" in
    --build)
        for f in 01_schema 02_constraints 03_functions 04_triggers 05_views 06_indexes 07_roles 08_seed; do
            file="$SCRIPT_DIR/$f.sql"
            if [ ! -f "$file" ]; then
                echo "run.sh: skipping $f.sql (not present)"
                continue
            fi
            echo "run.sh: $f.sql"
            run_psql -f "$file" || { rc=$?; echo "run.sh: $f.sql failed" >&2; exit "$rc"; }
        done
        exit 0
        ;;
    --test)
        run_psql -f "$SCRIPT_DIR/10_tests.sql"
        exit $?
        ;;
    -c)
        [ -n "$2" ] || { echo "run.sh: -c needs SQL" >&2; exit 2; }
        sql="$2"; shift 2
        run_psql -c "$sql" "$@"
        exit $?
        ;;
    *)
        file="$(resolve "$1")"; shift
        run_psql -f "$file" "$@"
        exit $?
        ;;
esac
