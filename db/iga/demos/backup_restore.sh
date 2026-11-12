#!/usr/bin/env bash
# Backup and recovery demo (spec section 10). Dump from dwarpal_dbms, restore ONLY into dwarpal_dbms_restore.
#   db/iga/demos/backup_restore.sh [DUMP_FILE]      (default dump path: $IGA_DUMP or $TMPDIR/iga_dwarpal_dbms.dump; keep it OUT of the repo)
# The password is read here from env DWARPAL_DB_MIGRATOR_PASSWORD or db/local.properties, exported only to the
# child processes and never printed.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN="$HERE/../run.sh"
BIN="/d/Program Files/PostgreSQL/18/bin"
DUMP="${1:-${IGA_DUMP:-${TMPDIR:-/tmp}/iga_dwarpal_dbms.dump}}"
PW="${DWARPAL_DB_MIGRATOR_PASSWORD:-}"
[ -z "$PW" ] && [ -f "$HERE/../../local.properties" ] && PW="$(grep '^migrator\.password=' "$HERE/../../local.properties" | head -n 1 | cut -d= -f2- | tr -d '\r')"
[ -z "$PW" ] && { echo "no password source" >&2; exit 2; }
SRC=dwarpal_dbms; DST=dwarpal_dbms_restore
case "$DUMP" in "$HERE"/*|*/l5-try/*) echo "refusing to write the dump inside the repo" >&2; exit 2;; esac
pg() { local tool="$1"; shift; PGPASSWORD="$PW" "$BIN/$tool.exe" -h localhost -p 5432 -U dwarpal_migrator "$@"; }
counts() { "$RUN" --db "$1" -t -A -q -c "
SELECT 'department|'||count(*) FROM iga.department UNION ALL SELECT 'person|'||count(*) FROM iga.person
UNION ALL SELECT 'system|'||count(*) FROM iga.system UNION ALL SELECT 'account|'||count(*) FROM iga.account
UNION ALL SELECT 'role|'||count(*) FROM iga.role UNION ALL SELECT 'entitlement|'||count(*) FROM iga.entitlement
UNION ALL SELECT 'role_entitlement|'||count(*) FROM iga.role_entitlement UNION ALL SELECT 'role_assignment|'||count(*) FROM iga.role_assignment
UNION ALL SELECT 'sod_rule|'||count(*) FROM iga.sod_rule UNION ALL SELECT 'dept_birthright_role|'||count(*) FROM iga.dept_birthright_role
UNION ALL SELECT 'lifecycle_event|'||count(*) FROM iga.lifecycle_event UNION ALL SELECT 'security_event|'||count(*) FROM iga.security_event
UNION ALL SELECT 'audit_log|'||count(*) FROM iga.audit_log UNION ALL SELECT 'review_campaign|'||count(*) FROM iga.review_campaign
UNION ALL SELECT 'review_item|'||count(*) FROM iga.review_item ORDER BY 1"; }

echo "=== 1. Logical backup of schema iga from $SRC (custom format, compressed)"
pg pg_dump -d "$SRC" -n iga -Fc --no-owner -f "$DUMP" || exit 1
ls -l "$DUMP" | awk '{print "dump size (bytes): " $5}'
echo "table of contents entries: $(pg pg_restore -l "$DUMP" | grep -vc '^;')"
counts "$SRC" > "${DUMP}.src.counts"
echo; echo "=== 2. Restore into a NEW empty schema in $DST (old demo schema dropped first)"
"$RUN" --db "$DST" -q -c "DROP SCHEMA IF EXISTS iga CASCADE" 2>&1 | grep -v NOTICE
pg pg_restore -d "$DST" --no-owner -v "$DUMP" 2>&1 | grep -ci "processing data for table" | awk '{print "tables with data restored: " $1}'
counts "$DST" > "${DUMP}.dst.counts"
echo; echo "=== 3. Row counts: source | restored"
paste -d'|' "${DUMP}.src.counts" "${DUMP}.dst.counts" | awk -F'|' '{printf "%-22s %8s %8s  %s\n",$1,$2,$4,($2==$4?"match":"DIFFERENT")}'
if diff -q "${DUMP}.src.counts" "${DUMP}.dst.counts" >/dev/null; then echo "ALL ROW COUNTS MATCH"; else echo "ROW COUNTS DIFFER"; fi
echo; echo "=== 4. Audit chain verified on the restored copy (NULL = chain intact, otherwise the first bad seq)"
"$RUN" --db "$DST" -q -c "SELECT iga.verify_audit_chain() AS first_bad_seq, (iga.verify_audit_chain() IS NULL) AS chain_intact, (SELECT count(*) FROM iga.audit_log) AS audit_rows"
echo; echo "=== 5. Accident: DROP TABLE iga.lifecycle_event in $DST, then recover only that table from the dump"
"$RUN" --db "$DST" -q -c "SELECT count(*) AS rows_before_accident FROM iga.lifecycle_event"
"$RUN" --db "$DST" -q -c "DROP TABLE iga.lifecycle_event"
"$RUN" --db "$DST" -q -c "SELECT count(*) FROM iga.lifecycle_event" 2>&1 | grep -v '^$' | head -3
echo "--- pg_restore -n iga -t lifecycle_event"
pg pg_restore -d "$DST" --no-owner -n iga -t lifecycle_event "$DUMP" && echo "restore of the single table finished"
"$RUN" --db "$DST" -q -c "SELECT count(*) AS rows_after_recovery FROM iga.lifecycle_event"
counts "$DST" > "${DUMP}.dst2.counts"
if diff -q "${DUMP}.src.counts" "${DUMP}.dst2.counts" >/dev/null; then echo "ALL ROW COUNTS MATCH AFTER RECOVERY"; else echo "ROW COUNTS DIFFER AFTER RECOVERY"; fi
"$RUN" --db "$DST" -q -c "SELECT (iga.verify_audit_chain() IS NULL) AS chain_intact_after_recovery"
echo; echo "=== 6. Restored copy rebuilt with the same objects? functions / views / indexes"
"$RUN" --db "$DST" -q -c "SELECT (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='iga') AS functions, (SELECT count(*) FROM pg_views WHERE schemaname='iga') AS views, (SELECT count(*) FROM pg_indexes WHERE schemaname='iga') AS indexes"
"$RUN" --db "$SRC" -q -c "SELECT (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='iga') AS functions, (SELECT count(*) FROM pg_views WHERE schemaname='iga') AS views, (SELECT count(*) FROM pg_indexes WHERE schemaname='iga') AS indexes"
