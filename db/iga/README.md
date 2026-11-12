# db/iga: identity, access governance and audit schema

SQL for the PostgreSQL schema `iga`, built in the separate database `dwarpal_dbms`. Spec: `DBMS_BUILD_PROPOSAL.md`. Report: `docs/dbms/phase0-report.md`.

## Files and run order

| File | Purpose |
|---|---|
| `00_setup_as_postgres.sql` | One-time setup run as the postgres superuser |
| `01_schema.sql` | Drops and recreates schema `iga`; tables, keys, partitions |
| `02_constraints.sql` | CHECK, UNIQUE and partial unique constraints |
| `03_functions.sql` | Audit hash functions, joiner / mover / leaver procedures |
| `04_triggers.sql` | Audit, append-only and lifecycle triggers |
| `05_views.sql` | Reporting views |
| `06_indexes.sql` | Indexes |
| `07_roles.sql` | Grants and row-level security |
| `08_seed.sql` | Seed data |
| `09_demo_queries.sql` | Read-only showcase queries |
| `10_tests.sql` | Tests; prints `PASS`/`FAIL`/`SKIP` lines and a `SUMMARY` line |
| `99_drop.sql` | `DROP SCHEMA IF EXISTS iga CASCADE`; safe to re-run |

Not every file exists at every stage; this is the planned set.

## Running

Use the wrapper, from anywhere (a relative file name is also looked up next to the script):

    db/iga/run.sh 01_schema.sql              # one file
    db/iga/run.sh --build                    # 01 to 08 in order, skipping absent files
    db/iga/run.sh --test                     # 10_tests.sql
    db/iga/run.sh -c "select count(*) from iga.person"
    db/iga/run.sh --db dwarpal_dbms_restore 09_demo_queries.sql

`--db` accepts `dwarpal_dbms` (default) or `dwarpal_dbms_restore`. Extra arguments after a file name go to psql. The exit code is psql's.

The wrapper connects to localhost:5432 as `dwarpal_migrator` with `ON_ERROR_STOP` on. The password comes from the environment variable `DWARPAL_DB_MIGRATOR_PASSWORD` if set, otherwise from `migrator.password` in `db/local.properties`. It is passed only to the psql process and is never printed.

## Dropping

    db/iga/run.sh 99_drop.sql

This removes the `iga` schema and everything in it. Cluster-level roles are not dropped.

## Demos and captures (db/iga/demos)

| Script | Output | Notes |
|---|---|---|
| `explain_capture.sql` | `docs/dbms/explain-before.txt`, `explain-after.txt` | Run before and after `06_indexes.sql` |
| `pruning_capture.sql` | `docs/dbms/explain-pruning.txt` | One-month query touches one partition |
| `backup_restore.sh [DUMP]` | `docs/dbms/backup-restore-output.txt` | `pg_dump -Fc`, restore into `dwarpal_dbms_restore`, row counts, audit chain check, dropped-table recovery. The dump file stays outside the repo |
| `roles_demo.sql` | `docs/dbms/roles-demo-output.txt` | Grants and row-level security checks |
| `atomicity.sql`, `isolation.sh`, `deadlock.sh`, `durability.sh` | `docs/dbms/demo-*.txt` | Run against `dwarpal_dbms_restore`; see `demos/README.md` |

`09_demo_queries.sql` output is saved in `docs/dbms/demo-queries-output.txt`.
