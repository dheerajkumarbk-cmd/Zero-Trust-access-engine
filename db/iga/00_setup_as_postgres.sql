-- One-time setup for the DBMS course database (schema "iga"). Run it ONCE, as the PostgreSQL admin ("postgres"), from psql:
--     \i 'C:/Users/Admin/dwr/l5-try/db/iga/00_setup_as_postgres.sql'
-- It asks you to type four NEW passwords (nothing is echoed, nothing is saved to a file, no password is in this script).
-- It needs the role dwarpal_migrator, which db/setup/00-create-roles-and-databases.sql made earlier.
-- It does not touch the databases dwarpal or dwarpal_test.
--
-- Two databases, both owned by dwarpal_migrator:
--   dwarpal_dbms          the course database. All tables live in the schema "iga", built by db/iga/01..10 as dwarpal_migrator.
--   dwarpal_dbms_restore  empty; the backup-and-restore demonstration restores a dump into it (the migrator may not create databases).
-- Four roles, none a superuser, none able to create roles or databases:
--   iga_app       runs the procedures; no direct table writes
--   iga_reviewer  reads the views; decides only its own review items (row-level security)
--   iga_auditor   read-only on everything, including the audit log
--   iga_admin     schema changes; still cannot change or delete audit rows
-- dwarpal_migrator may SET ROLE to each of them (without inheriting their rights), so the test script can check every role
-- over one connection.
-- One extension: btree_gist (for the "no overlapping privileged sessions" exclusion constraint). Only an admin can add it.

\set ON_ERROR_STOP on
SET password_encryption = 'scram-sha-256';

CREATE ROLE iga_app      LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE ROLE iga_reviewer LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE ROLE iga_auditor  LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE ROLE iga_admin    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
\echo 'Type a NEW password for iga_app, then the same again:'
\password iga_app
\echo 'Type a NEW, different password for iga_reviewer, then the same again:'
\password iga_reviewer
\echo 'Type a NEW, different password for iga_auditor, then the same again:'
\password iga_auditor
\echo 'Type a NEW, different password for iga_admin, then the same again:'
\password iga_admin

GRANT iga_app, iga_reviewer, iga_auditor, iga_admin TO dwarpal_migrator WITH INHERIT FALSE, SET TRUE;

CREATE DATABASE dwarpal_dbms         OWNER dwarpal_migrator;
CREATE DATABASE dwarpal_dbms_restore OWNER dwarpal_migrator;
REVOKE ALL ON DATABASE dwarpal_dbms         FROM PUBLIC;
REVOKE ALL ON DATABASE dwarpal_dbms_restore FROM PUBLIC;
GRANT CONNECT ON DATABASE dwarpal_dbms TO iga_app, iga_reviewer, iga_auditor, iga_admin;

\connect dwarpal_dbms
CREATE EXTENSION IF NOT EXISTS btree_gist;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
\connect dwarpal_dbms_restore
CREATE EXTENSION IF NOT EXISTS btree_gist;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

\echo
\echo '--- Checks (safe to show; no secrets) ---'
SELECT datname, pg_get_userbyid(datdba) AS owner FROM pg_database WHERE datname LIKE 'dwarpal_dbms%' ORDER BY 1;
SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname LIKE 'iga\_%' ORDER BY 1;
\connect dwarpal_dbms
SELECT extname, extversion FROM pg_extension WHERE extname = 'btree_gist';
