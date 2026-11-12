-- One-time setup for the Dwarpal directory database. Run it ONCE, as the PostgreSQL admin ("postgres"), from psql:
--     \i 'C:/Users/Admin/dwr/l5-try/db/setup/00-create-roles-and-databases.sql'
-- It asks you to type two NEW passwords (nothing is echoed, nothing is saved to a file, no password is in this script).
--
-- Two roles, neither one a superuser:
--   dwarpal_migrator  owns the two databases and their tables. Used only to build or change the tables, and by the tests.
--   dwarpal_app       what the running lab signs in as. Can read and write rows. Cannot create, change or drop tables.
-- Two databases: dwarpal (the lab's real data) and dwarpal_test (tests only, wiped on every test run).

\set ON_ERROR_STOP on
SET password_encryption = 'scram-sha-256';

CREATE ROLE dwarpal_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE ROLE dwarpal_app      LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
\echo 'Type a NEW password for dwarpal_migrator, then the same again:'
\password dwarpal_migrator
\echo 'Type a NEW, different password for dwarpal_app, then the same again:'
\password dwarpal_app

CREATE DATABASE dwarpal      OWNER dwarpal_migrator;
CREATE DATABASE dwarpal_test OWNER dwarpal_migrator;
REVOKE ALL ON DATABASE dwarpal      FROM PUBLIC;
REVOKE ALL ON DATABASE dwarpal_test FROM PUBLIC;
GRANT CONNECT ON DATABASE dwarpal      TO dwarpal_app;
GRANT CONNECT ON DATABASE dwarpal_test TO dwarpal_app;
-- Nobody but the admin needs the maintenance database; the app role gets no way in.
REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;

\echo
\echo '--- Checks (safe to show; no secrets) ---'
SHOW listen_addresses;
SHOW password_encryption;
SHOW server_encoding;
SELECT rule_number AS n, type, database, user_name, address, auth_method
  FROM pg_hba_file_rules WHERE error IS NULL ORDER BY rule_number;
