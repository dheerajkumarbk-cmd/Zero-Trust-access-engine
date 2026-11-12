-- 99_drop.sql: remove the iga schema and everything in it (tables, partitions, views, functions, triggers, types).
-- Safe to re-run. Roles iga_app, iga_reviewer, iga_auditor, iga_admin are cluster-level and are not dropped here.
DROP SCHEMA IF EXISTS iga CASCADE;
