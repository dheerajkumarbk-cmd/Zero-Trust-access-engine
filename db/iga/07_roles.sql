-- 07_roles.sql : privileges for the four roles created by 00_setup_as_postgres.sql (this file does NOT create roles).
-- Re-runnable: every statement is a REVOKE/GRANT/ALTER/DROP POLICY IF EXISTS+CREATE POLICY. Run after 01..04 (05 optional).
-- Run order matters in one place: 03_functions.sql does CREATE OR REPLACE PROCEDURE, which resets SECURITY DEFINER,
-- so always re-run this file after 03.
--
--   iga_app       calls joiner / mover / leaver (SECURITY DEFINER); reads views; no direct table access at all.
--   iga_reviewer  reads views; decides only its own review items (row-level security on review_item).
--   iga_auditor   read-only on every table and view, including audit_log.
--   iga_admin     schema changes + full table access, except audit_log which stays read-only.
-- The owner (dwarpal_migrator) owns every object and is the only role that can change audit_log through the triggers.
\set ON_ERROR_STOP on
SET search_path = iga, public;
BEGIN;

-- ---------------------------------------------------------------------------------------------
-- 0. Clean slate: nobody gets anything by accident. (The owner keeps its own rights regardless.)
-- ---------------------------------------------------------------------------------------------
REVOKE ALL ON SCHEMA iga FROM PUBLIC;
REVOKE ALL ON ALL TABLES    IN SCHEMA iga FROM PUBLIC, iga_app, iga_reviewer, iga_auditor, iga_admin;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA iga FROM PUBLIC, iga_app, iga_reviewer, iga_auditor, iga_admin;
-- Functions are executable by PUBLIC by default. audit_write is SECURITY DEFINER and appends to the audit chain,
-- so leaving it open would let anybody forge audit rows; close every routine and open them one by one below.
REVOKE ALL ON ALL ROUTINES  IN SCHEMA iga FROM PUBLIC, iga_app, iga_reviewer, iga_auditor, iga_admin;

-- ---------------------------------------------------------------------------------------------
-- 1. Schema access
-- ---------------------------------------------------------------------------------------------
GRANT USAGE ON SCHEMA iga TO iga_app, iga_reviewer, iga_auditor, iga_admin;
GRANT CREATE ON SCHEMA iga TO iga_admin;          -- schema changes (new tables/views/indexes of its own)

-- ---------------------------------------------------------------------------------------------
-- 2. iga_app : only the three lifecycle procedures + the views
-- The procedures run as their owner (SECURITY DEFINER) so iga_app needs no INSERT/UPDATE/DELETE on any table.
-- search_path is pinned to iga, pg_temp so a caller cannot hijack name resolution inside the definer procedure
-- (pg_temp last; "public" is deliberately absent). ALTER ... without an argument list works because each name is unique.
-- ---------------------------------------------------------------------------------------------
ALTER PROCEDURE iga.joiner SECURITY DEFINER SET search_path = iga, pg_temp;
ALTER PROCEDURE iga.mover  SECURITY DEFINER SET search_path = iga, pg_temp;
ALTER PROCEDURE iga.leaver SECURITY DEFINER SET search_path = iga, pg_temp;
GRANT EXECUTE ON PROCEDURE iga.joiner, iga.mover, iga.leaver TO iga_app;

-- Views: granted with a DO block so this file works whether 05_views.sql has run or not (and picks up every view
-- that exists, including materialized views). Views run with their owner's rights, so granting the view is enough.
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT format('%I.%I', n.nspname, c.relname) AS rel
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'iga' AND c.relkind IN ('v', 'm')
  LOOP
    EXECUTE format('GRANT SELECT ON %s TO iga_app, iga_reviewer', r.rel);
  END LOOP;
END $$;

-- ---------------------------------------------------------------------------------------------
-- 3. iga_reviewer : may read its own review items and fill in decision / decided_at, nothing else
-- ---------------------------------------------------------------------------------------------
GRANT SELECT ON iga.review_item TO iga_reviewer;
GRANT UPDATE (decision, decided_at) ON iga.review_item TO iga_reviewer;   -- column-level: cannot move an item to another reviewer
GRANT SELECT ON iga.review_campaign TO iga_reviewer;                      -- campaign name and dates are not sensitive

-- Row-level security on review_item.
-- FORCE is used so the policies below are the single, visible statement of who sees what, owner included
-- (without FORCE the owner silently bypasses RLS and pg_policies would not tell the whole story). Because of FORCE the
-- owner needs its own policy, otherwise even dwarpal_migrator (and the SECURITY DEFINER procedures, which run as the
-- owner) would see and write zero rows.
ALTER TABLE iga.review_item ENABLE ROW LEVEL SECURITY;
ALTER TABLE iga.review_item FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rv_own_items      ON iga.review_item;
DROP POLICY IF EXISTS rv_owner_all      ON iga.review_item;
DROP POLICY IF EXISTS rv_auditor_read   ON iga.review_item;
DROP POLICY IF EXISTS rv_admin_all      ON iga.review_item;

-- The reviewer's identity: the application sets  SELECT set_config('iga.reviewer_id', '<person_id>', false)  (or SET LOCAL)
-- after login. current_setting(..., true) returns NULL when the setting was never made, and nullif turns an empty string
-- into NULL, so an unset session sees NO rows (NULL comparison is never true) instead of raising an error.
-- A production system would not trust a client-settable value: it would map the login role (current_user / session_user)
-- to a person_id through a lookup table, or have the connection pooler set the value from the authenticated identity.
-- Here the GUC keeps the demo to one database connection. USING also acts as WITH CHECK for the update, so a reviewer
-- cannot move a row out of its own set.
CREATE POLICY rv_own_items ON iga.review_item
    FOR ALL TO iga_reviewer
    USING (reviewer_id = nullif(current_setting('iga.reviewer_id', true), '')::bigint);

CREATE POLICY rv_owner_all ON iga.review_item
    FOR ALL TO dwarpal_migrator
    USING (true) WITH CHECK (true);

CREATE POLICY rv_auditor_read ON iga.review_item
    FOR SELECT TO iga_auditor
    USING (true);

CREATE POLICY rv_admin_all ON iga.review_item
    FOR ALL TO iga_admin
    USING (true) WITH CHECK (true);

-- ---------------------------------------------------------------------------------------------
-- 4. iga_auditor : read everything (tables, partitions, views, audit_log) and verify the audit chain
-- ---------------------------------------------------------------------------------------------
GRANT SELECT ON ALL TABLES IN SCHEMA iga TO iga_auditor;     -- ALL TABLES includes views, partitions and sequences' tables
GRANT EXECUTE ON FUNCTION iga.verify_audit_chain(), iga.audit_canonical(bigint, timestamptz, text, text, text, text, jsonb, jsonb),
                          iga.audit_hash(bytea, text) TO iga_auditor;

-- ---------------------------------------------------------------------------------------------
-- 5. iga_admin : full access to tables, but the audit log is read-only for everybody except the owner's triggers
-- (the append-only trigger rejects UPDATE/DELETE/TRUNCATE anyway; this is the second lock, at privilege level)
-- ---------------------------------------------------------------------------------------------
GRANT ALL ON ALL TABLES IN SCHEMA iga TO iga_admin;
REVOKE ALL ON iga.audit_log FROM iga_admin;
GRANT SELECT ON iga.audit_log TO iga_admin;
GRANT EXECUTE ON PROCEDURE iga.joiner, iga.mover, iga.leaver TO iga_admin;
GRANT EXECUTE ON FUNCTION iga.verify_audit_chain(), iga.audit_canonical(bigint, timestamptz, text, text, text, text, jsonb, jsonb),
                          iga.audit_hash(bytea, text) TO iga_admin;
-- audit_write and the trigger functions are intentionally granted to nobody: triggers fire without an EXECUTE check,
-- and audit_write is only ever reached through them.

-- ---------------------------------------------------------------------------------------------
-- 6. Future objects (phase 5 tables, extra views): same rules without editing this file
-- ---------------------------------------------------------------------------------------------
ALTER DEFAULT PRIVILEGES IN SCHEMA iga GRANT SELECT ON TABLES TO iga_auditor;
ALTER DEFAULT PRIVILEGES IN SCHEMA iga GRANT ALL    ON TABLES TO iga_admin;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON ROUTINES FROM PUBLIC;   -- new functions are closed until granted

COMMIT;
