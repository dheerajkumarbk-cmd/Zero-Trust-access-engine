-- 06_indexes.sql: the six indexes of spec section 7. Re-runnable (IF NOT EXISTS). Run after 01..05.
-- On the partitioned security_event table an index created on the parent is created on every partition.
\set ON_ERROR_STOP on
BEGIN;
SET search_path = iga, public;

-- "Last 50 events for this account": equality on account_id, then newest first with no sort.
CREATE INDEX IF NOT EXISTS ix_event_account_time ON security_event (account_id, occurred_at DESC);

-- Time-range scans on an append-only table, at a fraction of a B-tree's size.
CREATE INDEX IF NOT EXISTS brin_event_time ON security_event USING brin (occurred_at);

-- Search inside the JSONB details (device, country, method ...) with @>.
CREATE INDEX IF NOT EXISTS gin_event_details ON security_event USING gin (details);

-- "What does this account hold right now?": only live grants are indexed, revoked history is not.
CREATE INDEX IF NOT EXISTS ix_role_assignment_live ON role_assignment (account_id) WHERE revoked_at IS NULL;

-- Dormant account report: only active accounts, ordered by last login.
CREATE INDEX IF NOT EXISTS ix_account_active_login ON account (last_login_at) WHERE status = 'active';

-- Case-insensitive e-mail lookup.
CREATE INDEX IF NOT EXISTS ix_person_email_lower ON person (lower(email));

COMMIT;
ANALYZE security_event;
ANALYZE role_assignment;
ANALYZE account;
ANALYZE person;
