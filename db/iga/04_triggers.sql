-- 04_triggers.sql  (schema iga)
-- Audit triggers, the append-only guard on audit_log, the grant guard, the leaver safety net.
-- Re-runnable: functions are CREATE OR REPLACE, triggers are dropped first.
\set ON_ERROR_STOP on
BEGIN;
SET search_path = iga, public;

-- ---------------------------------------------------------------------------
-- trg_audit_row: one generic AFTER row trigger that records every change.
-- Concept: a trigger runs inside the statement that fired it, in the same
-- transaction, so the audit row and the change commit or roll back together.
-- TG_ARGV[0] names the primary-key column of the audited table.
-- SECURITY DEFINER lets the trigger write to audit_log on behalf of roles that
-- have no right on that table. The actor shows the login (session_user) and the
-- role that is active in the caller's session (SET ROLE is visible through
-- current_setting('role'); plain current_user would show the function owner).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION trg_audit_row()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = iga, pg_temp
AS $$
DECLARE
    v_old   jsonb;
    v_new   jsonb;
    v_pk    text;
    v_actor text;
BEGIN
    IF TG_OP = 'INSERT' THEN
        v_new := to_jsonb(NEW);
        v_pk  := v_new ->> TG_ARGV[0];
    ELSIF TG_OP = 'UPDATE' THEN
        v_old := to_jsonb(OLD);
        v_new := to_jsonb(NEW);
        v_pk  := v_new ->> TG_ARGV[0];
    ELSE  -- DELETE
        v_old := to_jsonb(OLD);
        v_pk  := v_old ->> TG_ARGV[0];
    END IF;

    v_actor := session_user || '/' ||
               CASE WHEN current_setting('role') = 'none' THEN session_user
                    ELSE current_setting('role') END;

    PERFORM iga.audit_write(v_actor, TG_OP, TG_TABLE_NAME::text, v_pk, v_old, v_new);
    RETURN NULL;  -- AFTER trigger: return value is ignored
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_person ON person;
CREATE TRIGGER trg_audit_person
    AFTER INSERT OR UPDATE OR DELETE ON person
    FOR EACH ROW EXECUTE FUNCTION trg_audit_row('person_id');

DROP TRIGGER IF EXISTS trg_audit_account ON account;
CREATE TRIGGER trg_audit_account
    AFTER INSERT OR UPDATE OR DELETE ON account
    FOR EACH ROW EXECUTE FUNCTION trg_audit_row('account_id');

DROP TRIGGER IF EXISTS trg_audit_role_assignment ON role_assignment;
CREATE TRIGGER trg_audit_role_assignment
    AFTER INSERT OR UPDATE OR DELETE ON role_assignment
    FOR EACH ROW EXECUTE FUNCTION trg_audit_row('assignment_id');

-- ---------------------------------------------------------------------------
-- trg_audit_immutable: audit_log is append-only.
-- Concept: a BEFORE trigger that always raises an exception cancels the
-- statement. Used for row UPDATE/DELETE and, as a statement trigger, TRUNCATE
-- (TRUNCATE does not fire row triggers, so it needs its own trigger).
-- A superuser can still disable the trigger; verify_audit_chain() then
-- exposes the tampering.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION trg_audit_immutable()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = iga, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only: % rejected', TG_OP;
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_immutable ON audit_log;
CREATE TRIGGER trg_audit_immutable
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION trg_audit_immutable();

DROP TRIGGER IF EXISTS trg_audit_no_truncate ON audit_log;
CREATE TRIGGER trg_audit_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION trg_audit_immutable();

-- ---------------------------------------------------------------------------
-- trg_no_grant_to_terminated: business rule enforced in the database.
-- Concept: a BEFORE INSERT trigger can reject a row before it is stored, so no
-- application path (procedure, ad-hoc SQL, future code) can give a role to a
-- terminated person or to a disabled account. Service accounts (person_id NULL)
-- are checked only on the account's own status.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION trg_no_grant_to_terminated()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = iga, pg_temp
AS $$
DECLARE
    v_acc_status    text;
    v_person_status text;
BEGIN
    SELECT a.status, p.status
      INTO v_acc_status, v_person_status
      FROM iga.account a
      LEFT JOIN iga.person p ON p.person_id = a.person_id
     WHERE a.account_id = NEW.account_id;

    IF NOT FOUND THEN
        RETURN NEW;  -- unknown account: the foreign key reports it
    END IF;

    IF v_person_status = 'terminated' THEN
        RAISE EXCEPTION 'grant to terminated person rejected';
    END IF;
    IF v_acc_status = 'disabled' THEN
        RAISE EXCEPTION 'grant to disabled account rejected';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_no_grant_to_terminated ON role_assignment;
CREATE TRIGGER trg_no_grant_to_terminated
    BEFORE INSERT ON role_assignment
    FOR EACH ROW EXECUTE FUNCTION trg_no_grant_to_terminated();

-- ---------------------------------------------------------------------------
-- trg_leaver_cascade: safety net.
-- Concept: if someone sets a person to 'terminated' by hand (not through the
-- leaver procedure), the accounts are still disabled in the same statement.
-- The WHEN clause makes it fire only on the change into 'terminated'.
-- It does not revoke assignments; v_leaver_residual_access shows that gap.
-- The UPDATE on account in turn fires trg_audit_account.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION trg_leaver_cascade()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = iga, pg_temp
AS $$
BEGIN
    UPDATE iga.account
       SET status = 'disabled'
     WHERE person_id = NEW.person_id
       AND status <> 'disabled';
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS trg_leaver_cascade ON person;
CREATE TRIGGER trg_leaver_cascade
    AFTER UPDATE OF status ON person
    FOR EACH ROW
    WHEN (NEW.status = 'terminated' AND OLD.status IS DISTINCT FROM 'terminated')
    EXECUTE FUNCTION trg_leaver_cascade();


-- ---------------------------------------------------------------------------
-- Segregation of duties (phase 5, spec test 4): a live grant is rejected when the same account already holds
-- a live role that forms a rule pair (sod_rule) with the new role. Enforced here, in the database, so that no
-- application path (procedure, script, manual SQL) can bypass it. A per-account advisory lock serialises
-- concurrent grants, otherwise two sessions could each pass the check and both insert.
-- Existing violations (the seed plants three) are reported by v_sod_violations; they are not blocked retroactively.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION trg_sod_check()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = iga, pg_temp
AS $$
DECLARE
    v_other bigint;
BEGIN
    IF NEW.revoked_at IS NOT NULL OR (NEW.valid_to IS NOT NULL AND NEW.valid_to <= now()) THEN
        RETURN NEW;  -- not a live grant: nothing to protect
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('iga.sod_check'), NEW.account_id::int);
    SELECT ra.role_id
      INTO v_other
      FROM iga.role_assignment ra
      JOIN iga.sod_rule sr
        ON (sr.role_a = NEW.role_id AND sr.role_b = ra.role_id)
        OR (sr.role_b = NEW.role_id AND sr.role_a = ra.role_id)
     WHERE ra.account_id = NEW.account_id
       AND ra.revoked_at IS NULL
       AND (ra.valid_to IS NULL OR ra.valid_to > now())
       AND ra.assignment_id IS DISTINCT FROM NEW.assignment_id
     LIMIT 1;
    IF FOUND THEN
        RAISE EXCEPTION 'segregation of duties: role % conflicts with live role % on account %',
            NEW.role_id, v_other, NEW.account_id USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_sod_check ON role_assignment;
CREATE TRIGGER trg_sod_check
    BEFORE INSERT OR UPDATE OF role_id, revoked_at, valid_to ON role_assignment
    FOR EACH ROW EXECUTE FUNCTION trg_sod_check();
-- ---------------------------------------------------------------------------
-- Privileges: nobody except the owner may change audit rows or call audit_write
-- directly (the triggers call it as the owner). Application roles come in 07.
-- ---------------------------------------------------------------------------
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM PUBLIC;
REVOKE ALL ON FUNCTION audit_write(text, text, text, text, jsonb, jsonb) FROM PUBLIC;

COMMIT;
