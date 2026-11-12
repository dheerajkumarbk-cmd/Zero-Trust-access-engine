-- 03_functions.sql  (schema iga)
-- Audit-chain helper functions and the three lifecycle procedures (joiner, mover, leaver).
-- Re-runnable: everything is CREATE OR REPLACE.
\set ON_ERROR_STOP on
BEGIN;
SET search_path = iga, public;

-- ---------------------------------------------------------------------------
-- audit_canonical: turns one audit row into one exact piece of text.
-- Concept: a hash is only useful if the text being hashed is byte-for-byte the
-- same every time. So nothing here may depend on session settings (TimeZone,
-- DateStyle, extra_float_digits, locale): the timestamp is rendered in UTC with
-- a fixed pattern, numbers use ::text, and jsonb::text always prints keys in
-- one fixed order. Every field is length-prefixed ('V5:hello;') and NULL is
-- 'N;', so ("ab","c") can never look the same as ("a","bc").
-- Field order: seq, occurred_at, actor, action, table, row_pk, old, new.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit_canonical(
    p_seq bigint, p_occurred_at timestamptz, p_actor text, p_action text,
    p_table text, p_row_pk text, p_old jsonb, p_new jsonb)
RETURNS text
LANGUAGE sql IMMUTABLE
AS $$
    SELECT string_agg(
               CASE WHEN t.v IS NULL THEN 'N;'
                    ELSE 'V' || length(t.v) || ':' || t.v || ';' END,
               '' ORDER BY t.ord)
    FROM (VALUES
        (1, p_seq::text),
        (2, to_char(p_occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')),
        (3, p_actor),
        (4, p_action),
        (5, p_table),
        (6, p_row_pk),
        (7, p_old::text),
        (8, p_new::text)
    ) AS t(ord, v);
$$;

-- ---------------------------------------------------------------------------
-- audit_hash: the link of the chain.
-- Concept: row_hash = SHA-256(previous row's hash || this row's canonical text).
-- Changing any old row changes its hash, which no longer matches the next
-- row's prev_hash, so the break is visible. sha256() is built in (PostgreSQL 11+).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit_hash(p_prev bytea, p_canonical text)
RETURNS bytea
LANGUAGE sql IMMUTABLE
AS $$
    SELECT sha256(p_prev || convert_to(p_canonical, 'UTF8'));
$$;

-- ---------------------------------------------------------------------------
-- audit_write: the only way a row gets into audit_log.
-- Concepts: (1) SECURITY DEFINER - runs with the owner's rights, so ordinary
-- roles can have NO insert right on audit_log yet still cause audit rows through
-- triggers. The search_path is pinned so nobody can hijack it with a fake table.
-- (2) A transaction-level advisory lock makes writers take turns: two writers
-- can never read the same "previous hash" and fork the chain. The lock is
-- released automatically at COMMIT or ROLLBACK, and a rolled-back transaction
-- leaves no gap because its audit row is rolled back too.
-- Note: the read of max(seq) happens after the lock, in a fresh statement
-- snapshot, which is correct under READ COMMITTED (the default).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit_write(
    p_actor text, p_action text, p_table text, p_row_pk text,
    p_old jsonb, p_new jsonb)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = iga, pg_temp
AS $$
DECLARE
    v_prev_seq  bigint;
    v_prev_hash bytea;
    v_seq       bigint;
    v_now       timestamptz;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('iga.audit_log'));

    SELECT a.seq, a.row_hash
      INTO v_prev_seq, v_prev_hash
      FROM iga.audit_log a
     ORDER BY a.seq DESC
     LIMIT 1;

    IF NOT FOUND THEN
        v_prev_seq  := 0;
        v_prev_hash := decode(repeat('00', 32), 'hex');
    END IF;

    v_seq := v_prev_seq + 1;
    v_now := date_trunc('microseconds', clock_timestamp());

    INSERT INTO iga.audit_log
        (seq, occurred_at, actor, action, table_name, row_pk,
         old_row, new_row, prev_hash, row_hash)
    VALUES
        (v_seq, v_now, p_actor, p_action, p_table, p_row_pk,
         p_old, p_new, v_prev_hash,
         iga.audit_hash(v_prev_hash,
             iga.audit_canonical(v_seq, v_now, p_actor, p_action, p_table, p_row_pk, p_old, p_new)));

    RETURN v_seq;
END;
$$;

-- ---------------------------------------------------------------------------
-- verify_audit_chain: walks the log from the first row to the last and returns
-- the first seq that is wrong, or NULL if the whole chain is intact.
-- A row is wrong if: its seq is not previous+1 (a row was deleted or inserted),
-- or its prev_hash is not the previous row's row_hash (the link is broken), or
-- its row_hash differs from the hash recomputed from its own contents (the row
-- was edited). The first row must have seq 1 and 32 zero bytes as prev_hash.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION verify_audit_chain()
RETURNS bigint
LANGUAGE plpgsql STABLE
SET search_path = iga, pg_temp
AS $$
DECLARE
    r             record;
    v_expect_seq  bigint := 1;
    v_expect_prev bytea  := decode(repeat('00', 32), 'hex');
BEGIN
    FOR r IN
        SELECT a.seq, a.occurred_at, a.actor, a.action, a.table_name, a.row_pk,
               a.old_row, a.new_row, a.prev_hash, a.row_hash
          FROM iga.audit_log a
         ORDER BY a.seq
    LOOP
        IF r.seq IS DISTINCT FROM v_expect_seq THEN
            RETURN r.seq;                      -- gap (or duplicate/out-of-order)
        END IF;
        IF r.prev_hash IS DISTINCT FROM v_expect_prev THEN
            RETURN r.seq;                      -- link to previous row broken
        END IF;
        IF r.row_hash IS DISTINCT FROM iga.audit_hash(r.prev_hash,
               iga.audit_canonical(r.seq, r.occurred_at, r.actor, r.action,
                                   r.table_name, r.row_pk, r.old_row, r.new_row)) THEN
            RETURN r.seq;                      -- row contents were changed
        END IF;
        v_expect_seq  := r.seq + 1;
        v_expect_prev := r.row_hash;
    END LOOP;
    RETURN NULL;
END;
$$;

-- ---------------------------------------------------------------------------
-- joiner: hire a person.
-- Concept: ATOMICITY. A procedure body runs inside the caller's transaction and
-- contains no COMMIT, so person + accounts + grants + lifecycle event are
-- all-or-nothing. If one requested extra role does not exist, the exception
-- aborts the statement and PostgreSQL undoes every earlier step: no half-hired
-- person is left behind. Foreign keys and CHECKs are verified as part of it.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE joiner(
    p_employee_no text, p_full_name text, p_email text,
    p_dept_id bigint, p_manager_id bigint, p_hire_date date,
    p_system_ids bigint[],
    p_extra_roles text[] DEFAULT '{}',
    INOUT p_person_id bigint DEFAULT NULL)
LANGUAGE plpgsql
SET search_path = iga, public
AS $$
DECLARE
    v_name  text;
    v_found integer;
BEGIN
    IF p_system_ids IS NULL OR cardinality(p_system_ids) = 0 THEN
        RAISE EXCEPTION 'joiner needs at least one system id';
    END IF;

    -- 1. the person
    INSERT INTO person (employee_no, full_name, email, dept_id, manager_id, status, hire_date)
    VALUES (p_employee_no, p_full_name, p_email, p_dept_id, p_manager_id, 'active', p_hire_date)
    RETURNING person_id INTO p_person_id;

    -- 2. one human account per requested system
    INSERT INTO account (person_id, system_id, username, account_type, status)
    SELECT p_person_id, s.system_id, lower(p_employee_no), 'human', 'active'
      FROM (SELECT DISTINCT unnest(p_system_ids) AS system_id) s;

    -- 3. birthright roles of the department, only for systems the person got an account in
    INSERT INTO role_assignment (account_id, role_id, granted_by)
    SELECT a.account_id, r.role_id, NULL
      FROM account a
      JOIN role r                  ON r.system_id = a.system_id
      JOIN dept_birthright_role b  ON b.role_id = r.role_id AND b.dept_id = p_dept_id
     WHERE a.person_id = p_person_id;

    -- 4. extra roles requested by name; a missing role aborts the whole joiner
    FOREACH v_name IN ARRAY COALESCE(p_extra_roles, '{}'::text[]) LOOP
        INSERT INTO role_assignment (account_id, role_id, granted_by)
        SELECT a.account_id, r.role_id, NULL
          FROM account a
          JOIN role r ON r.system_id = a.system_id AND r.name = v_name
         WHERE a.person_id = p_person_id
        ON CONFLICT (account_id, role_id) WHERE revoked_at IS NULL DO NOTHING;
        GET DIAGNOSTICS v_found = ROW_COUNT;

        IF v_found = 0 AND NOT EXISTS (
               SELECT 1
                 FROM account a
                 JOIN role r ON r.system_id = a.system_id AND r.name = v_name
                WHERE a.person_id = p_person_id) THEN
            RAISE EXCEPTION 'role % does not exist', v_name USING ERRCODE = 'P0002';
        END IF;
    END LOOP;

    -- 5. lifecycle record
    INSERT INTO lifecycle_event (person_id, event_type, new_dept_id, processed_at)
    VALUES (p_person_id, 'joiner', p_dept_id, now());
END;
$$;

-- ---------------------------------------------------------------------------
-- mover: change a person's department.
-- Concept: ROW LOCKING. SELECT ... FOR UPDATE locks the person row until the end
-- of the transaction, so two movers (or a mover and a leaver) on the same person
-- queue up instead of interleaving. Revoking the old roles, granting the new
-- ones and changing the department all commit together, so no other session
-- ever sees the person holding both sets. (Two sessions locking two people in
-- opposite order can deadlock; PostgreSQL detects it and aborts one of them.)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE mover(p_person_id bigint, p_new_dept_id bigint)
LANGUAGE plpgsql
SET search_path = iga, public
AS $$
DECLARE
    v_old_dept bigint;
    v_status   text;
BEGIN
    SELECT p.dept_id, p.status
      INTO v_old_dept, v_status
      FROM person p
     WHERE p.person_id = p_person_id
       FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'person % does not exist', p_person_id USING ERRCODE = 'P0002';
    END IF;
    IF v_status = 'terminated' THEN
        RAISE EXCEPTION 'person % is terminated and cannot move', p_person_id;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM department d WHERE d.dept_id = p_new_dept_id) THEN
        RAISE EXCEPTION 'department % does not exist', p_new_dept_id USING ERRCODE = 'P0002';
    END IF;

    -- revoke birthright roles of the old department that the new one does not give
    UPDATE role_assignment ra
       SET revoked_at = now()
      FROM account a
     WHERE ra.account_id = a.account_id
       AND a.person_id = p_person_id
       AND ra.revoked_at IS NULL
       AND EXISTS (SELECT 1 FROM dept_birthright_role o
                    WHERE o.dept_id = v_old_dept AND o.role_id = ra.role_id)
       AND NOT EXISTS (SELECT 1 FROM dept_birthright_role n
                        WHERE n.dept_id = p_new_dept_id AND n.role_id = ra.role_id);

    -- grant the new department's birthright roles on active accounts (skip live ones)
    INSERT INTO role_assignment (account_id, role_id, granted_by)
    SELECT a.account_id, r.role_id, NULL
      FROM account a
      JOIN role r                 ON r.system_id = a.system_id
      JOIN dept_birthright_role b ON b.role_id = r.role_id AND b.dept_id = p_new_dept_id
     WHERE a.person_id = p_person_id
       AND a.status = 'active'
       AND NOT EXISTS (SELECT 1 FROM role_assignment x
                        WHERE x.account_id = a.account_id
                          AND x.role_id = r.role_id
                          AND x.revoked_at IS NULL);

    UPDATE person SET dept_id = p_new_dept_id WHERE person_id = p_person_id;

    INSERT INTO lifecycle_event (person_id, event_type, old_dept_id, new_dept_id, processed_at)
    VALUES (p_person_id, 'mover', v_old_dept, p_new_dept_id, now());
END;
$$;

-- ---------------------------------------------------------------------------
-- leaver: terminate a person.
-- Concept: CONSISTENCY. All access is taken away in one transaction: live
-- assignments are revoked first, then the person is marked terminated (which
-- fires trg_leaver_cascade), then every account is disabled. Constraints and
-- triggers are checked as the statements run, so the committed state never has
-- a terminated person with live access. The person row is locked FOR UPDATE so
-- a concurrent mover/leaver on the same person must wait.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE leaver(p_person_id bigint, p_end_date date DEFAULT current_date)
LANGUAGE plpgsql
SET search_path = iga, public
AS $$
DECLARE
    v_dept   bigint;
    v_status text;
BEGIN
    SELECT p.dept_id, p.status
      INTO v_dept, v_status
      FROM person p
     WHERE p.person_id = p_person_id
       FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'person % does not exist', p_person_id USING ERRCODE = 'P0002';
    END IF;
    IF v_status = 'terminated' THEN
        RAISE EXCEPTION 'person % is already terminated', p_person_id;
    END IF;

    -- 1. revoke every live assignment (before the status change, so no trigger conflicts)
    UPDATE role_assignment ra
       SET revoked_at = now()
      FROM account a
     WHERE ra.account_id = a.account_id
       AND a.person_id = p_person_id
       AND ra.revoked_at IS NULL;

    -- 2. terminate the person
    UPDATE person
       SET status   = 'terminated',
           end_date = greatest(COALESCE(p_end_date, current_date), hire_date)
     WHERE person_id = p_person_id;

    -- 3. disable every account (trg_leaver_cascade already did; this makes the procedure self-contained)
    UPDATE account SET status = 'disabled'
     WHERE person_id = p_person_id AND status <> 'disabled';

    -- 4. phase 5: end open privileged sessions, only if that table (with the expected columns) exists
    IF to_regclass('iga.privileged_session') IS NOT NULL
       AND (SELECT count(*) FROM pg_attribute
             WHERE attrelid = to_regclass('iga.privileged_session')
               AND attname IN ('account_id', 'ended_at') AND NOT attisdropped) = 2 THEN
        EXECUTE 'UPDATE iga.privileged_session SET ended_at = now()
                  WHERE ended_at IS NULL
                    AND account_id IN (SELECT account_id FROM iga.account WHERE person_id = $1)'
          USING p_person_id;
    END IF;

    -- 5. lifecycle record
    INSERT INTO lifecycle_event (person_id, event_type, old_dept_id, processed_at)
    VALUES (p_person_id, 'leaver', v_dept, now());
END;
$$;

COMMIT;
