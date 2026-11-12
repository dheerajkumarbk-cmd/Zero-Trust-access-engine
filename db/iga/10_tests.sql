-- 10_tests.sql: automated tests for schema iga (spec section 12 + extras).
-- Run:  db/iga/run.sh 10_tests.sql
-- Output: one line per test (PASS n name | FAIL n name: detail | SKIP n name: reason), then
--         SUMMARY pass=X fail=Y skip=Z
-- Every test builds its own fixture rows inside a subtransaction (inner BEGIN ... EXCEPTION block)
-- and undoes them by raising a marker exception (SQLSTATE T0001). The whole script additionally runs
-- inside BEGIN ... ROLLBACK, so the database is unchanged afterwards.
-- A test whose objects are not built yet records SKIP (to_regclass / pg_proc checks).
\set QUIET on
\set ON_ERROR_STOP on
SET client_min_messages = warning;
SET search_path = iga, public;

BEGIN;

CREATE TEMP TABLE test_result(n int, name text, status text, detail text);

-- ---------------------------------------------------------------------------------------------
-- Helpers (temp schema: vanish with the session / the final ROLLBACK)
-- ---------------------------------------------------------------------------------------------

-- Names of missing objects. Items 'p:name' = a routine named name in schema iga; anything else = relation.
CREATE FUNCTION pg_temp.missing(VARIADIC p_items text[]) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE v_item text; v_out text := '';
BEGIN
  FOREACH v_item IN ARRAY p_items LOOP
    IF v_item LIKE 'p:%' THEN
      IF NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                      WHERE n.nspname = 'iga' AND p.proname = substr(v_item, 3)) THEN
        v_out := v_out || ' ' || v_item;
      END IF;
    ELSIF to_regclass(v_item) IS NULL THEN
      v_out := v_out || ' ' || v_item;
    END IF;
  END LOOP;
  RETURN nullif(btrim(v_out), '');
END $f$;

-- Run a statement; never raises. ok=true, or ok=false with SQLSTATE, constraint name and message.
CREATE FUNCTION pg_temp.try(p_sql text) RETURNS jsonb LANGUAGE plpgsql AS $f$
DECLARE v_c text; v_m text;
BEGIN
  EXECUTE p_sql;
  RETURN jsonb_build_object('ok', true);
EXCEPTION WHEN OTHERS THEN
  GET STACKED DIAGNOSTICS v_c = CONSTRAINT_NAME, v_m = MESSAGE_TEXT;
  RETURN jsonb_build_object('ok', false, 'state', SQLSTATE, 'constraint', v_c, 'msg', v_m);
END $f$;

-- Minimal fixture: department, person (active, or terminated with end_date), system, human account, role.
CREATE FUNCTION pg_temp.fix(p_tag text, p_terminated boolean DEFAULT false) RETURNS jsonb LANGUAGE plpgsql AS $f$
DECLARE v_dept bigint; v_person bigint; v_sys bigint; v_acct bigint; v_role bigint;
BEGIN
  INSERT INTO iga.department(name) VALUES ('zz_test_dept_' || p_tag) RETURNING dept_id INTO v_dept;
  INSERT INTO iga.person(employee_no, full_name, email, dept_id, status, hire_date, end_date)
  VALUES ('zz_' || p_tag, 'ZZ Test ' || p_tag, 'zz_' || p_tag || '@zz.invalid', v_dept,
          CASE WHEN p_terminated THEN 'terminated' ELSE 'active' END,
          date '2020-01-01', CASE WHEN p_terminated THEN date '2025-01-01' END)
  RETURNING person_id INTO v_person;
  INSERT INTO iga.system(name, criticality) VALUES ('zz_test_sys_' || p_tag, 2) RETURNING system_id INTO v_sys;
  INSERT INTO iga.account(person_id, system_id, username, account_type, status)
  VALUES (v_person, v_sys, 'zz_' || p_tag, 'human', 'active') RETURNING account_id INTO v_acct;
  INSERT INTO iga.role(system_id, name, is_privileged) VALUES (v_sys, 'zz_role_' || p_tag, false)
  RETURNING role_id INTO v_role;
  RETURN jsonb_build_object('dept', v_dept, 'person', v_person, 'system', v_sys, 'account', v_acct, 'role', v_role);
END $f$;

-- Live (not revoked) assignments of one role on all accounts of a person.
CREATE FUNCTION pg_temp.live(p_person bigint, p_role bigint) RETURNS bigint LANGUAGE plpgsql AS $f$
BEGIN
  RETURN (SELECT count(*) FROM iga.role_assignment ra JOIN iga.account a ON a.account_id = ra.account_id
           WHERE a.person_id = p_person AND ra.role_id = p_role AND ra.revoked_at IS NULL);
END $f$;

-- ---------------------------------------------------------------------------------------------
-- 1  person end_date before hire_date rejected
-- ---------------------------------------------------------------------------------------------
DO $$
DECLARE v_m text; v jsonb; r jsonb; st text := 'FAIL'; dt text;
BEGIN
  v_m := pg_temp.missing('iga.person', 'iga.department');
  IF v_m IS NOT NULL THEN
    INSERT INTO test_result VALUES (1, 'person end_date before hire_date rejected', 'SKIP', 'not built: ' || v_m); RETURN;
  END IF;
  BEGIN
    v := pg_temp.fix('t1');
    r := pg_temp.try(format($q$INSERT INTO iga.person(employee_no, full_name, email, dept_id, status, hire_date, end_date)
                              VALUES ('zz_t1b','ZZ t1b','zz_t1b@zz.invalid', %s, 'active', DATE '2024-01-02', DATE '2024-01-01')$q$,
                            v->>'dept'));
    IF (r->>'ok')::boolean THEN dt := 'insert was accepted';
    ELSIF r->>'state' = '23514' AND r->>'constraint' = 'ck_person_dates' THEN st := 'PASS';
    ELSE dt := 'wrong error: ' || r::text; END IF;
    RAISE EXCEPTION 'rollback-marker' USING ERRCODE = 'T0001';
  EXCEPTION
    WHEN SQLSTATE 'T0001' THEN NULL;
    WHEN OTHERS THEN st := 'FAIL'; dt := 'unexpected ' || SQLSTATE || ': ' || SQLERRM;
  END;
  INSERT INTO test_result VALUES (1, 'person end_date before hire_date rejected', st, dt);
END $$;

-- ---------------------------------------------------------------------------------------------
-- 2  duplicate username in one system rejected
-- ---------------------------------------------------------------------------------------------
DO $$
DECLARE v_m text; v jsonb; r jsonb; st text := 'FAIL'; dt text;
BEGIN
  v_m := pg_temp.missing('iga.account', 'iga.person', 'iga.system');
  IF v_m IS NOT NULL THEN
    INSERT INTO test_result VALUES (2, 'duplicate username in one system rejected', 'SKIP', 'not built: ' || v_m); RETURN;
  END IF;
  BEGIN
    v := pg_temp.fix('t2');
    r := pg_temp.try(format($q$INSERT INTO iga.account(person_id, system_id, username, account_type)
                              VALUES (%s, %s, 'zz_t2', 'human')$q$, v->>'person', v->>'system'));
    IF (r->>'ok')::boolean THEN dt := 'duplicate insert was accepted';
    ELSIF r->>'state' = '23505' AND r->>'constraint' = 'uq_account_system_username' THEN st := 'PASS';
    ELSE dt := 'wrong error: ' || r::text; END IF;
    RAISE EXCEPTION 'rollback-marker' USING ERRCODE = 'T0001';
  EXCEPTION
    WHEN SQLSTATE 'T0001' THEN NULL;
    WHEN OTHERS THEN st := 'FAIL'; dt := 'unexpected ' || SQLSTATE || ': ' || SQLERRM;
  END;
  INSERT INTO test_result VALUES (2, 'duplicate username in one system rejected', st, dt);
END $$;

-- ---------------------------------------------------------------------------------------------
-- 3  grant to an account of a terminated person rejected (trg_no_grant_to_terminated)
-- ---------------------------------------------------------------------------------------------
DO $$
DECLARE v_m text; v jsonb; r jsonb; st text := 'FAIL'; dt text;
BEGIN
  v_m := pg_temp.missing('iga.role_assignment', 'iga.account', 'iga.person', 'iga.role');
  IF v_m IS NOT NULL THEN
    INSERT INTO test_result VALUES (3, 'grant to terminated person rejected', 'SKIP', 'not built: ' || v_m); RETURN;
  END IF;
  BEGIN
    v := pg_temp.fix('t3', true);   -- person inserted directly as terminated, account still active
    r := pg_temp.try(format('INSERT INTO iga.role_assignment(account_id, role_id) VALUES (%s, %s)',
                            v->>'account', v->>'role'));
    IF (r->>'ok')::boolean THEN dt := 'grant was accepted';
    ELSIF r->>'state' = 'P0001' AND r->>'msg' LIKE 'grant to terminated%' THEN st := 'PASS';
    ELSE dt := 'wrong error: ' || r::text; END IF;
    RAISE EXCEPTION 'rollback-marker' USING ERRCODE = 'T0001';
  EXCEPTION
    WHEN SQLSTATE 'T0001' THEN NULL;
    WHEN OTHERS THEN st := 'FAIL'; dt := 'unexpected ' || SQLSTATE || ': ' || SQLERRM;
  END;
  INSERT INTO test_result VALUES (3, 'grant to terminated person rejected', st, dt);
END $$;

-- ---------------------------------------------------------------------------------------------
-- 4  segregation-of-duties grant rejected (phase 5: trg_sod_check)
-- ---------------------------------------------------------------------------------------------
DO $$
DECLARE v_m text; v jsonb; r jsonb; v_r2 bigint; v_a bigint; v_b bigint; st text := 'FAIL'; dt text;
BEGIN
  v_m := pg_temp.missing('iga.sod_rule', 'iga.role_assignment');
  IF v_m IS NULL AND NOT EXISTS (SELECT 1 FROM pg_trigger
                                  WHERE tgname = 'trg_sod_check' AND tgrelid = to_regclass('iga.role_assignment')) THEN
    v_m := 'trigger trg_sod_check';
  END IF;
  IF v_m IS NOT NULL THEN
    INSERT INTO test_result VALUES (4, 'segregation-of-duties grant rejected', 'SKIP', 'not built: ' || v_m); RETURN;
  END IF;
  BEGIN
    v := pg_temp.fix('t4');
    INSERT INTO iga.role(system_id, name) VALUES ((v->>'system')::bigint, 'zz_role_t4b') RETURNING role_id INTO v_r2;
    v_a := least((v->>'role')::bigint, v_r2);
    v_b := greatest((v->>'role')::bigint, v_r2);
    INSERT INTO iga.sod_rule(role_a, role_b, description) VALUES (v_a, v_b, 'zz_test_rule');
    r := pg_temp.try(format('INSERT INTO iga.role_assignment(account_id, role_id) VALUES (%s, %s)', v->>'account', v->>'role'));
    IF NOT (r->>'ok')::boolean THEN
      dt := 'first (non-conflicting) grant failed: ' || r::text;
    ELSE
      r := pg_temp.try(format('INSERT INTO iga.role_assignment(account_id, role_id) VALUES (%s, %s)', v->>'account', v_r2));
      IF (r->>'ok')::boolean THEN dt := 'conflicting grant was accepted';
      ELSIF r->>'state' = '23505' THEN dt := 'rejected by unique index, not by SoD rule: ' || r::text;
      ELSE st := 'PASS'; dt := 'rejected: ' || (r->>'state') || ' ' || (r->>'msg'); END IF;
    END IF;
    RAISE EXCEPTION 'rollback-marker' USING ERRCODE = 'T0001';
  EXCEPTION
    WHEN SQLSTATE 'T0001' THEN NULL;
    WHEN OTHERS THEN st := 'FAIL'; dt := 'unexpected ' || SQLSTATE || ': ' || SQLERRM;
  END;
  IF st = 'PASS' THEN dt := NULL; END IF;
  INSERT INTO test_result VALUES (4, 'segregation-of-duties grant rejected', st, dt);
END $$;

-- ---------------------------------------------------------------------------------------------
-- 5  overlapping privileged sessions rejected (phase 5: privileged_session EXCLUDE constraint)
-- ---------------------------------------------------------------------------------------------
DO $$
DECLARE v_m text; v jsonb; r jsonb; v_appr bigint; st text := 'FAIL'; dt text;
BEGIN
  v_m := pg_temp.missing('iga.privileged_session');
  IF v_m IS NOT NULL THEN
    INSERT INTO test_result VALUES (5, 'overlapping privileged sessions rejected', 'SKIP', 'not built: ' || v_m); RETURN;
  END IF;
  BEGIN
    v := pg_temp.fix('t5');
    UPDATE iga.role SET is_privileged = true WHERE role_id = (v->>'role')::bigint;
    INSERT INTO iga.person(employee_no, full_name, email, dept_id, hire_date)
    VALUES ('zz_t5_appr', 'ZZ t5 approver', 'zz_t5_appr@zz.invalid', (v->>'dept')::bigint, date '2020-01-01')
    RETURNING person_id INTO v_appr;
    INSERT INTO iga.role_assignment(account_id, role_id, granted_by)
    VALUES ((v->>'account')::bigint, (v->>'role')::bigint, v_appr);
    r := pg_temp.try(format($q$INSERT INTO iga.privileged_session(account_id, role_id, approved_by, reason, during)
        VALUES (%s, %s, %s, 'zz_t5 first', tstzrange(now(), now() + interval '2 hours'))$q$, v->>'account', v->>'role', v_appr));
    IF NOT (r->>'ok')::boolean THEN
      dt := 'first session insert failed: ' || r::text;
    ELSE
      r := pg_temp.try(format($q$INSERT INTO iga.privileged_session(account_id, role_id, approved_by, reason, during)
          VALUES (%s, %s, %s, 'zz_t5 overlap', tstzrange(now() + interval '1 hour', now() + interval '3 hours'))$q$,
          v->>'account', v->>'role', v_appr));
      IF (r->>'ok')::boolean THEN dt := 'overlapping session was accepted';
      ELSIF r->>'state' <> '23P01' THEN dt := 'wrong error: ' || r::text;
      ELSE
        r := pg_temp.try(format($q$INSERT INTO iga.privileged_session(account_id, role_id, approved_by, reason, during)
            VALUES (%s, %s, %s, 'zz_t5 adjacent', tstzrange(now() + interval '2 hours', now() + interval '4 hours'))$q$,
            v->>'account', v->>'role', v_appr));
        IF (r->>'ok')::boolean THEN st := 'PASS';
        ELSE dt := 'adjacent non-overlapping session rejected: ' || r::text; END IF;
      END IF;
    END IF;
    RAISE EXCEPTION 'rollback-marker' USING ERRCODE = 'T0001';
  EXCEPTION
    WHEN SQLSTATE 'T0001' THEN NULL;
    WHEN OTHERS THEN st := 'FAIL'; dt := 'unexpected ' || SQLSTATE || ': ' || SQLERRM;
  END;
  INSERT INTO test_result VALUES (5, 'overlapping privileged sessions rejected', st, dt);
END $$;

-- ---------------------------------------------------------------------------------------------
-- 6  self-approved request rejected (phase 5: access_request)
-- ---------------------------------------------------------------------------------------------
DO $$
DECLARE v_m text; v jsonb; r jsonb; v_appr bigint; st text := 'FAIL'; dt text;
BEGIN
  v_m := pg_temp.missing('iga.access_request');
  IF v_m IS NOT NULL THEN
    INSERT INTO test_result VALUES (6, 'self-approved request rejected', 'SKIP', 'not built: ' || v_m); RETURN;
  END IF;
  BEGIN
    v := pg_temp.fix('t6');
    INSERT INTO iga.person(employee_no, full_name, email, dept_id, hire_date)
    VALUES ('zz_t6_appr', 'ZZ t6 approver', 'zz_t6_appr@zz.invalid', (v->>'dept')::bigint, date '2020-01-01')
    RETURNING person_id INTO v_appr;
    r := pg_temp.try(format($q$INSERT INTO iga.access_request(requester_id, account_id, role_id, justification, status, decided_by, decided_at)
        VALUES (%s, %s, %s, 'zz_t6 self', 'approved', %s, now())$q$, v->>'person', v->>'account', v->>'role', v->>'person'));
    IF (r->>'ok')::boolean THEN dt := 'self-approved request was accepted';
    ELSIF r->>'state' <> '23514' THEN dt := 'wrong error (expected check_violation): ' || r::text;
    ELSE
      r := pg_temp.try(format($q$INSERT INTO iga.access_request(requester_id, account_id, role_id, justification, status, decided_by, decided_at)
          VALUES (%s, %s, %s, 'zz_t6 other', 'approved', %s, now())$q$, v->>'person', v->>'account', v->>'role', v_appr));
      IF (r->>'ok')::boolean THEN st := 'PASS';
      ELSE dt := 'approval by a different person was rejected: ' || r::text; END IF;
    END IF;
    RAISE EXCEPTION 'rollback-marker' USING ERRCODE = 'T0001';
  EXCEPTION
    WHEN SQLSTATE 'T0001' THEN NULL;
    WHEN OTHERS THEN st := 'FAIL'; dt := 'unexpected ' || SQLSTATE || ': ' || SQLERRM;
  END;
  INSERT INTO test_result VALUES (6, 'self-approved request rejected', st, dt);
END $$;

-- ---------------------------------------------------------------------------------------------
-- 7  joiner with a bad role leaves no rows (P0002, all-or-nothing)
-- ---------------------------------------------------------------------------------------------
DO $$
DECLARE v_m text; v jsonb; r jsonb; st text := 'FAIL'; dt text;
        n_p0 bigint; n_a0 bigint; n_l0 bigint; n_g0 bigint; n_u0 bigint;
        n_p1 bigint; n_a1 bigint; n_l1 bigint; n_g1 bigint; n_u1 bigint;
BEGIN
  v_m := pg_temp.missing('iga.person', 'iga.account', 'iga.lifecycle_event', 'iga.role_assignment', 'iga.audit_log', 'p:joiner');
  IF v_m IS NOT NULL THEN
    INSERT INTO test_result VALUES (7, 'joiner with bad role leaves no rows', 'SKIP', 'not built: ' || v_m); RETURN;
  END IF;
  BEGIN
    v := pg_temp.fix('t7');
    SELECT count(*) INTO n_p0 FROM iga.person;
    SELECT count(*) INTO n_a0 FROM iga.account;
    SELECT count(*) INTO n_l0 FROM iga.lifecycle_event;
    SELECT count(*) INTO n_g0 FROM iga.role_assignment;
    SELECT count(*) INTO n_u0 FROM iga.audit_log;
    r := pg_temp.try(format($q$CALL iga.joiner('zz_t7j', 'ZZ t7 joiner', 'zz_t7j@zz.invalid', %s, NULL::bigint,
                              DATE '2026-01-01', ARRAY[%s]::bigint[], ARRAY['zz_no_such_role']::text[], NULL::bigint)$q$,
                            v->>'dept', v->>'system'));
    SELECT count(*) INTO n_p1 FROM iga.person;
    SELECT count(*) INTO n_a1 FROM iga.account;
    SELECT count(*) INTO n_l1 FROM iga.lifecycle_event;
    SELECT count(*) INTO n_g1 FROM iga.role_assignment;
    SELECT count(*) INTO n_u1 FROM iga.audit_log;
    IF (r->>'ok')::boolean THEN dt := 'joiner with unknown role succeeded';
    ELSIF r->>'state' <> 'P0002' THEN dt := 'wrong error (expected P0002): ' || r::text;
    ELSIF EXISTS (SELECT 1 FROM iga.person WHERE employee_no = 'zz_t7j') THEN dt := 'person row left behind';
    ELSIF EXISTS (SELECT 1 FROM iga.account WHERE username = 'zz_t7j') THEN dt := 'account row left behind';
    ELSIF EXISTS (SELECT 1 FROM iga.lifecycle_event le
                   WHERE le.person_id NOT IN (SELECT person_id FROM iga.person)) THEN dt := 'orphan lifecycle_event';
    ELSIF (n_p1, n_a1, n_l1, n_g1, n_u1) IS DISTINCT FROM (n_p0, n_a0, n_l0, n_g0, n_u0) THEN
      dt := format('row counts changed: person %s->%s account %s->%s lifecycle %s->%s assignment %s->%s audit %s->%s',
                   n_p0, n_p1, n_a0, n_a1, n_l0, n_l1, n_g0, n_g1, n_u0, n_u1);
    ELSE st := 'PASS'; END IF;
    RAISE EXCEPTION 'rollback-marker' USING ERRCODE = 'T0001';
  EXCEPTION
    WHEN SQLSTATE 'T0001' THEN NULL;
    WHEN OTHERS THEN st := 'FAIL'; dt := 'unexpected ' || SQLSTATE || ': ' || SQLERRM;
  END;
  INSERT INTO test_result VALUES (7, 'joiner with bad role leaves no rows', st, dt);
END $$;

-- ---------------------------------------------------------------------------------------------
-- 8  joiner then leaver leaves no residual access (v_leaver_residual_access, plus a direct check)
-- ---------------------------------------------------------------------------------------------
DO $$
DECLARE v_m text; v jsonb; r jsonb; v_pid bigint; v_view boolean; v_vcnt bigint := 0;
        st text := 'FAIL'; dt text; v_n bigint; v_status text; v_note text;
BEGIN
  v_m := pg_temp.missing('iga.person', 'iga.account', 'iga.role_assignment', 'iga.lifecycle_event',
                         'iga.dept_birthright_role', 'p:joiner', 'p:leaver');
  IF v_m IS NOT NULL THEN
    INSERT INTO test_result VALUES (8, 'leaver leaves no residual access', 'SKIP', 'not built: ' || v_m); RETURN;
  END IF;
  v_view := to_regclass('iga.v_leaver_residual_access') IS NOT NULL
            AND EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = to_regclass('iga.v_leaver_residual_access')
                         AND attname = 'person_id' AND NOT attisdropped);
  v_note := CASE WHEN v_view THEN NULL
                 ELSE 'view iga.v_leaver_residual_access missing (or without person_id): direct check only' END;
  BEGIN
    v := pg_temp.fix('t8');
    INSERT INTO iga.dept_birthright_role(dept_id, role_id) VALUES ((v->>'dept')::bigint, (v->>'role')::bigint);
    r := pg_temp.try(format($q$CALL iga.joiner('zz_t8j', 'ZZ t8 joiner', 'zz_t8j@zz.invalid', %s, NULL::bigint,
                              DATE '2026-01-01', ARRAY[%s]::bigint[], ARRAY[]::text[], NULL::bigint)$q$,
                            v->>'dept', v->>'system'));
    IF NOT (r->>'ok')::boolean THEN
      dt := 'joiner failed: ' || r::text;
    ELSE
      SELECT person_id INTO v_pid FROM iga.person WHERE employee_no = 'zz_t8j';
      IF pg_temp.live(v_pid, (v->>'role')::bigint) <> 1 THEN
        dt := 'precondition: joiner did not grant the birthright role';
      ELSE
        r := pg_temp.try(format('CALL iga.leaver(%s)', v_pid));
        IF NOT (r->>'ok')::boolean THEN
          dt := 'leaver failed: ' || r::text;
        ELSE
          IF v_view THEN
            EXECUTE format('SELECT count(*) FROM iga.v_leaver_residual_access x WHERE to_jsonb(x)->>%L = %L',
                           'person_id', v_pid::text) INTO v_vcnt;
          END IF;
          SELECT status INTO v_status FROM iga.person WHERE person_id = v_pid;
          IF v_vcnt <> 0 THEN dt := format('v_leaver_residual_access still has %s row(s) for the person', v_vcnt);
          ELSIF v_status <> 'terminated' THEN dt := 'person status is ' || coalesce(v_status, 'NULL');
          ELSE
            SELECT count(*) INTO v_n FROM iga.role_assignment ra JOIN iga.account a ON a.account_id = ra.account_id
             WHERE a.person_id = v_pid AND ra.revoked_at IS NULL;
            IF v_n <> 0 THEN dt := v_n || ' live role_assignment(s) remain';
            ELSE
              SELECT count(*) INTO v_n FROM iga.account WHERE person_id = v_pid;
              IF v_n < 1 THEN dt := 'precondition: person has no account';
              ELSE
                SELECT count(*) INTO v_n FROM iga.account WHERE person_id = v_pid AND status <> 'disabled';
                IF v_n <> 0 THEN dt := v_n || ' account(s) not disabled';
                ELSE
                  SELECT count(*) INTO v_n FROM iga.lifecycle_event WHERE person_id = v_pid AND event_type = 'leaver';
                  IF v_n <> 1 THEN dt := v_n || ' leaver lifecycle_event(s), expected 1';
                  ELSE st := 'PASS'; dt := v_note; END IF;
                END IF;
              END IF;
            END IF;
          END IF;
        END IF;
      END IF;
    END IF;
    RAISE EXCEPTION 'rollback-marker' USING ERRCODE = 'T0001';
  EXCEPTION
    WHEN SQLSTATE 'T0001' THEN NULL;
    WHEN OTHERS THEN st := 'FAIL'; dt := 'unexpected ' || SQLSTATE || ': ' || SQLERRM;
  END;
  INSERT INTO test_result VALUES (8, 'leaver leaves no residual access', st, dt);
END $$;

-- ---------------------------------------------------------------------------------------------
-- 9  UPDATE and DELETE on audit_log rejected
-- ---------------------------------------------------------------------------------------------
DO $$
DECLARE v_m text; v jsonb; r jsonb; st text := 'FAIL'; dt text;
BEGIN
  v_m := pg_temp.missing('iga.audit_log', 'iga.person', 'iga.department');
  IF v_m IS NOT NULL THEN
    INSERT INTO test_result VALUES (9, 'UPDATE/DELETE on audit_log rejected', 'SKIP', 'not built: ' || v_m); RETURN;
  END IF;
  BEGIN
    v := pg_temp.fix('t9');
    IF NOT EXISTS (SELECT 1 FROM iga.audit_log) THEN
      st := 'SKIP'; dt := 'no audit rows were written by the fixture (audit triggers not built?)';
    ELSE
      r := pg_temp.try('UPDATE iga.audit_log SET actor = actor || ''x'' WHERE seq = (SELECT max(seq) FROM iga.audit_log)');
      IF (r->>'ok')::boolean THEN dt := 'UPDATE was accepted';
      ELSIF NOT (r->>'state' = 'P0001' AND r->>'msg' LIKE 'audit_log is append-only%') THEN dt := 'UPDATE wrong error: ' || r::text;
      ELSE
        r := pg_temp.try('DELETE FROM iga.audit_log WHERE seq = (SELECT max(seq) FROM iga.audit_log)');
        IF (r->>'ok')::boolean THEN dt := 'DELETE was accepted';
        ELSIF NOT (r->>'state' = 'P0001' AND r->>'msg' LIKE 'audit_log is append-only%') THEN dt := 'DELETE wrong error: ' || r::text;
        ELSE st := 'PASS'; END IF;
      END IF;
    END IF;
    RAISE EXCEPTION 'rollback-marker' USING ERRCODE = 'T0001';
  EXCEPTION
    WHEN SQLSTATE 'T0001' THEN NULL;
    WHEN OTHERS THEN st := 'FAIL'; dt := 'unexpected ' || SQLSTATE || ': ' || SQLERRM;
  END;
  INSERT INTO test_result VALUES (9, 'UPDATE/DELETE on audit_log rejected', st, dt);
END $$;

-- ---------------------------------------------------------------------------------------------
-- 10  tamper detection: altered audit row is found by verify_audit_chain()
-- ---------------------------------------------------------------------------------------------
DO $$
DECLARE v_m text; v jsonb; r jsonb; v_s bigint; v_n bigint; v_ver bigint; v_tz text;
        st text := 'FAIL'; dt text;
BEGIN
  v_m := pg_temp.missing('iga.audit_log', 'iga.person', 'iga.account', 'iga.role_assignment', 'p:verify_audit_chain');
  IF v_m IS NOT NULL THEN
    INSERT INTO test_result VALUES (10, 'altered audit row is found by verifier', 'SKIP', 'not built: ' || v_m); RETURN;
  END IF;
  BEGIN
    v := pg_temp.fix('t10');
    INSERT INTO iga.role_assignment(account_id, role_id) VALUES ((v->>'account')::bigint, (v->>'role')::bigint);
    UPDATE iga.person SET full_name = 'ZZ Test t10 renamed' WHERE person_id = (v->>'person')::bigint;
    SELECT count(*) INTO v_n FROM iga.audit_log;
    IF v_n < 3 THEN
      st := 'SKIP'; dt := 'fewer than 3 audit rows after fixture (audit triggers not built?)';
    ELSE
      v_ver := iga.verify_audit_chain();
      IF v_ver IS NOT NULL THEN
        dt := 'chain not clean before tampering, first bad seq = ' || v_ver;
      ELSE
        SELECT seq INTO v_s FROM iga.audit_log ORDER BY seq DESC OFFSET 1 LIMIT 1;   -- a row that is not the last one
        ALTER TABLE iga.audit_log DISABLE TRIGGER trg_audit_immutable;
        UPDATE iga.audit_log SET new_row = coalesce(new_row, '{}'::jsonb) || '{"zz_tampered": true}'::jsonb WHERE seq = v_s;
        ALTER TABLE iga.audit_log ENABLE TRIGGER trg_audit_immutable;
        v_ver := iga.verify_audit_chain();
        IF v_ver IS DISTINCT FROM v_s THEN
          dt := format('verifier returned %s, expected %s', coalesce(v_ver::text, 'NULL'), v_s);
        ELSE
          -- same answer under a non-UTC time zone
          v_tz := current_setting('TimeZone');
          PERFORM set_config('TimeZone', 'Asia/Kolkata', true);
          v_ver := iga.verify_audit_chain();
          PERFORM set_config('TimeZone', v_tz, true);
          IF v_ver IS DISTINCT FROM v_s THEN
            dt := format('under TimeZone Asia/Kolkata verifier returned %s, expected %s', coalesce(v_ver::text, 'NULL'), v_s);
          ELSE
            -- trigger is enabled again: the row cannot be repaired by UPDATE
            r := pg_temp.try('UPDATE iga.audit_log SET actor = actor WHERE seq = ' || v_s);
            IF (r->>'ok')::boolean THEN dt := 'trg_audit_immutable was not re-enabled';
            ELSE st := 'PASS'; END IF;
          END IF;
        END IF;
      END IF;
    END IF;
    RAISE EXCEPTION 'rollback-marker' USING ERRCODE = 'T0001';   -- undoes the tampering and the ALTER TABLE
  EXCEPTION
    WHEN SQLSTATE 'T0001' THEN NULL;
    WHEN OTHERS THEN st := 'FAIL'; dt := 'unexpected ' || SQLSTATE || ': ' || SQLERRM;
  END;
  INSERT INTO test_result VALUES (10, 'altered audit row is found by verifier', st, dt);
END $$;

-- ---------------------------------------------------------------------------------------------
-- 11  one-month security_event query scans exactly one partition
-- ---------------------------------------------------------------------------------------------
DO $$
DECLARE v_m text; v_plan json; v_rels text[]; st text := 'FAIL'; dt text;
BEGIN
  v_m := pg_temp.missing('iga.security_event');
  IF v_m IS NOT NULL THEN
    INSERT INTO test_result VALUES (11, 'one-month event query scans one partition', 'SKIP', 'not built: ' || v_m); RETURN;
  END IF;
  EXECUTE $q$EXPLAIN (FORMAT JSON) SELECT count(*) FROM iga.security_event
              WHERE occurred_at >= '2026-07-01 00:00+00' AND occurred_at < '2026-08-01 00:00+00'$q$ INTO v_plan;
  SELECT coalesce(array_agg(DISTINCT t.m[1] ORDER BY t.m[1]), '{}') INTO v_rels
    FROM regexp_matches(v_plan::text, '"Relation Name"\s*:\s*"([^"]+)"', 'g') AS t(m)
   WHERE t.m[1] LIKE 'security\_event\_%';
  IF v_rels = ARRAY['security_event_2026_07'] THEN st := 'PASS';
  ELSE dt := 'partitions in plan: ' || coalesce(array_to_string(v_rels, ', '), '(none)'); END IF;
  INSERT INTO test_result VALUES (11, 'one-month event query scans one partition', st, dt);
END $$;

-- ---------------------------------------------------------------------------------------------
-- 12  iga_reviewer sees only its own review items (row-level security; phase 4)
-- ---------------------------------------------------------------------------------------------
DO $$
DECLARE v_m text; v jsonb; v_pol text; v_guc text; v_rev_a bigint; v_rev_b bigint; v_r2 bigint;
        v_as1 bigint; v_as2 bigint; v_camp bigint; v_own bigint; v_other bigint; v_total bigint;
        st text := 'FAIL'; dt text;
BEGIN
  v_m := pg_temp.missing('iga.review_item', 'iga.review_campaign', 'iga.role_assignment');
  IF v_m IS NOT NULL THEN
    INSERT INTO test_result VALUES (12, 'reviewer cannot see another reviewer''s items', 'SKIP', 'not built: ' || v_m); RETURN;
  END IF;
  SELECT string_agg(coalesce(qual, ''), ' ') INTO v_pol FROM pg_policies
   WHERE schemaname = 'iga' AND tablename = 'review_item';
  IF v_pol IS NULL THEN
    INSERT INTO test_result VALUES (12, 'reviewer cannot see another reviewer''s items', 'SKIP', 'no RLS policy on iga.review_item yet'); RETURN;
  END IF;
  v_guc := substring(v_pol FROM 'current_setting\(''([^'']+)''');
  IF v_guc IS NULL THEN
    INSERT INTO test_result VALUES (12, 'reviewer cannot see another reviewer''s items', 'SKIP',
                                    'policy is not keyed on current_setting(), test cannot drive it: ' || v_pol); RETURN;
  END IF;
  BEGIN
    v := pg_temp.fix('t12');
    v_rev_a := (v->>'person')::bigint;
    INSERT INTO iga.person(employee_no, full_name, email, dept_id, hire_date)
    VALUES ('zz_t12_b', 'ZZ t12 reviewer B', 'zz_t12_b@zz.invalid', (v->>'dept')::bigint, date '2020-01-01')
    RETURNING person_id INTO v_rev_b;
    INSERT INTO iga.role(system_id, name) VALUES ((v->>'system')::bigint, 'zz_role_t12b') RETURNING role_id INTO v_r2;
    INSERT INTO iga.role_assignment(account_id, role_id) VALUES ((v->>'account')::bigint, (v->>'role')::bigint)
      RETURNING assignment_id INTO v_as1;
    INSERT INTO iga.role_assignment(account_id, role_id) VALUES ((v->>'account')::bigint, v_r2)
      RETURNING assignment_id INTO v_as2;
    INSERT INTO iga.review_campaign(name, starts_on, ends_on) VALUES ('zz_t12', current_date, current_date + 30)
      RETURNING campaign_id INTO v_camp;
    INSERT INTO iga.review_item(campaign_id, assignment_id, reviewer_id) VALUES (v_camp, v_as1, v_rev_a);
    INSERT INTO iga.review_item(campaign_id, assignment_id, reviewer_id) VALUES (v_camp, v_as2, v_rev_b);
    PERFORM set_config(v_guc, v_rev_a::text, true);
    EXECUTE 'SET LOCAL ROLE iga_reviewer';
    SELECT count(*) FILTER (WHERE reviewer_id = v_rev_a), count(*) FILTER (WHERE reviewer_id = v_rev_b), count(*)
      INTO v_own, v_other, v_total FROM iga.review_item WHERE campaign_id = v_camp;
    EXECUTE 'RESET ROLE';
    IF v_own = 1 AND v_other = 0 AND v_total = 1 THEN st := 'PASS';
    ELSE dt := format('as reviewer A: own=%s other=%s total=%s (expected 1/0/1); guc=%s', v_own, v_other, v_total, v_guc); END IF;
    RAISE EXCEPTION 'rollback-marker' USING ERRCODE = 'T0001';
  EXCEPTION
    WHEN SQLSTATE 'T0001' THEN NULL;
    WHEN OTHERS THEN st := 'FAIL'; dt := 'unexpected ' || SQLSTATE || ': ' || SQLERRM;
  END;
  INSERT INTO test_result VALUES (12, 'reviewer cannot see another reviewer''s items', st, dt);
END $$;

-- ---------------------------------------------------------------------------------------------
-- 13  verify_audit_chain() and the canonical hash do not depend on session settings
-- ---------------------------------------------------------------------------------------------
DO $$
DECLARE v_m text; v jsonb;
        v_sets text[] := ARRAY[ARRAY['UTC', 'ISO, MDY', 'postgres', '0'],
                               ARRAY['Asia/Kolkata', 'SQL, DMY', 'sql_standard', '3'],
                               ARRAY['America/St_Johns', 'German', 'iso_8601', '1']];
        i int; v_ver text := ''; v_h text; v_sh text; v_hs text[] := '{}'; v_sstored text;
        o_tz text; o_ds text; o_is text; o_fd text;
        st text := 'FAIL'; dt text;
BEGIN
  v_m := pg_temp.missing('iga.audit_log', 'iga.person', 'iga.account', 'p:verify_audit_chain', 'p:audit_hash', 'p:audit_canonical');
  IF v_m IS NOT NULL THEN
    INSERT INTO test_result VALUES (13, 'audit verification independent of session settings', 'SKIP', 'not built: ' || v_m); RETURN;
  END IF;
  BEGIN
    o_tz := current_setting('TimeZone'); o_ds := current_setting('DateStyle');
    o_is := current_setting('IntervalStyle'); o_fd := current_setting('extra_float_digits');
    -- write audit rows under three different settings
    FOR i IN 1..3 LOOP
      PERFORM set_config('TimeZone', v_sets[i][1], true);
      PERFORM set_config('DateStyle', v_sets[i][2], true);
      PERFORM set_config('IntervalStyle', v_sets[i][3], true);
      PERFORM set_config('extra_float_digits', v_sets[i][4], true);
      IF i = 1 THEN v := pg_temp.fix('t13');
      ELSE
        UPDATE iga.person SET full_name = full_name || ' x' || i WHERE person_id = (v->>'person')::bigint;
        UPDATE iga.account SET last_login_at = now() WHERE account_id = (v->>'account')::bigint;
      END IF;
    END LOOP;
    IF (SELECT count(*) FROM iga.audit_log) < 3 THEN
      st := 'SKIP'; dt := 'fewer than 3 audit rows after fixture (audit triggers not built?)';
    ELSE
      -- verify and recompute hashes of the last rows under each setting
      FOR i IN 1..3 LOOP
        PERFORM set_config('TimeZone', v_sets[i][1], true);
        PERFORM set_config('DateStyle', v_sets[i][2], true);
        PERFORM set_config('IntervalStyle', v_sets[i][3], true);
        PERFORM set_config('extra_float_digits', v_sets[i][4], true);
        v_ver := v_ver || coalesce(iga.verify_audit_chain()::text, 'NULL') || ';';
        SELECT string_agg(encode(iga.audit_hash(a.prev_hash, iga.audit_canonical(a.seq, a.occurred_at, a.actor, a.action,
                                  a.table_name, a.row_pk, a.old_row, a.new_row)), 'hex'), ',' ORDER BY a.seq),
               string_agg(encode(a.row_hash, 'hex'), ',' ORDER BY a.seq)
          INTO v_h, v_sstored
          FROM (SELECT * FROM iga.audit_log ORDER BY seq DESC LIMIT 10) a;
        v_hs := v_hs || v_h;
        v_sh := v_sstored;
      END LOOP;
      IF v_ver <> 'NULL;NULL;NULL;' THEN dt := 'verify results under the 3 settings: ' || v_ver;
      ELSIF NOT (v_hs[1] = v_hs[2] AND v_hs[2] = v_hs[3]) THEN dt := 'recomputed hashes differ between settings';
      ELSIF v_hs[1] <> v_sh THEN dt := 'recomputed hashes differ from stored row_hash';
      ELSE st := 'PASS'; END IF;
    END IF;
    PERFORM set_config('TimeZone', o_tz, true);
    PERFORM set_config('DateStyle', o_ds, true);
    PERFORM set_config('IntervalStyle', o_is, true);
    PERFORM set_config('extra_float_digits', o_fd, true);
    RAISE EXCEPTION 'rollback-marker' USING ERRCODE = 'T0001';
  EXCEPTION
    WHEN SQLSTATE 'T0001' THEN NULL;
    WHEN OTHERS THEN st := 'FAIL'; dt := 'unexpected ' || SQLSTATE || ': ' || SQLERRM;
  END;
  INSERT INTO test_result VALUES (13, 'audit verification independent of session settings', st, dt);
END $$;

-- ---------------------------------------------------------------------------------------------
-- 14  partition layout of security_event
-- ---------------------------------------------------------------------------------------------
DO $$
DECLARE v_m text; v_names text[]; v_expected text[]; v_default text; v_kind "char"; v_b text;
        st text := 'FAIL'; dt text;
BEGIN
  v_m := pg_temp.missing('iga.security_event');
  IF v_m IS NOT NULL THEN
    INSERT INTO test_result VALUES (14, 'security_event partition layout', 'SKIP', 'not built: ' || v_m); RETURN;
  END IF;
  SELECT relkind INTO v_kind FROM pg_class WHERE oid = 'iga.security_event'::regclass;
  SELECT array_agg(c.relname::text ORDER BY c.relname) INTO v_names
    FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid WHERE i.inhparent = 'iga.security_event'::regclass;
  SELECT array_agg('security_event_2026_' || lpad(g::text, 2, '0') ORDER BY g) || ARRAY['security_event_default']
    INTO v_expected FROM generate_series(5, 12) g;
  SELECT c.relname::text INTO v_default
    FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
   WHERE i.inhparent = 'iga.security_event'::regclass AND pg_get_expr(c.relpartbound, c.oid) = 'DEFAULT';
  SELECT pg_get_expr(c.relpartbound, c.oid) INTO v_b FROM pg_class c WHERE c.oid = to_regclass('iga.security_event_2026_07');
  IF v_kind <> 'p' THEN dt := 'security_event is not partitioned (relkind ' || v_kind || ')';
  ELSIF v_names IS DISTINCT FROM (SELECT array_agg(x ORDER BY x) FROM unnest(v_expected) x) THEN
    dt := 'partitions: ' || coalesce(array_to_string(v_names, ', '), '(none)');
  ELSIF v_default IS DISTINCT FROM 'security_event_default' THEN dt := 'DEFAULT partition is ' || coalesce(v_default, '(none)');
  ELSIF v_b NOT LIKE '%2026-07-01%' OR v_b NOT LIKE '%2026-08-01%' THEN dt := 'bounds of security_event_2026_07: ' || v_b;
  ELSE st := 'PASS'; END IF;
  INSERT INTO test_result VALUES (14, 'security_event partition layout', st, dt);
END $$;

-- ---------------------------------------------------------------------------------------------
-- 15  one live grant per (account, role); a new grant is fine after revocation
-- ---------------------------------------------------------------------------------------------
DO $$
DECLARE v_m text; v jsonb; r jsonb; v_a1 bigint; st text := 'FAIL'; dt text;
BEGIN
  v_m := pg_temp.missing('iga.role_assignment', 'iga.account', 'iga.role');
  IF v_m IS NOT NULL THEN
    INSERT INTO test_result VALUES (15, 'one live grant per account and role', 'SKIP', 'not built: ' || v_m); RETURN;
  END IF;
  BEGIN
    v := pg_temp.fix('t15');
    INSERT INTO iga.role_assignment(account_id, role_id) VALUES ((v->>'account')::bigint, (v->>'role')::bigint)
      RETURNING assignment_id INTO v_a1;
    r := pg_temp.try(format('INSERT INTO iga.role_assignment(account_id, role_id) VALUES (%s, %s)', v->>'account', v->>'role'));
    IF (r->>'ok')::boolean THEN dt := 'second live grant was accepted';
    ELSIF NOT (r->>'state' = '23505' AND r->>'constraint' = 'uq_assignment_live') THEN dt := 'wrong error: ' || r::text;
    ELSE
      UPDATE iga.role_assignment SET revoked_at = now() WHERE assignment_id = v_a1;
      r := pg_temp.try(format('INSERT INTO iga.role_assignment(account_id, role_id) VALUES (%s, %s)', v->>'account', v->>'role'));
      IF (r->>'ok')::boolean THEN st := 'PASS';
      ELSE dt := 'new grant after revocation was rejected: ' || r::text; END IF;
    END IF;
    RAISE EXCEPTION 'rollback-marker' USING ERRCODE = 'T0001';
  EXCEPTION
    WHEN SQLSTATE 'T0001' THEN NULL;
    WHEN OTHERS THEN st := 'FAIL'; dt := 'unexpected ' || SQLSTATE || ': ' || SQLERRM;
  END;
  INSERT INTO test_result VALUES (15, 'one live grant per account and role', st, dt);
END $$;

-- ---------------------------------------------------------------------------------------------
-- 16  trg_leaver_cascade: terminating a person by hand disables the person's accounts
-- ---------------------------------------------------------------------------------------------
DO $$
DECLARE v_m text; v jsonb; v_bad bigint; v_cnt bigint; st text := 'FAIL'; dt text;
BEGIN
  v_m := pg_temp.missing('iga.person', 'iga.account');
  IF v_m IS NOT NULL OR NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_leaver_cascade') THEN
    INSERT INTO test_result VALUES (16, 'terminating a person disables accounts (trg_leaver_cascade)', 'SKIP',
                                    'not built: ' || coalesce(v_m, 'trigger trg_leaver_cascade')); RETURN;
  END IF;
  BEGIN
    v := pg_temp.fix('t16');
    INSERT INTO iga.account(person_id, system_id, username, account_type)
    VALUES ((v->>'person')::bigint, (v->>'system')::bigint, 'zz_t16_b', 'human');
    UPDATE iga.person SET status = 'terminated', end_date = date '2025-06-01' WHERE person_id = (v->>'person')::bigint;
    SELECT count(*) INTO v_cnt FROM iga.account WHERE person_id = (v->>'person')::bigint;
    SELECT count(*) INTO v_bad FROM iga.account WHERE person_id = (v->>'person')::bigint AND status <> 'disabled';
    IF v_cnt <> 2 THEN dt := 'expected 2 accounts, found ' || v_cnt;
    ELSIF v_bad <> 0 THEN dt := v_bad || ' account(s) still not disabled';
    ELSE st := 'PASS'; END IF;
    RAISE EXCEPTION 'rollback-marker' USING ERRCODE = 'T0001';
  EXCEPTION
    WHEN SQLSTATE 'T0001' THEN NULL;
    WHEN OTHERS THEN st := 'FAIL'; dt := 'unexpected ' || SQLSTATE || ': ' || SQLERRM;
  END;
  INSERT INTO test_result VALUES (16, 'terminating a person disables accounts (trg_leaver_cascade)', st, dt);
END $$;

-- ---------------------------------------------------------------------------------------------
-- 17  mover: A-only birthright revoked, B birthright granted, common one kept, dept changed, one event
-- ---------------------------------------------------------------------------------------------
DO $$
DECLARE v_m text; v jsonb; r jsonb; v_pid bigint; v_dept_b bigint; v_ra bigint; v_rb bigint; v_rc bigint;
        v_dept_now bigint; v_n bigint; v_old bigint; v_new bigint; st text := 'FAIL'; dt text;
BEGIN
  v_m := pg_temp.missing('iga.person', 'iga.account', 'iga.role_assignment', 'iga.lifecycle_event',
                         'iga.dept_birthright_role', 'p:joiner', 'p:mover');
  IF v_m IS NOT NULL THEN
    INSERT INTO test_result VALUES (17, 'mover swaps birthright roles', 'SKIP', 'not built: ' || v_m); RETURN;
  END IF;
  BEGIN
    v := pg_temp.fix('t17');
    v_ra := (v->>'role')::bigint;
    INSERT INTO iga.department(name) VALUES ('zz_test_dept_t17b') RETURNING dept_id INTO v_dept_b;
    INSERT INTO iga.role(system_id, name) VALUES ((v->>'system')::bigint, 'zz_role_t17b') RETURNING role_id INTO v_rb;
    INSERT INTO iga.role(system_id, name) VALUES ((v->>'system')::bigint, 'zz_role_t17c') RETURNING role_id INTO v_rc;
    INSERT INTO iga.dept_birthright_role(dept_id, role_id)
    VALUES ((v->>'dept')::bigint, v_ra), ((v->>'dept')::bigint, v_rc), (v_dept_b, v_rb), (v_dept_b, v_rc);
    r := pg_temp.try(format($q$CALL iga.joiner('zz_t17j', 'ZZ t17 joiner', 'zz_t17j@zz.invalid', %s, NULL::bigint,
                              DATE '2026-01-01', ARRAY[%s]::bigint[], ARRAY[]::text[], NULL::bigint)$q$,
                            v->>'dept', v->>'system'));
    IF NOT (r->>'ok')::boolean THEN
      dt := 'joiner failed: ' || r::text;
    ELSE
      SELECT person_id INTO v_pid FROM iga.person WHERE employee_no = 'zz_t17j';
      IF NOT (pg_temp.live(v_pid, v_ra) = 1 AND pg_temp.live(v_pid, v_rc) = 1 AND pg_temp.live(v_pid, v_rb) = 0) THEN
        dt := format('precondition after joiner: live A-only=%s common=%s B-only=%s (expected 1/1/0)',
                     pg_temp.live(v_pid, v_ra), pg_temp.live(v_pid, v_rc), pg_temp.live(v_pid, v_rb));
      ELSE
        r := pg_temp.try(format('CALL iga.mover(%s, %s)', v_pid, v_dept_b));
        IF NOT (r->>'ok')::boolean THEN
          dt := 'mover failed: ' || r::text;
        ELSE
          SELECT dept_id INTO v_dept_now FROM iga.person WHERE person_id = v_pid;
          SELECT count(*) INTO v_n FROM iga.lifecycle_event WHERE person_id = v_pid AND event_type = 'mover';
          SELECT old_dept_id, new_dept_id INTO v_old, v_new FROM iga.lifecycle_event
           WHERE person_id = v_pid AND event_type = 'mover' LIMIT 1;
          IF pg_temp.live(v_pid, v_ra) <> 0 THEN dt := 'A-only birthright role was not revoked';
          ELSIF pg_temp.live(v_pid, v_rb) <> 1 THEN dt := 'B birthright role was not granted';
          ELSIF pg_temp.live(v_pid, v_rc) <> 1 THEN dt := 'common birthright role is not live exactly once';
          ELSIF v_dept_now IS DISTINCT FROM v_dept_b THEN dt := 'person.dept_id was not updated';
          ELSIF v_n <> 1 THEN dt := v_n || ' mover lifecycle_event(s), expected 1';
          ELSIF v_old IS DISTINCT FROM (v->>'dept')::bigint OR v_new IS DISTINCT FROM v_dept_b THEN
            dt := 'mover event has wrong old/new department';
          ELSE st := 'PASS'; END IF;
        END IF;
      END IF;
    END IF;
    RAISE EXCEPTION 'rollback-marker' USING ERRCODE = 'T0001';
  EXCEPTION
    WHEN SQLSTATE 'T0001' THEN NULL;
    WHEN OTHERS THEN st := 'FAIL'; dt := 'unexpected ' || SQLSTATE || ': ' || SQLERRM;
  END;
  INSERT INTO test_result VALUES (17, 'mover swaps birthright roles', st, dt);
END $$;

-- ---------------------------------------------------------------------------------------------
-- 18  TRUNCATE audit_log rejected
-- ---------------------------------------------------------------------------------------------
DO $$
DECLARE v_m text; v jsonb; r jsonb; st text := 'FAIL'; dt text;
BEGIN
  v_m := pg_temp.missing('iga.audit_log');
  IF v_m IS NOT NULL THEN
    INSERT INTO test_result VALUES (18, 'TRUNCATE audit_log rejected', 'SKIP', 'not built: ' || v_m); RETURN;
  END IF;
  BEGIN
    r := pg_temp.try('TRUNCATE iga.audit_log');   -- if it were accepted, the marker rollback below restores the rows
    IF (r->>'ok')::boolean THEN dt := 'TRUNCATE was accepted';
    ELSIF r->>'state' = 'P0001' AND r->>'msg' LIKE 'audit_log is append-only%' THEN st := 'PASS';
    ELSE dt := 'wrong error: ' || r::text; END IF;
    RAISE EXCEPTION 'rollback-marker' USING ERRCODE = 'T0001';
  EXCEPTION
    WHEN SQLSTATE 'T0001' THEN NULL;
    WHEN OTHERS THEN st := 'FAIL'; dt := 'unexpected ' || SQLSTATE || ': ' || SQLERRM;
  END;
  INSERT INTO test_result VALUES (18, 'TRUNCATE audit_log rejected', st, dt);
END $$;

-- ---------------------------------------------------------------------------------------------
-- 19  seed + views: table counts and the planted faults (08_seed.sql) are returned exactly.
--     SKIP when a view is missing or the seed is not loaded.
-- ---------------------------------------------------------------------------------------------
DO $$
DECLARE
  v_m text; v_actual bigint; v_bad text := ''; r record; st text := 'PASS'; dt text;
BEGIN
  v_m := pg_temp.missing('iga.v_effective_access', 'iga.v_orphan_accounts', 'iga.v_leaver_residual_access',
                         'iga.v_sod_violations', 'iga.v_dormant_accounts', 'iga.v_privileged_overdue',
                         'iga.v_unowned_service_accounts', 'iga.mv_access_summary');
  IF v_m IS NOT NULL THEN
    INSERT INTO test_result VALUES (19, 'seed counts and planted faults', 'SKIP', 'not built: ' || v_m); RETURN;
  END IF;
  IF (SELECT count(*) FROM iga.person) = 0 THEN
    INSERT INTO test_result VALUES (19, 'seed counts and planted faults', 'SKIP', 'seed not loaded'); RETURN;
  END IF;
  BEGIN
    FOR r IN
      SELECT * FROM (VALUES
        ('person',                     'SELECT count(*) FROM iga.person',                                  200::bigint),
        ('account',                    'SELECT count(*) FROM iga.account',                                 520),
        ('role_assignment',            'SELECT count(*) FROM iga.role_assignment',                         900),
        ('security_event',             'SELECT count(*) FROM iga.security_event',                          500000),
        ('v_orphan_accounts',          'SELECT count(*) FROM iga.v_orphan_accounts',                       6),
        ('v_leaver_residual persons',  'SELECT count(DISTINCT person_id) FROM iga.v_leaver_residual_access', 4),
        ('v_sod_violations',           'SELECT count(*) FROM iga.v_sod_violations',                        3),
        ('v_dormant_accounts',         'SELECT count(*) FROM iga.v_dormant_accounts',                      12),
        ('v_unowned_service_accounts', 'SELECT count(*) FROM iga.v_unowned_service_accounts',              3),
        ('v_privileged_overdue',       'SELECT count(*) FROM iga.v_privileged_overdue',                    2)
      ) AS t(label, q, expected)
    LOOP
      EXECUTE r.q INTO v_actual;
      IF v_actual <> r.expected THEN
        v_bad := v_bad || format(' %s=%s (expected %s);', r.label, v_actual, r.expected);
      END IF;
    END LOOP;
    IF v_bad <> '' THEN st := 'FAIL'; dt := btrim(v_bad); END IF;
  EXCEPTION WHEN OTHERS THEN
    st := 'FAIL'; dt := 'unexpected ' || SQLSTATE || ': ' || SQLERRM;
  END;
  INSERT INTO test_result VALUES (19, 'seed counts and planted faults', st, dt);
END $$;

-- ---------------------------------------------------------------------------------------------
-- Report
-- ---------------------------------------------------------------------------------------------
\pset tuples_only on
\pset format unaligned
SELECT status || ' ' || n || ' ' || name || coalesce(': ' || detail, '') FROM test_result ORDER BY n;
SELECT 'SUMMARY pass=' || count(*) FILTER (WHERE status = 'PASS')
       || ' fail=' || count(*) FILTER (WHERE status = 'FAIL')
       || ' skip=' || count(*) FILTER (WHERE status = 'SKIP') FROM test_result;

ROLLBACK;
