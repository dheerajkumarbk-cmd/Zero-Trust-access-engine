-- roles_demo.sql : DEMO - ROLES, PRIVILEGES AND ROW-LEVEL SECURITY (spec sections 6 and 9).
-- Run:  db/iga/run.sh db/iga/demos/roles_demo.sql > docs/dbms/roles-demo-output.txt
-- Everything happens inside BEGIN ... ROLLBACK: nothing is left behind (audit rows written meanwhile are rolled back too).
-- Each check switches to a role with SET LOCAL ROLE inside a throw-away subtransaction (see pg_temp.try_as), runs one
-- statement, and reports "ok, rows=N" or the SQLSTATE and message the database raised. The migrator can SET ROLE to the
-- four NOLOGIN-style roles because 00_setup granted them to it WITH SET TRUE, INHERIT FALSE.
\set ON_ERROR_STOP on
\pset pager off
\pset null '(null)'
SET search_path = iga, public;
SET client_min_messages = warning;

BEGIN;

-- try_as(role, reviewer GUC or NULL, statement) -> 'ok, rows=N' | 'SQLSTATE message'. Always undoes what the statement did.
CREATE FUNCTION pg_temp.try_as(p_role text, p_guc text, p_sql text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE n bigint := -1;
BEGIN
  IF p_guc IS NOT NULL THEN PERFORM set_config('iga.reviewer_id', p_guc, true); END IF;
  EXECUTE format('SET LOCAL ROLE %I', p_role);
  EXECUTE p_sql;
  GET DIAGNOSTICS n = ROW_COUNT;
  RAISE EXCEPTION 'rollback-marker' USING ERRCODE = 'T0001';
EXCEPTION
  WHEN SQLSTATE 'T0001' THEN RETURN 'ok, rows=' || n;
  WHEN OTHERS THEN RETURN SQLSTATE || ' ' || SQLERRM;
END $f$;

CREATE TEMP TABLE res (n serial, role_name text, what text, expected text, actual text);

\echo '=== 0. Fixture (rolled back at the end): 1 department, 1 system, 2 roles, 3 people, 1 account, 2 assignments, 1 campaign, 2 review items'
INSERT INTO department (name) VALUES ('ZZ_ROLES_DEPT');
INSERT INTO system (name, criticality) VALUES ('ZZ_ROLES_SYS', 2);
SELECT d.dept_id AS dept, s.system_id AS sys FROM department d, system s WHERE d.name = 'ZZ_ROLES_DEPT' AND s.name = 'ZZ_ROLES_SYS' \gset
INSERT INTO role (system_id, name) VALUES (:sys, 'zz_r1'), (:sys, 'zz_r2');
INSERT INTO dept_birthright_role (dept_id, role_id) SELECT :dept, role_id FROM role WHERE name = 'zz_r1';
INSERT INTO person (employee_no, full_name, email, dept_id, hire_date) VALUES
  ('ZZ-ROLE-A', 'Reviewer A', 'zz_role_a@zz.invalid', :dept, date '2020-01-01'),
  ('ZZ-ROLE-B', 'Reviewer B', 'zz_role_b@zz.invalid', :dept, date '2020-01-01'),
  ('ZZ-ROLE-C', 'Employee C', 'zz_role_c@zz.invalid', :dept, date '2020-01-01');
SELECT (SELECT person_id FROM person WHERE employee_no = 'ZZ-ROLE-A') AS pa,
       (SELECT person_id FROM person WHERE employee_no = 'ZZ-ROLE-B') AS pb,
       (SELECT person_id FROM person WHERE employee_no = 'ZZ-ROLE-C') AS pc \gset
INSERT INTO account (person_id, system_id, username, account_type) VALUES (:pc, :sys, 'zz-role-c', 'human');
INSERT INTO role_assignment (account_id, role_id)
SELECT a.account_id, r.role_id FROM account a, role r WHERE a.username = 'zz-role-c' AND r.name IN ('zz_r1', 'zz_r2');
INSERT INTO review_campaign (name, starts_on, ends_on) VALUES ('zz_roles_campaign', current_date, current_date + 30);
INSERT INTO review_item (campaign_id, assignment_id, reviewer_id)
SELECT c.campaign_id, ra.assignment_id, CASE r.name WHEN 'zz_r1' THEN :pa ELSE :pb END
  FROM review_campaign c, role_assignment ra JOIN role r ON r.role_id = ra.role_id
 WHERE c.name = 'zz_roles_campaign' AND r.name IN ('zz_r1', 'zz_r2');
SELECT count(*) AS review_items_total, count(*) FILTER (WHERE reviewer_id = :pa) AS for_a, count(*) FILTER (WHERE reviewer_id = :pb) AS for_b
  FROM review_item;

-- ------------------------------------------------------------------ iga_app
INSERT INTO res (role_name, what, expected, actual) VALUES
 ('iga_app', 'DELETE FROM audit_log',                           '42501', pg_temp.try_as('iga_app', NULL, 'DELETE FROM iga.audit_log')),
 ('iga_app', 'TRUNCATE audit_log',                              '42501', pg_temp.try_as('iga_app', NULL, 'TRUNCATE iga.audit_log')),
 ('iga_app', 'SELECT FROM audit_log',                           '42501', pg_temp.try_as('iga_app', NULL, 'SELECT * FROM iga.audit_log')),
 ('iga_app', 'INSERT INTO person (direct table write)',         '42501', pg_temp.try_as('iga_app', NULL,
     format('INSERT INTO iga.person (employee_no, full_name, email, dept_id, hire_date) VALUES (''ZZ-X'', ''x'', ''zz_x@zz.invalid'', %s, current_date)', :dept))),
 ('iga_app', 'SELECT FROM person (no direct table read)',       '42501', pg_temp.try_as('iga_app', NULL, 'SELECT * FROM iga.person')),
 ('iga_app', 'call iga.audit_write (forge an audit row)',       '42501', pg_temp.try_as('iga_app', NULL,
     $q$SELECT iga.audit_write('forged', 'DELETE', 'person', '1', NULL, NULL)$q$)),
 ('iga_app', 'CALL iga.joiner(...) (SECURITY DEFINER)',         'ok',    pg_temp.try_as('iga_app', NULL,
     format('CALL iga.joiner(''ZZ-ROLE-N'', ''New Hire'', ''zz_role_n@zz.invalid'', %s, NULL, current_date, ARRAY[%s]::bigint[])', :dept, :sys))),
 ('iga_app', 'CALL iga.leaver(person C)',                       'ok',    pg_temp.try_as('iga_app', NULL, format('CALL iga.leaver(%s)', :pc))),
 ('iga_app', 'SELECT FROM review_item',                         '42501', pg_temp.try_as('iga_app', NULL, 'SELECT * FROM iga.review_item'));
-- A view, if 05_views.sql has been built: iga_app can read it without any table right.
SELECT format('INSERT INTO res (role_name, what, expected, actual) VALUES (''iga_app'', %L, ''ok'', pg_temp.try_as(''iga_app'', NULL, %L))',
              'SELECT FROM view ' || relname, 'SELECT * FROM iga.' || quote_ident(relname))
  FROM (SELECT relname FROM pg_class WHERE relnamespace = 'iga'::regnamespace AND relkind = 'v' ORDER BY relname LIMIT 1) v \gexec

-- ------------------------------------------------------------------ iga_auditor
INSERT INTO res (role_name, what, expected, actual) VALUES
 ('iga_auditor', 'SELECT FROM audit_log',               'ok',    pg_temp.try_as('iga_auditor', NULL, 'SELECT * FROM iga.audit_log')),
 ('iga_auditor', 'SELECT FROM person',                  'ok',    pg_temp.try_as('iga_auditor', NULL, 'SELECT * FROM iga.person')),
 ('iga_auditor', 'SELECT verify_audit_chain()',         'ok',    pg_temp.try_as('iga_auditor', NULL, 'SELECT iga.verify_audit_chain()')),
 ('iga_auditor', 'sees ALL review items (rows=2)',      'ok, rows=2', pg_temp.try_as('iga_auditor', NULL, 'SELECT * FROM iga.review_item')),
 ('iga_auditor', 'DELETE FROM audit_log',               '42501', pg_temp.try_as('iga_auditor', NULL, 'DELETE FROM iga.audit_log')),
 ('iga_auditor', 'UPDATE person',                       '42501', pg_temp.try_as('iga_auditor', NULL, 'UPDATE iga.person SET full_name = full_name')),
 ('iga_auditor', 'CALL iga.leaver(...)',                '42501', pg_temp.try_as('iga_auditor', NULL, format('CALL iga.leaver(%s)', :pc)));

-- ------------------------------------------------------------------ iga_admin
INSERT INTO res (role_name, what, expected, actual) VALUES
 ('iga_admin', 'SELECT FROM audit_log',                 'ok',    pg_temp.try_as('iga_admin', NULL, 'SELECT * FROM iga.audit_log')),
 ('iga_admin', 'UPDATE audit_log',                      '42501', pg_temp.try_as('iga_admin', NULL, 'UPDATE iga.audit_log SET actor = actor')),
 ('iga_admin', 'DELETE FROM audit_log',                 '42501', pg_temp.try_as('iga_admin', NULL, 'DELETE FROM iga.audit_log')),
 ('iga_admin', 'INSERT INTO audit_log',                 '42501', pg_temp.try_as('iga_admin', NULL, 'INSERT INTO iga.audit_log SELECT * FROM iga.audit_log')),
 ('iga_admin', 'TRUNCATE audit_log',                    '42501', pg_temp.try_as('iga_admin', NULL, 'TRUNCATE iga.audit_log')),
 ('iga_admin', 'UPDATE department (ordinary table)',    'ok',    pg_temp.try_as('iga_admin', NULL, 'UPDATE iga.department SET name = name')),
 ('iga_admin', 'CREATE TABLE in schema iga',            'ok',    pg_temp.try_as('iga_admin', NULL, 'CREATE TABLE iga.zz_admin_made (x int)')),
 ('iga_admin', 'sees ALL review items (rows=2)',        'ok, rows=2', pg_temp.try_as('iga_admin', NULL, 'SELECT * FROM iga.review_item'));

-- ------------------------------------------------------------------ iga_reviewer (row-level security)
INSERT INTO res (role_name, what, expected, actual) VALUES
 ('iga_reviewer', 'no iga.reviewer_id set: sees nothing',                  'ok, rows=0', pg_temp.try_as('iga_reviewer', '', 'SELECT * FROM iga.review_item')),
 ('iga_reviewer', 'as reviewer A: sees only A''s item (rows=1)',           'ok, rows=1', pg_temp.try_as('iga_reviewer', :'pa', 'SELECT * FROM iga.review_item')),
 ('iga_reviewer', 'as reviewer B: sees only B''s item (rows=1)',           'ok, rows=1', pg_temp.try_as('iga_reviewer', :'pb', 'SELECT * FROM iga.review_item')),
 ('iga_reviewer', 'A decides own item: keep',                              'ok, rows=1', pg_temp.try_as('iga_reviewer', :'pa',
     format('UPDATE iga.review_item SET decision = ''keep'', decided_at = now() WHERE reviewer_id = %s', :pa))),
 ('iga_reviewer', 'A tries to decide B''s item: 0 rows (RLS hides it)',    'ok, rows=0', pg_temp.try_as('iga_reviewer', :'pa',
     format('UPDATE iga.review_item SET decision = ''revoke'', decided_at = now() WHERE reviewer_id = %s', :pb))),
 ('iga_reviewer', 'A tries to hand own item to B (column privilege)',      '42501', pg_temp.try_as('iga_reviewer', :'pa',
     format('UPDATE iga.review_item SET reviewer_id = %s', :pb))),
 ('iga_reviewer', 'A sets an invalid decision (CHECK)',                    '23514', pg_temp.try_as('iga_reviewer', :'pa',
     'UPDATE iga.review_item SET decision = ''maybe''')),
 ('iga_reviewer', 'INSERT a review item',                                  '42501', pg_temp.try_as('iga_reviewer', :'pa',
     'INSERT INTO iga.review_item (campaign_id, assignment_id, reviewer_id) SELECT campaign_id, assignment_id, reviewer_id FROM iga.review_item')),
 ('iga_reviewer', 'DELETE a review item',                                  '42501', pg_temp.try_as('iga_reviewer', :'pa', 'DELETE FROM iga.review_item')),
 ('iga_reviewer', 'SELECT FROM role_assignment (base table)',              '42501', pg_temp.try_as('iga_reviewer', :'pa', 'SELECT * FROM iga.role_assignment')),
 ('iga_reviewer', 'SELECT FROM audit_log',                                 '42501', pg_temp.try_as('iga_reviewer', :'pa', 'SELECT * FROM iga.audit_log'));

\echo
\echo '=== RESULTS (verdict PASS when the actual outcome starts with the expected one) ==='
SELECT n, role_name, what, expected,
       CASE WHEN actual LIKE expected || '%' THEN 'PASS' ELSE 'FAIL' END AS verdict,
       left(actual, 90) AS actual
  FROM res ORDER BY n;
SELECT count(*) FILTER (WHERE actual LIKE expected || '%') AS passed,
       count(*) FILTER (WHERE actual NOT LIKE expected || '%') AS failed
  FROM res;

\echo
\echo '=== Policies on review_item (from pg_policies) ==='
SELECT policyname, cmd, roles, qual FROM pg_policies WHERE schemaname = 'iga' AND tablename = 'review_item' ORDER BY policyname;

\echo
\echo '=== Fixture is rolled back: ==='
ROLLBACK;
SELECT (SELECT count(*) FROM iga.department WHERE name = 'ZZ_ROLES_DEPT') AS leftover_departments,
       (SELECT count(*) FROM iga.review_campaign WHERE name = 'zz_roles_campaign') AS leftover_campaigns;
