-- atomicity.sql : DEMO 1 - ATOMICITY (spec section 4). All steps of iga.joiner happen or none do.
-- Run:  db/iga/run.sh --db dwarpal_dbms db/iga/demos/atomicity.sql -v ON_ERROR_STOP=0
-- Re-runnable: it creates its own fixture (names start with DEMO_ATOM / DEMO-ATOM) and removes it at the end.
-- Note: audit_log is append-only by design, so audit rows written by committed fixture work are not removed.
\set ON_ERROR_STOP off
\set VERBOSITY verbose
SET search_path = iga, public;
SET client_min_messages = warning;

\echo '=== 0. Fixture (committed): department, system, role, birthright mapping ==='
DELETE FROM role_assignment WHERE account_id IN (SELECT account_id FROM account WHERE username LIKE 'demo-atom-%');
DELETE FROM lifecycle_event WHERE person_id IN (SELECT person_id FROM person WHERE employee_no LIKE 'DEMO-ATOM-%');
DELETE FROM account WHERE username LIKE 'demo-atom-%';
DELETE FROM person  WHERE employee_no LIKE 'DEMO-ATOM-%';
DELETE FROM dept_birthright_role WHERE dept_id IN (SELECT dept_id FROM department WHERE name = 'DEMO_ATOM_DEPT');
DELETE FROM role       WHERE name = 'demo_atom_viewer';
DELETE FROM system     WHERE name = 'DEMO_ATOM_SYS';
DELETE FROM department WHERE name = 'DEMO_ATOM_DEPT';
INSERT INTO department (name) VALUES ('DEMO_ATOM_DEPT');
INSERT INTO system (name, criticality) VALUES ('DEMO_ATOM_SYS', 2);
INSERT INTO role (system_id, name) SELECT system_id, 'demo_atom_viewer' FROM system WHERE name = 'DEMO_ATOM_SYS';
INSERT INTO dept_birthright_role (dept_id, role_id)
SELECT d.dept_id, r.role_id FROM department d, role r WHERE d.name = 'DEMO_ATOM_DEPT' AND r.name = 'demo_atom_viewer';
SELECT d.dept_id AS demo_dept, s.system_id AS demo_system
  FROM department d, system s WHERE d.name = 'DEMO_ATOM_DEPT' AND s.name = 'DEMO_ATOM_SYS' \gset
\echo 'Fixture ids: dept=' :demo_dept ' system=' :demo_system

-- Helper view of "what is left behind" for a person (employee_no pattern DEMO-ATOM-%).
CREATE OR REPLACE TEMP VIEW leftovers AS
SELECT (SELECT count(*) FROM person          WHERE employee_no LIKE 'DEMO-ATOM-%')                              AS persons,
       (SELECT count(*) FROM account         WHERE username    LIKE 'demo-atom-%')                              AS accounts,
       (SELECT count(*) FROM role_assignment ra JOIN account a USING (account_id)
         WHERE a.username LIKE 'demo-atom-%')                                                                   AS assignments,
       (SELECT count(*) FROM lifecycle_event le JOIN person p USING (person_id)
         WHERE p.employee_no LIKE 'DEMO-ATOM-%')                                                                AS lifecycle_events;
SELECT count(*) AS audit_rows_before FROM audit_log \gset
\echo 'audit_log rows before the demo:' :audit_rows_before

\echo
\echo '=== 1. Baseline: nothing exists for the demo people ==='
SELECT * FROM leftovers;

\echo
\echo '=== 2. joiner with a role that does not exist (autocommit: the CALL is its own transaction) ==='
\echo 'Expect: ERROR P0002 "role no_such_role does not exist"'
CALL joiner('DEMO-ATOM-1', 'Atom One', 'demo.atom1@example.test', :demo_dept, NULL, current_date,
            ARRAY[:demo_system]::bigint[], p_extra_roles => ARRAY['no_such_role']);

\echo
\echo '=== 3. After the failure: no person, account, assignment or lifecycle row remained ==='
SELECT * FROM leftovers;
SELECT (count(*) = :audit_rows_before) AS audit_log_unchanged FROM audit_log;

\echo
\echo '=== 4. A successful joiner inside BEGIN .. ROLLBACK ==='
BEGIN;
CALL joiner('DEMO-ATOM-1', 'Atom One', 'demo.atom1@example.test', :demo_dept, NULL, current_date,
            ARRAY[:demo_system]::bigint[]);
\echo 'Inside the transaction (visible to this session only): everything was created'
SELECT * FROM leftovers;
ROLLBACK;
\echo 'After ROLLBACK: everything is gone again'
SELECT * FROM leftovers;

\echo
\echo '=== 5. SAVEPOINT: partial rollback inside one transaction ==='
BEGIN;
CALL joiner('DEMO-ATOM-2', 'Atom Two', 'demo.atom2@example.test', :demo_dept, NULL, current_date,
            ARRAY[:demo_system]::bigint[]);
SAVEPOINT after_atom2;
\echo 'Second joiner fails (missing role); the transaction is now in the aborted state:'
CALL joiner('DEMO-ATOM-3', 'Atom Three', 'demo.atom3@example.test', :demo_dept, NULL, current_date,
            ARRAY[:demo_system]::bigint[], p_extra_roles => ARRAY['no_such_role']);
ROLLBACK TO SAVEPOINT after_atom2;
\echo 'After ROLLBACK TO SAVEPOINT: DEMO-ATOM-2 is still there, DEMO-ATOM-3 is not'
SELECT employee_no FROM person WHERE employee_no LIKE 'DEMO-ATOM-%' ORDER BY 1;
COMMIT;
\echo 'After COMMIT only DEMO-ATOM-2 is permanent:'
SELECT employee_no, status FROM person WHERE employee_no LIKE 'DEMO-ATOM-%' ORDER BY 1;
SELECT * FROM leftovers;

\echo
\echo '=== 6. Cleanup of the fixture ==='
DELETE FROM role_assignment WHERE account_id IN (SELECT account_id FROM account WHERE username LIKE 'demo-atom-%');
DELETE FROM lifecycle_event WHERE person_id IN (SELECT person_id FROM person WHERE employee_no LIKE 'DEMO-ATOM-%');
DELETE FROM account WHERE username LIKE 'demo-atom-%';
DELETE FROM person  WHERE employee_no LIKE 'DEMO-ATOM-%';
DELETE FROM dept_birthright_role WHERE dept_id = :demo_dept;
DELETE FROM role       WHERE name = 'demo_atom_viewer';
DELETE FROM system     WHERE name = 'DEMO_ATOM_SYS';
DELETE FROM department WHERE name = 'DEMO_ATOM_DEPT';
SELECT * FROM leftovers;
