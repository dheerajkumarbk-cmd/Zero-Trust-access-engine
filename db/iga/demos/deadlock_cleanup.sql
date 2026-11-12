-- deadlock_cleanup.sql : removes the deadlock demo fixture (safe to run when nothing exists).
SET search_path = iga, public;
SET client_min_messages = warning;
DELETE FROM role_assignment WHERE account_id IN (SELECT account_id FROM account WHERE username LIKE 'demo-dl-%');
DELETE FROM lifecycle_event WHERE person_id IN (SELECT person_id FROM person WHERE employee_no LIKE 'DEMO-DL-%');
DELETE FROM account WHERE username LIKE 'demo-dl-%';
DELETE FROM person  WHERE employee_no LIKE 'DEMO-DL-%';
DELETE FROM dept_birthright_role WHERE dept_id IN (SELECT dept_id FROM department WHERE name LIKE 'DEMO_DL_DEPT_%');
DELETE FROM role       WHERE name LIKE 'demo_dl_role_%';
DELETE FROM system     WHERE name = 'DEMO_DL_SYS';
DELETE FROM department WHERE name LIKE 'DEMO_DL_DEPT_%';
