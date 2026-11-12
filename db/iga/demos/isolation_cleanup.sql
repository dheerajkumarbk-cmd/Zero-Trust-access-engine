-- isolation_cleanup.sql : removes the isolation demo fixture (safe to run when nothing exists).
SET search_path = iga, public;
SET client_min_messages = warning;
DELETE FROM role_assignment WHERE account_id IN (SELECT account_id FROM account WHERE username LIKE 'demo-iso-%');
DELETE FROM lifecycle_event WHERE person_id IN (SELECT person_id FROM person WHERE employee_no LIKE 'DEMO-ISO-%');
DELETE FROM account WHERE username LIKE 'demo-iso-%';
DELETE FROM person  WHERE employee_no LIKE 'DEMO-ISO-%';
DELETE FROM role       WHERE name = 'demo_iso_priv';
DELETE FROM system     WHERE name = 'DEMO_ISO_SYS';
DELETE FROM department WHERE name = 'DEMO_ISO_DEPT';
