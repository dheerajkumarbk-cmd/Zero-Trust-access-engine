-- isolation_setup.sql : fixture for the isolation demo. Privileged role demo_iso_priv with 2 live holders
-- (H1, H2) and two candidates (C1, C2) who each have an account but no assignment yet.
\ir isolation_cleanup.sql
SET search_path = iga, public;
SET client_min_messages = warning;
INSERT INTO department (name) VALUES ('DEMO_ISO_DEPT');
INSERT INTO system (name, criticality) VALUES ('DEMO_ISO_SYS', 3);
INSERT INTO role (system_id, name, is_privileged)
  SELECT system_id, 'demo_iso_priv', true FROM system WHERE name = 'DEMO_ISO_SYS';
INSERT INTO person (employee_no, full_name, email, dept_id, hire_date)
  SELECT 'DEMO-ISO-' || n, 'Iso ' || n, 'demo.iso.' || lower(n) || '@example.test', d.dept_id, current_date
    FROM department d, unnest(ARRAY['H1','H2','C1','C2']) n WHERE d.name = 'DEMO_ISO_DEPT';
INSERT INTO account (person_id, system_id, username, account_type)
  SELECT p.person_id, s.system_id, lower(p.employee_no), 'human'
    FROM person p, system s WHERE p.employee_no LIKE 'DEMO-ISO-%' AND s.name = 'DEMO_ISO_SYS';
-- the two existing holders
INSERT INTO role_assignment (account_id, role_id)
  SELECT a.account_id, r.role_id FROM account a, role r
   WHERE a.username IN ('demo-iso-h1','demo-iso-h2') AND r.name = 'demo_iso_priv';
