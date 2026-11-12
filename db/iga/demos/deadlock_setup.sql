-- deadlock_setup.sql : two departments (each with one birthright role), two people X and Y in department 1.
\ir deadlock_cleanup.sql
SET search_path = iga, public;
SET client_min_messages = warning;
INSERT INTO department (name) VALUES ('DEMO_DL_DEPT_1'), ('DEMO_DL_DEPT_2');
INSERT INTO system (name, criticality) VALUES ('DEMO_DL_SYS', 2);
INSERT INTO role (system_id, name)
  SELECT s.system_id, 'demo_dl_role_' || n FROM system s, unnest(ARRAY['1','2']) n WHERE s.name = 'DEMO_DL_SYS';
INSERT INTO dept_birthright_role (dept_id, role_id)
  SELECT d.dept_id, r.role_id FROM department d, role r
   WHERE replace(d.name, 'DEMO_DL_DEPT_', '') = replace(r.name, 'demo_dl_role_', '')
     AND d.name LIKE 'DEMO_DL_DEPT_%' AND r.name LIKE 'demo_dl_role_%';
INSERT INTO person (employee_no, full_name, email, dept_id, hire_date)
  SELECT 'DEMO-DL-' || n, 'Deadlock ' || n, 'demo.dl.' || lower(n) || '@example.test', d.dept_id, current_date
    FROM department d, unnest(ARRAY['X','Y']) n WHERE d.name = 'DEMO_DL_DEPT_1';
INSERT INTO account (person_id, system_id, username, account_type)
  SELECT p.person_id, s.system_id, lower(p.employee_no), 'human'
    FROM person p, system s WHERE p.employee_no LIKE 'DEMO-DL-%' AND s.name = 'DEMO_DL_SYS';
INSERT INTO role_assignment (account_id, role_id)
  SELECT a.account_id, r.role_id FROM account a, role r
   WHERE a.username LIKE 'demo-dl-%' AND r.name = 'demo_dl_role_1';
