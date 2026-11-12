-- durability_step3.sql : after the restart, is the committed marker row still there?
SET search_path = iga, public;
SELECT dept_id, name, 'SURVIVED THE RESTART' AS verdict FROM department WHERE name = 'DEMO_DURABILITY_MARKER';
SELECT pg_postmaster_start_time() AS server_started_at, pg_current_wal_lsn() AS wal_lsn_now;
