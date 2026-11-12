-- durability_step1.sql : write and commit a marker row, show the WAL position before and after.
SET search_path = iga, public;
\pset tuples_only off
\echo '--- durability-related settings'
SELECT name, setting FROM pg_settings
 WHERE name IN ('fsync','synchronous_commit','wal_level','full_page_writes','wal_sync_method') ORDER BY name;
\echo '--- last checkpoint: crash recovery would start replaying the WAL at redo_lsn'
SELECT checkpoint_lsn, redo_lsn, redo_wal_file, checkpoint_time FROM pg_control_checkpoint();
DELETE FROM department WHERE name = 'DEMO_DURABILITY_MARKER';   -- re-runnable
SELECT pg_current_wal_lsn() AS lsn_before, pg_walfile_name(pg_current_wal_lsn()) AS wal_file_before \gset
\echo '--- WAL position before the insert:' :lsn_before '(file' :wal_file_before ')'
BEGIN;
INSERT INTO department (name) VALUES ('DEMO_DURABILITY_MARKER');
SELECT pg_current_wal_insert_lsn() AS lsn_in_tx \gset
\echo '--- inside the transaction the change is only in the WAL buffers (insert position):' :lsn_in_tx
COMMIT;
\echo '--- COMMIT returned: with synchronous_commit=on the commit record was flushed to disk first'
SELECT pg_current_wal_lsn() AS lsn_after, pg_walfile_name(pg_current_wal_lsn()) AS wal_file_after,
       pg_current_wal_flush_lsn() AS flushed_to_disk_lsn,
       pg_wal_lsn_diff(pg_current_wal_lsn(), :'lsn_before') AS wal_bytes_written_by_the_insert;
SELECT dept_id, name FROM department WHERE name = 'DEMO_DURABILITY_MARKER';
