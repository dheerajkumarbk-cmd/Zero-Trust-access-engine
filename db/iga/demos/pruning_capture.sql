-- pruning_capture.sql: partition pruning. A one-month query touches one partition; a query with no time filter touches all.
--   db/iga/run.sh demos/pruning_capture.sql -q > docs/dbms/explain-pruning.txt
\set ON_ERROR_STOP on
SET search_path = iga, public;
SET jit = off;
\echo === Q1 events of July 2026 (bounds match partition security_event_2026_07): expect ONE partition in the plan
EXPLAIN (ANALYZE, BUFFERS) SELECT count(*) FROM security_event WHERE occurred_at >= '2026-07-01 00:00+00' AND occurred_at < '2026-08-01 00:00+00';
\echo
\echo === Q2 same query, no time filter: every partition is visited (for contrast)
EXPLAIN (ANALYZE, BUFFERS) SELECT count(*) FROM security_event;
\echo
\echo === Q3 partitions that actually exist and their sizes
SELECT c.relname AS partition, c.reltuples::bigint AS approx_rows, pg_size_pretty(pg_relation_size(c.oid)) AS heap_size
  FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
 WHERE i.inhparent = 'iga.security_event'::regclass ORDER BY c.relname;
