-- explain_capture.sql: EXPLAIN (ANALYZE, BUFFERS) for the six spec section 7 queries, each run twice
-- (first run = cold-ish, second = warm). Read-only. Run before and after 06_indexes.sql:
--   db/iga/run.sh demos/explain_capture.sql -q > docs/dbms/explain-before.txt   (no indexes)
--   db/iga/run.sh demos/explain_capture.sql -q > docs/dbms/explain-after.txt    (with indexes)
-- Timings are noisy (the machine runs other work); compare plan shapes and buffer counts first.
\set ON_ERROR_STOP on
\pset footer off
SET search_path = iga, public;
SET jit = off;
SELECT account_id AS acct FROM security_event GROUP BY account_id ORDER BY count(*) DESC, account_id LIMIT 1 \gset
SELECT person_id AS pid, lower(email) AS em FROM person WHERE person_id = 77 \gset
\echo
\echo === Q1 last 50 events for one account (composite B-tree account_id, occurred_at DESC)
EXPLAIN (ANALYZE, BUFFERS) SELECT * FROM security_event WHERE account_id = :acct ORDER BY occurred_at DESC LIMIT 50;
EXPLAIN (ANALYZE, BUFFERS) SELECT * FROM security_event WHERE account_id = :acct ORDER BY occurred_at DESC LIMIT 50;
\echo
\echo === Q2 time-range scan, 1 day (BRIN on occurred_at, inside one partition)
EXPLAIN (ANALYZE, BUFFERS) SELECT count(*) FROM security_event WHERE occurred_at >= '2026-08-10 00:00+00' AND occurred_at < '2026-08-11 00:00+00';
EXPLAIN (ANALYZE, BUFFERS) SELECT count(*) FROM security_event WHERE occurred_at >= '2026-08-10 00:00+00' AND occurred_at < '2026-08-11 00:00+00';
\echo
\echo === Q3 search inside JSONB (GIN on details)
EXPLAIN (ANALYZE, BUFFERS) SELECT count(*) FROM security_event WHERE details @> '{"device":"unknown","country":"RU"}';
EXPLAIN (ANALYZE, BUFFERS) SELECT count(*) FROM security_event WHERE details @> '{"device":"unknown","country":"RU"}';
\echo
\echo === Q4 live grants of one account (partial B-tree WHERE revoked_at IS NULL)
EXPLAIN (ANALYZE, BUFFERS) SELECT * FROM role_assignment WHERE account_id = 100 AND revoked_at IS NULL;
EXPLAIN (ANALYZE, BUFFERS) SELECT * FROM role_assignment WHERE account_id = 100 AND revoked_at IS NULL;
\echo
\echo === Q5 dormant account report (partial B-tree on last_login_at WHERE status = 'active')
EXPLAIN (ANALYZE, BUFFERS) SELECT account_id, username FROM account WHERE status = 'active' AND last_login_at < timestamptz '2026-08-01 00:00+00';
EXPLAIN (ANALYZE, BUFFERS) SELECT account_id, username FROM account WHERE status = 'active' AND last_login_at < timestamptz '2026-08-01 00:00+00';
\echo
\echo === Q6 case-insensitive e-mail lookup (expression index lower(email))
EXPLAIN (ANALYZE, BUFFERS) SELECT person_id, full_name FROM person WHERE lower(email) = :'em';
EXPLAIN (ANALYZE, BUFFERS) SELECT person_id, full_name FROM person WHERE lower(email) = :'em';
