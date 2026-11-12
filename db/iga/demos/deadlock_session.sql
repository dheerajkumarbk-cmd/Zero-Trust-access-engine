-- deadlock_session.sql : one session of the opposite-order mover race.
-- psql variables: label (A/B), first (employee_no locked first), second (employee_no moved second).
-- Step 1 locks the first person with SELECT .. FOR UPDATE (what mover does internally), step 2 waits
-- so both sessions hold their first lock, step 3 CALLs mover on the other person, which needs the
-- row lock the other session already holds.
\set ON_ERROR_STOP off
\set VERBOSITY verbose
\pset tuples_only on
SET search_path = iga, public;
SELECT person_id AS p1 FROM person WHERE employee_no = :'first' \gset
SELECT person_id AS p2 FROM person WHERE employee_no = :'second' \gset
SELECT dept_id AS d2 FROM department WHERE name = 'DEMO_DL_DEPT_2' \gset
\echo [session :label] BEGIN
BEGIN;
\echo [session :label] locking :first (person_id :p1) with SELECT ... FOR UPDATE
SELECT person_id FROM person WHERE person_id = :p1 FOR UPDATE;
\echo [session :label] holding the lock on :first, sleeping 2 s
SELECT pg_sleep(2) AS slept \gset
\echo [session :label] CALL mover on :second (person_id :p2); waits for the lock held by the other session
CALL mover(:p2, :d2);
\echo [session :label] COMMIT
COMMIT;
