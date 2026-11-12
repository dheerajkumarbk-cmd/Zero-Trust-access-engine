-- 09_demo_queries.sql: three showcase queries from spec section 8. Read-only; safe to run any time.
--   db/iga/run.sh 09_demo_queries.sql -q > docs/dbms/demo-queries-output.txt
\set ON_ERROR_STOP on
SET search_path = iga, public;

\echo === A. Recursive query: the management chain above one person (person_id 150), nearest manager first
WITH RECURSIVE chain AS (
    SELECT p.person_id, p.full_name, p.manager_id, 0 AS levels_above
      FROM person p WHERE p.person_id = 150
    UNION ALL
    SELECT m.person_id, m.full_name, m.manager_id, c.levels_above + 1
      FROM chain c JOIN person m ON m.person_id = c.manager_id
     WHERE c.levels_above < 20            -- guard against a loop in bad data
)
SELECT levels_above, person_id, full_name FROM chain ORDER BY levels_above;

\echo
\echo === B. Window function: top 3 accounts per day by failed logins (rank), for the 5 days with the largest single-account count (accounts with fewer than 3 failures omitted)
WITH daily AS (
    SELECT date_trunc('day', occurred_at AT TIME ZONE 'UTC')::date AS day, account_id, count(*) AS failed
      FROM security_event
     WHERE event_type = 'login' AND outcome = 'failure' AND account_id IS NOT NULL
     GROUP BY 1, 2
), ranked AS (
    SELECT day, account_id, failed,
           rank() OVER (PARTITION BY day ORDER BY failed DESC) AS rnk,
           sum(failed) OVER (PARTITION BY day) AS day_total
      FROM daily
)
SELECT r.day, r.rnk, r.account_id, a.username, r.failed, r.day_total
  FROM ranked r JOIN account a USING (account_id)
 WHERE r.rnk <= 3 AND r.failed >= 3 AND r.day IN (SELECT day FROM ranked GROUP BY day ORDER BY max(failed) DESC, day LIMIT 5)
 ORDER BY r.day, r.rnk, r.account_id;

\echo
\echo === C. GROUP BY ... HAVING: brute-force candidates, more than 10 failed logins in one 5-minute window (expected 8)
SELECT e.account_id, a.username, e.source_ip,
       date_bin('5 minutes', e.occurred_at, timestamptz '2026-01-01 00:00+00') AS window_start,
       count(*) AS failures
  FROM security_event e JOIN account a USING (account_id)
 WHERE e.event_type = 'login' AND e.outcome = 'failure'
 GROUP BY e.account_id, a.username, e.source_ip, window_start
HAVING count(*) > 10
 ORDER BY window_start;
