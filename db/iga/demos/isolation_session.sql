-- isolation_session.sql : one session of the "last free slot" race.
-- psql variables: label (A/B), level ('READ COMMITTED'|'SERIALIZABLE'), cand (username of the candidate),
--                 delay (seconds to wait between the check and the insert, to force the interleaving).
-- Business rule, enforced ONLY by this check inside the transaction (no constraint can express it):
--   a privileged role may have at most 3 live holders.
\set ON_ERROR_STOP off
\set VERBOSITY verbose
\pset tuples_only on
SET search_path = iga, public;
\echo [session :label] BEGIN ISOLATION LEVEL :level
BEGIN ISOLATION LEVEL :level;
SELECT count(*) AS n, (count(*) < 3) AS has_slot
  FROM role_assignment ra JOIN role r USING (role_id)
 WHERE r.name = 'demo_iso_priv' AND ra.revoked_at IS NULL \gset
\echo [session :label] check: live holders =:n, free slot =:has_slot
\echo [session :label] sleeping :delay s before the insert (so both sessions have read the count)
SELECT pg_sleep(:delay) AS slept \gset
\if :has_slot
  \echo [session :label] INSERT assignment for :cand
  INSERT INTO role_assignment (account_id, role_id)
    SELECT a.account_id, r.role_id FROM account a, role r
     WHERE a.username = :'cand' AND r.name = 'demo_iso_priv';
\else
  \echo [session :label] no free slot, nothing to do
\endif
\echo [session :label] COMMIT
COMMIT;
