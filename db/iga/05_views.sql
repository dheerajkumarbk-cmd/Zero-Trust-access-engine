-- 05_views.sql: governance views (spec section 8). Works on an empty schema; re-runnable.
-- "Live grant" everywhere means: revoked_at IS NULL AND (valid_to IS NULL OR valid_to > now()).
\set ON_ERROR_STOP on

BEGIN;
SET search_path = iga, public;

-- Every live grant expanded down to the entitlement. LEFT JOINs keep roles that have no entitlements yet,
-- and service/agent accounts that have no person.
CREATE OR REPLACE VIEW v_effective_access AS
SELECT ra.assignment_id,
       p.person_id,
       p.full_name,
       a.account_id,
       a.username,
       a.account_type,
       s.system_id,
       s.name        AS system_name,
       r.role_id,
       r.name        AS role_name,
       r.is_privileged,
       e.entitlement_id,
       e.action,
       e.resource,
       ra.valid_from,
       ra.valid_to
  FROM role_assignment ra
  JOIN account a              ON a.account_id = ra.account_id
  JOIN role r                 ON r.role_id = ra.role_id
  JOIN system s               ON s.system_id = r.system_id
  LEFT JOIN person p          ON p.person_id = a.person_id
  LEFT JOIN role_entitlement re ON re.role_id = r.role_id
  LEFT JOIN entitlement e     ON e.entitlement_id = re.entitlement_id
 WHERE ra.revoked_at IS NULL
   AND (ra.valid_to IS NULL OR ra.valid_to > now());
COMMENT ON VIEW v_effective_access IS
    'Person, account, system, role and entitlement for every live grant (not revoked, not expired).';

CREATE OR REPLACE VIEW v_orphan_accounts AS
SELECT a.account_id,
       a.username,
       a.system_id,
       s.name        AS system_name,
       a.person_id,
       p.full_name,
       p.status      AS person_status,
       p.end_date,
       a.last_login_at
  FROM account a
  JOIN system s      ON s.system_id = a.system_id
  LEFT JOIN person p ON p.person_id = a.person_id
 WHERE a.account_type = 'human'
   AND a.status = 'active'
   AND (a.person_id IS NULL OR p.status = 'terminated');
COMMENT ON VIEW v_orphan_accounts IS
    'Active human accounts whose person is missing or terminated: the account should have been disabled.';

CREATE OR REPLACE VIEW v_leaver_residual_access AS
SELECT p.person_id,
       p.full_name,
       p.end_date,
       a.account_id,
       a.username,
       a.status      AS account_status,
       ra.assignment_id,
       ra.role_id,
       r.name        AS role_name,
       r.is_privileged,
       ra.valid_to
  FROM person p
  JOIN account a          ON a.person_id = p.person_id
  JOIN role_assignment ra ON ra.account_id = a.account_id
  JOIN role r             ON r.role_id = ra.role_id
 WHERE p.status = 'terminated'
   AND ra.revoked_at IS NULL
   AND (ra.valid_to IS NULL OR ra.valid_to > now());
COMMENT ON VIEW v_leaver_residual_access IS
    'Terminated people who still hold a live assignment. Must always be empty; rows mean the leaver procedure was bypassed.';

CREATE OR REPLACE VIEW v_sod_violations AS
SELECT a.account_id,
       a.username,
       a.person_id,
       sr.role_a,
       ra_a.name     AS role_a_name,
       sr.role_b,
       rb_b.name     AS role_b_name,
       sr.description AS rule_description
  FROM sod_rule sr
  JOIN role ra_a          ON ra_a.role_id = sr.role_a
  JOIN role rb_b          ON rb_b.role_id = sr.role_b
  JOIN role_assignment x  ON x.role_id = sr.role_a
                         AND x.revoked_at IS NULL AND (x.valid_to IS NULL OR x.valid_to > now())
  JOIN role_assignment y  ON y.role_id = sr.role_b AND y.account_id = x.account_id
                         AND y.revoked_at IS NULL AND (y.valid_to IS NULL OR y.valid_to > now())
  JOIN account a          ON a.account_id = x.account_id;
COMMENT ON VIEW v_sod_violations IS
    'One row per account and segregation-of-duties rule where the account holds both roles of the rule live.';

CREATE OR REPLACE VIEW v_dormant_accounts AS
SELECT a.account_id,
       a.username,
       a.account_type,
       a.system_id,
       a.person_id,
       a.owner_person_id,
       a.last_login_at,
       CASE WHEN a.last_login_at IS NULL THEN NULL
            ELSE floor(extract(epoch FROM now() - a.last_login_at) / 86400)::int END AS days_since_login
  FROM account a
 WHERE a.status = 'active'
   AND (a.last_login_at IS NULL OR a.last_login_at < now() - interval '90 days');
COMMENT ON VIEW v_dormant_accounts IS
    'Active accounts that never logged in or have not logged in for 90 days.';

CREATE OR REPLACE VIEW v_privileged_overdue AS
SELECT ra.assignment_id,
       a.account_id,
       a.username,
       a.person_id,
       r.role_id,
       r.name        AS role_name,
       r.system_id,
       ra.valid_from,
       ra.valid_to,
       now() - ra.valid_to AS overdue_by
  FROM role_assignment ra
  JOIN role r    ON r.role_id = ra.role_id
  JOIN account a ON a.account_id = ra.account_id
 WHERE r.is_privileged
   AND ra.valid_to < now()
   AND ra.revoked_at IS NULL;
COMMENT ON VIEW v_privileged_overdue IS
    'Privileged grants whose valid_to has passed but which were never revoked.';

CREATE OR REPLACE VIEW v_unowned_service_accounts AS
SELECT a.account_id,
       a.username,
       a.account_type,
       a.system_id,
       a.owner_person_id,
       o.full_name   AS owner_name,
       o.end_date    AS owner_end_date
  FROM account a
  JOIN person o ON o.person_id = a.owner_person_id
 WHERE a.account_type IN ('service', 'ai_agent')
   AND a.status = 'active'
   AND o.status = 'terminated';
COMMENT ON VIEW v_unowned_service_accounts IS
    'Active service and AI-agent accounts whose accountable owner has been terminated.';

-- Materialised summary: live grants per department (of the person, or of the owner for service accounts) and system.
DROP MATERIALIZED VIEW IF EXISTS mv_access_summary;
CREATE MATERIALIZED VIEW mv_access_summary AS
SELECT d.dept_id,
       d.name        AS dept_name,
       s.system_id,
       s.name        AS system_name,
       count(*)      AS live_grants
  FROM role_assignment ra
  JOIN account a    ON a.account_id = ra.account_id
  JOIN person p     ON p.person_id = coalesce(a.person_id, a.owner_person_id)
  JOIN department d ON d.dept_id = p.dept_id
  JOIN role r       ON r.role_id = ra.role_id
  JOIN system s     ON s.system_id = r.system_id
 WHERE ra.revoked_at IS NULL
   AND (ra.valid_to IS NULL OR ra.valid_to > now())
 GROUP BY d.dept_id, d.name, s.system_id, s.name
WITH DATA;
CREATE UNIQUE INDEX uq_mv_access_summary ON mv_access_summary (dept_id, system_id);
COMMENT ON MATERIALIZED VIEW mv_access_summary IS
    'Live grants per department and system; REFRESH MATERIALIZED VIEW CONCURRENTLY mv_access_summary on demand.';

COMMIT;
