-- 08_seed.sql: reproducible demo data (spec section 11). Run ONCE on a freshly built schema (01..05 first).
-- Deterministic: no random(); everything derives from the row number i by arithmetic or hashtext(), so two
-- runs give the same data. Timestamps are relative to now() so view counts do not depend on the run date.
--
-- Counts: 8 departments, 200 people (15 terminated = E0186..E0200, 5 on_leave = E0101..E0105), 6 systems,
--         30 roles, 120 entitlements, 520 accounts (490 human, 25 service, 5 ai_agent), 900 role_assignments,
--         6 sod_rules, 500,000 security_event rows over [2026-05-01, 2026-11-01) UTC.
-- Planted faults (each view count is asserted at the end of this script and by test 19):
--   v_orphan_accounts            6  active human accounts created AFTER E0190..E0195 were terminated
--   v_leaver_residual_access     4  persons E0186..E0189 terminated by plain UPDATE: assignments stay live
--   v_sod_violations             3  three approver holders (systems 1-3) also granted 'requester'; rules added last
--   v_dormant_accounts          12  first account of E0140..E0151: 6 never logged in, 6 idle 100+ days
--   v_unowned_service_accounts   3  svc-005, svc-012, agent-027 owned by terminated E0196..E0198
--   v_privileged_overdue         2  'admin' grants to E0060 and E0061, valid_to 10 days ago, never revoked
-- Brute-force bursts: 8 accounts x 15 failed logins, 15 s apart, starting on a 5-minute boundary (spec-8 HAVING query).
\set ON_ERROR_STOP on
SET search_path = iga, public;

BEGIN;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM person) THEN
        RAISE EXCEPTION 'run 01..05 first (fresh schema)';
    END IF;
    IF to_regclass('iga.v_orphan_accounts') IS NULL OR to_regclass('iga.mv_access_summary') IS NULL THEN
        RAISE EXCEPTION 'run 05_views.sql first';
    END IF;
END $$;

-- ---------------------------------------------------------------------------------------------
-- Departments (hierarchy: Executive Office > 4 departments > Security, Sales, Customer Support)
-- ---------------------------------------------------------------------------------------------
INSERT INTO department (name, parent_dept_id) VALUES ('Executive Office', NULL);
INSERT INTO department (name, parent_dept_id)
SELECT v.n, (SELECT dept_id FROM department WHERE name = v.p)
  FROM (VALUES ('Engineering', 'Executive Office'), ('Finance', 'Executive Office'),
               ('Human Resources', 'Executive Office'), ('Operations', 'Executive Office')) v(n, p);
INSERT INTO department (name, parent_dept_id)
SELECT v.n, (SELECT dept_id FROM department WHERE name = v.p)
  FROM (VALUES ('Security', 'Engineering'), ('Sales', 'Operations'), ('Customer Support', 'Operations')) v(n, p);

CREATE TEMP TABLE tmp_dept AS
SELECT (row_number() OVER (ORDER BY dept_id))::int AS d, dept_id FROM department;

-- ---------------------------------------------------------------------------------------------
-- People (all start active, on_leave for E0101..E0105; terminations happen later by UPDATE)
-- ---------------------------------------------------------------------------------------------
INSERT INTO person (employee_no, full_name, email, dept_id, status, hire_date)
SELECT 'E' || lpad(i::text, 4, '0'),
       (ARRAY['Aarav','Diya','Vihaan','Ananya','Aditya','Isha','Rohan','Meera','Kabir','Saanvi',
              'Arjun','Kavya','Ishaan','Riya','Neel','Tara','Dev','Nisha','Yash','Pooja'])[1 + (i * 7) % 20]
       || ' ' ||
       (ARRAY['Sharma','Verma','Iyer','Nair','Gupta','Mehta','Reddy','Kulkarni','Joshi','Bose',
              'Patel','Singh','Rao','Das','Menon','Chopra','Banerjee','Shetty','Desai','Kapoor'])[1 + (i * 11 + i / 20) % 20],
       'e' || lpad(i::text, 4, '0') || '@dwarpal.example',
       td.dept_id,
       CASE WHEN i BETWEEN 101 AND 105 THEN 'on_leave' ELSE 'active' END,
       date '2019-01-01' + ((i * 37) % 1800)
  FROM generate_series(1, 200) AS i
  JOIN tmp_dept td ON td.d = 1 + (i % 8)
 ORDER BY i;

CREATE TEMP TABLE tmp_p AS
SELECT substr(employee_no, 2)::int AS i, person_id FROM person;
CREATE UNIQUE INDEX ON tmp_p (i);
CREATE UNIQUE INDEX ON tmp_p (person_id);

-- Managers form chains: person i reports to person (i-2)/3+1 (a ternary tree rooted at E0001).
UPDATE person p
   SET manager_id = m.person_id
  FROM tmp_p c
  JOIN tmp_p m ON m.i = (c.i - 2) / 3 + 1
 WHERE c.person_id = p.person_id AND c.i >= 2;

-- ---------------------------------------------------------------------------------------------
-- Systems, roles (5 per system), entitlements (20 per system), role_entitlement, birthright roles
-- ---------------------------------------------------------------------------------------------
INSERT INTO system (name, criticality)
VALUES ('ERP-Finance', 4), ('HR-Core', 4), ('Source-Control', 3), ('Cloud-Console', 4), ('CRM', 2), ('Data-Warehouse', 3);

CREATE TEMP TABLE tmp_sys AS
SELECT (row_number() OVER (ORDER BY system_id))::int AS s, system_id FROM system;

UPDATE system sy SET owner_person_id = tp.person_id
  FROM tmp_sys ts JOIN tmp_p tp ON tp.i = ts.s + 2
 WHERE ts.system_id = sy.system_id;

INSERT INTO role (system_id, name, is_privileged)
SELECT ts.system_id, r.name, (r.name = 'admin' OR (r.name = 'approver' AND ts.s <= 2))
  FROM tmp_sys ts
 CROSS JOIN (VALUES (1, 'reader'), (2, 'contributor'), (3, 'approver'), (4, 'requester'), (5, 'admin')) r(idx, name)
 ORDER BY ts.s, r.idx;

CREATE TEMP TABLE tmp_role AS
SELECT ts.s, x.idx, r.role_id, r.system_id
  FROM role r
  JOIN tmp_sys ts ON ts.system_id = r.system_id
  JOIN (VALUES (1, 'reader'), (2, 'contributor'), (3, 'approver'), (4, 'requester'), (5, 'admin')) x(idx, name)
    ON x.name = r.name;
CREATE UNIQUE INDEX ON tmp_role (s, idx);

INSERT INTO entitlement (system_id, action, resource)
SELECT ts.system_id, a.action, rs.resource
  FROM tmp_sys ts
 CROSS JOIN (VALUES ('read'), ('create'), ('update'), ('delete'), ('approve')) a(action)
 CROSS JOIN (VALUES ('records'), ('reports'), ('settings'), ('users')) rs(resource)
 ORDER BY ts.s, a.action, rs.resource;

INSERT INTO role_entitlement (role_id, entitlement_id)
SELECT r.role_id, e.entitlement_id
  FROM role r
  JOIN entitlement e ON e.system_id = r.system_id
 WHERE (r.name = 'reader'      AND e.action = 'read')
    OR (r.name = 'contributor' AND e.action IN ('read', 'create', 'update'))
    OR (r.name = 'approver'    AND e.action IN ('read', 'approve'))
    OR (r.name = 'requester'   AND e.action IN ('read', 'create'))
    OR (r.name = 'admin');

-- Department d receives the reader role of systems 1+d%6 and 1+(d+1)%6.
INSERT INTO dept_birthright_role (dept_id, role_id)
SELECT td.dept_id, tr.role_id
  FROM tmp_dept td
  JOIN tmp_role tr ON tr.idx = 1 AND tr.s IN (1 + td.d % 6, 1 + (td.d + 1) % 6);

-- ---------------------------------------------------------------------------------------------
-- Accounts: 484 human (2 per person, a 3rd for even i <= 168), 25 service, 5 ai_agent
-- Normal last_login_at is 0..29 days ago, so only the planted dormant accounts are dormant.
-- ---------------------------------------------------------------------------------------------
INSERT INTO account (person_id, system_id, username, account_type, status, last_login_at, created_at)
SELECT tp.person_id, ts.system_id, 'e' || lpad(g.i::text, 4, '0'), 'human', 'active',
       now() - make_interval(days => (g.i * 7 + k0.k * 3) % 30, hours => (g.i * 13) % 24),
       now() - make_interval(days => 200 + (g.i * 5) % 400)
  FROM generate_series(1, 200) AS g(i)
 CROSS JOIN generate_series(0, 2) AS k0(k)
  JOIN tmp_p tp   ON tp.i = g.i
  JOIN tmp_sys ts ON ts.s = 1 + (g.i + k0.k) % 6
 WHERE k0.k < 2 OR (g.i % 2 = 0 AND g.i <= 168)
 ORDER BY g.i, k0.k;

-- Service accounts 1..25, AI agents 26..30. Owner = person 10+n, except n=5, 12, 27 (terminated owners).
INSERT INTO account (person_id, system_id, username, account_type, owner_person_id, status, last_login_at, created_at)
SELECT NULL, ts.system_id,
       CASE WHEN n <= 25 THEN 'svc-' ELSE 'agent-' END || lpad(n::text, 3, '0'),
       CASE WHEN n <= 25 THEN 'service' ELSE 'ai_agent' END,
       o.person_id, 'active',
       now() - make_interval(days => n % 30, hours => (n * 5) % 24),
       now() - make_interval(days => 150 + n * 3)
  FROM generate_series(1, 30) AS n
  JOIN tmp_sys ts ON ts.s = 1 + n % 6
  JOIN tmp_p o ON o.i = CASE n WHEN 5 THEN 196 WHEN 12 THEN 197 WHEN 27 THEN 198 ELSE 10 + n END
 ORDER BY n;

-- PLANTED v_dormant_accounts (12): first account of E0140..E0151 (even i: never logged in; odd i: idle 100+ days).
UPDATE account a
   SET last_login_at = CASE WHEN tp.i % 2 = 0 THEN NULL ELSE now() - make_interval(days => 100 + tp.i) END
  FROM tmp_p tp
 WHERE tp.person_id = a.person_id
   AND tp.i BETWEEN 140 AND 151
   AND a.account_id = (SELECT min(a2.account_id) FROM account a2 WHERE a2.person_id = a.person_id);

-- ---------------------------------------------------------------------------------------------
-- Role assignments: 514 primary + 366 secondary + 15 live admin + 2 overdue admin + 3 SoD = 900
-- Roles used by the generic grants are reader/contributor/approver only, so no generic SoD pair arises.
-- ---------------------------------------------------------------------------------------------
CREATE TEMP TABLE tmp_acct_a AS
SELECT (row_number() OVER (ORDER BY account_id) - 1)::int AS rn, account_id, system_id, person_id FROM account;
CREATE UNIQUE INDEX ON tmp_acct_a (rn);

-- primary: one grant per account, role index 1 + rn%3
INSERT INTO role_assignment (account_id, role_id, granted_by, valid_from)
SELECT ta.account_id, tr.role_id, gb.person_id, now() - make_interval(days => 20 + (ta.rn * 3) % 300)
  FROM tmp_acct_a ta
  JOIN tmp_sys ts  ON ts.system_id = ta.system_id
  JOIN tmp_role tr ON tr.s = ts.s AND tr.idx = 1 + ta.rn % 3
  JOIN tmp_p gb    ON gb.i = 2
 ORDER BY ta.rn;

-- secondary: the next role in the reader > contributor > approver cycle for the first 366 accounts;
-- some non-privileged ones are temporary (only for E0020..E0120, so no planted fault depends on expiry).
INSERT INTO role_assignment (account_id, role_id, granted_by, valid_from, valid_to)
SELECT ta.account_id, tr.role_id, gb.person_id, now() - make_interval(days => 10 + (ta.rn * 5) % 200),
       CASE WHEN tr.idx <= 2 AND ta.rn % 5 = 0 AND tp.i BETWEEN 20 AND 120
            THEN now() + make_interval(days => 30 + ta.rn % 60) END
  FROM tmp_acct_a ta
  JOIN tmp_sys ts  ON ts.system_id = ta.system_id
  JOIN tmp_role tr ON tr.s = ts.s AND tr.idx = 1 + (1 + ta.rn % 3) % 3
  JOIN tmp_p gb    ON gb.i = 3
  LEFT JOIN tmp_p tp ON tp.person_id = ta.person_id
 WHERE ta.rn < 366
 ORDER BY ta.rn;

-- 15 ordinary live admin grants (no expiry): first account of E0070..E0084
INSERT INTO role_assignment (account_id, role_id, granted_by, valid_from)
SELECT x.account_id, tr.role_id, gb.person_id, now() - make_interval(days => 30 + x.i)
  FROM (SELECT DISTINCT ON (tp.i) tp.i, a.account_id, a.system_id
          FROM account a JOIN tmp_p tp ON tp.person_id = a.person_id
         WHERE tp.i BETWEEN 70 AND 84
         ORDER BY tp.i, a.account_id) x
  JOIN tmp_sys ts  ON ts.system_id = x.system_id
  JOIN tmp_role tr ON tr.s = ts.s AND tr.idx = 5
  JOIN tmp_p gb    ON gb.i = 1;

-- PLANTED v_privileged_overdue (2): admin grants to E0060 and E0061 expired 10 days ago, never revoked
INSERT INTO role_assignment (account_id, role_id, granted_by, valid_from, valid_to)
SELECT x.account_id, tr.role_id, gb.person_id, now() - interval '120 days', now() - interval '10 days'
  FROM (SELECT DISTINCT ON (tp.i) tp.i, a.account_id, a.system_id
          FROM account a JOIN tmp_p tp ON tp.person_id = a.person_id
         WHERE tp.i IN (60, 61)
         ORDER BY tp.i, a.account_id) x
  JOIN tmp_sys ts  ON ts.system_id = x.system_id
  JOIN tmp_role tr ON tr.s = ts.s AND tr.idx = 5
  JOIN tmp_p gb    ON gb.i = 1;

-- PLANTED v_sod_violations (3): in systems 1..3 the lowest-id account of E0020..E0120 holding 'approver'
-- is also granted 'requester'. The sod_rule rows come AFTER this, so the rules find existing violations.
INSERT INTO role_assignment (account_id, role_id, granted_by, valid_from)
SELECT x.account_id, r4.role_id, gb.person_id, now() - interval '15 days'
  FROM (SELECT DISTINCT ON (r3.s) r3.s, a.account_id
          FROM role_assignment ra
          JOIN tmp_role r3 ON r3.role_id = ra.role_id AND r3.idx = 3 AND r3.s <= 3
          JOIN account a   ON a.account_id = ra.account_id AND a.account_type = 'human'
          JOIN tmp_p tp    ON tp.person_id = a.person_id AND tp.i BETWEEN 20 AND 120
         WHERE ra.revoked_at IS NULL
         ORDER BY r3.s, a.account_id) x
  JOIN tmp_role r4 ON r4.s = x.s AND r4.idx = 4
  JOIN tmp_p gb    ON gb.i = 1;

-- ---------------------------------------------------------------------------------------------
-- Leavers: E0186..E0200 become terminated by plain UPDATE (trigger disables their accounts).
--   E0186..E0189  assignments left live      -> v_leaver_residual_access (4 persons)
--   E0190..E0200  assignments revoked first  -> clean
-- ---------------------------------------------------------------------------------------------
UPDATE role_assignment ra
   SET revoked_at = now() - interval '3 days'
  FROM account a
  JOIN tmp_p tp ON tp.person_id = a.person_id
 WHERE a.account_id = ra.account_id
   AND tp.i BETWEEN 190 AND 200
   AND ra.revoked_at IS NULL;

UPDATE person p
   SET status = 'terminated',
       end_date = date '2026-10-01' - (tp.i % 60)
  FROM tmp_p tp
 WHERE tp.person_id = p.person_id AND tp.i BETWEEN 186 AND 200;

-- leaver lifecycle events: processed for the clean ones, left unprocessed for the four with residual access
INSERT INTO lifecycle_event (person_id, event_type, old_dept_id, effective_at, processed_at)
SELECT p.person_id, 'leaver', p.dept_id, p.end_date::timestamptz,
       CASE WHEN tp.i >= 190 THEN p.end_date::timestamptz + interval '1 hour' END
  FROM person p JOIN tmp_p tp ON tp.person_id = p.person_id
 WHERE p.status = 'terminated'
 ORDER BY tp.i;

-- PLANTED v_orphan_accounts (6): accounts created for E0190..E0195 after termination, still enabled, no grants
INSERT INTO account (person_id, system_id, username, account_type, status, last_login_at, created_at)
SELECT tp.person_id, ts.system_id, 'e' || lpad(tp.i::text, 4, '0'), 'human', 'active',
       now() - make_interval(days => tp.i % 10), now() - interval '20 days'
  FROM tmp_p tp
  JOIN tmp_sys ts ON ts.s = 1 + (tp.i + 3) % 6
 WHERE tp.i BETWEEN 190 AND 195
 ORDER BY tp.i;

-- ---------------------------------------------------------------------------------------------
-- Segregation-of-duties rules (added after the grants): requester and approver of each system
-- ---------------------------------------------------------------------------------------------
INSERT INTO sod_rule (role_a, role_b, description)
SELECT least(r3.role_id, r4.role_id), greatest(r3.role_id, r4.role_id),
       'requester and approver on ' || sy.name || ' must not be held by one account'
  FROM tmp_role r3
  JOIN tmp_role r4 ON r4.s = r3.s AND r4.idx = 4
  JOIN system sy   ON sy.system_id = r3.system_id
 WHERE r3.idx = 3
 ORDER BY r3.s;

-- ---------------------------------------------------------------------------------------------
-- security_event: 499,880 spread events + 8 x 15 brute-force burst events = 500,000.
-- Event i happens 31.7952 s after event i-1 plus a deterministic jitter < 30 s, which exactly fills
-- the 184-day window; account, type, outcome, ip and device come from hashtext() of the row number.
-- ---------------------------------------------------------------------------------------------
CREATE TEMP TABLE tmp_ev_acct AS
SELECT (row_number() OVER (ORDER BY account_id))::int AS rn, account_id FROM account;
CREATE UNIQUE INDEX ON tmp_ev_acct (rn);
ANALYZE tmp_ev_acct;

INSERT INTO security_event (occurred_at, account_id, event_type, source_ip, outcome, details)
SELECT q.ts, ea.account_id, q.etype,
       (CASE WHEN q.outcome = 'failure' AND q.h1 % 3 = 0
             THEN '203.0.113.' || (1 + (q.h1 / 3) % 250)
             ELSE '10.' || (q.h3 % 250) || '.' || ((q.h3 / 250) % 250) || '.' || (1 + (q.h3 / 62500) % 250)
        END)::inet,
       q.outcome,
       jsonb_build_object('device',  (ARRAY['laptop','mobile','tablet','server','browser'])[1 + (q.h3 % 5)::int],
                          'country', (ARRAY['IN','IN','IN','IN','US','GB','DE','SG'])[1 + (q.h1 % 8)::int])
       || CASE q.etype
            WHEN 'access_denied' THEN jsonb_build_object('resource', (ARRAY['records','reports','settings','users'])[1 + (q.h2 % 4)::int])
            WHEN 'mfa'           THEN jsonb_build_object('method', (ARRAY['totp','push','sms'])[1 + (q.h2 % 3)::int])
            ELSE '{}'::jsonb
          END
  FROM (
        SELECT c.*,
               CASE WHEN c.etype = 'access_denied' THEN 'failure'
                    WHEN c.etype = 'login' AND c.h3 % 100 < 6 THEN 'failure'
                    WHEN c.etype = 'mfa'   AND c.h3 % 100 < 4 THEN 'failure'
                    ELSE 'success' END AS outcome
          FROM (
                SELECT g.i,
                       timestamptz '2026-05-01 00:00:00+00'
                         + interval '1 microsecond' * ((g.i - 1)::bigint * 31795200 + (g.i * 7919::bigint) % 30000000) AS ts,
                       abs(hashtext(g.i::text)::bigint)        AS h1,
                       abs(hashtext('b' || g.i::text)::bigint) AS h2,
                       abs(hashtext('c' || g.i::text)::bigint) AS h3,
                       CASE WHEN abs(hashtext('b' || g.i::text)::bigint) % 100 < 55 THEN 'login'
                            WHEN abs(hashtext('b' || g.i::text)::bigint) % 100 < 75 THEN 'logout'
                            WHEN abs(hashtext('b' || g.i::text)::bigint) % 100 < 85 THEN 'mfa'
                            WHEN abs(hashtext('b' || g.i::text)::bigint) % 100 < 88 THEN 'password_change'
                            ELSE 'access_denied' END AS etype
                  FROM generate_series(1, 499880) AS g(i)
               ) c
       ) q
  JOIN tmp_ev_acct ea ON ea.rn = 1 + (q.h1 % (SELECT count(*) FROM tmp_ev_acct))::int;

-- 8 brute-force bursts: 15 failed logins 15 s apart (210 s < 5 min) from one external address,
-- starting on a 5-minute boundary so all 15 fall into one date_bin bucket.
INSERT INTO security_event (occurred_at, account_id, event_type, source_ip, outcome, details)
SELECT timestamptz '2026-05-01 03:00:00+00' + k * interval '21 days' + j * interval '15 seconds',
       ea.account_id, 'login', ('203.0.113.' || (200 + k))::inet, 'failure',
       jsonb_build_object('device', 'unknown', 'country', (ARRAY['RU','CN','BR','NG'])[1 + k % 4])
  FROM generate_series(1, 8) AS k
 CROSS JOIN generate_series(0, 14) AS j
  JOIN tmp_ev_acct ea ON ea.rn = 37 * k;

-- ---------------------------------------------------------------------------------------------
-- Summary view and self-check: any mismatch aborts the whole seed (nothing is committed)
-- ---------------------------------------------------------------------------------------------
REFRESH MATERIALIZED VIEW mv_access_summary;

DO $$
DECLARE
    r record;
    v_actual bigint;
    v_bad text := '';
BEGIN
    FOR r IN
        SELECT * FROM (VALUES
            ('department',                 'SELECT count(*) FROM department',                                          8::bigint),
            ('person',                     'SELECT count(*) FROM person',                                              200),
            ('person terminated',          'SELECT count(*) FROM person WHERE status = ''terminated''',                15),
            ('person on_leave',            'SELECT count(*) FROM person WHERE status = ''on_leave''',                  5),
            ('system',                     'SELECT count(*) FROM system',                                              6),
            ('role',                       'SELECT count(*) FROM role',                                                30),
            ('entitlement',                'SELECT count(*) FROM entitlement',                                         120),
            ('account',                    'SELECT count(*) FROM account',                                             520),
            ('account service',            'SELECT count(*) FROM account WHERE account_type = ''service''',            25),
            ('account ai_agent',           'SELECT count(*) FROM account WHERE account_type = ''ai_agent''',           5),
            ('role_assignment',            'SELECT count(*) FROM role_assignment',                                     900),
            ('sod_rule',                   'SELECT count(*) FROM sod_rule',                                            6),
            ('security_event',             'SELECT count(*) FROM security_event',                                      500000),
            ('v_orphan_accounts',          'SELECT count(*) FROM v_orphan_accounts',                                   6),
            ('v_leaver_residual persons',  'SELECT count(DISTINCT person_id) FROM v_leaver_residual_access',           4),
            ('v_sod_violations',           'SELECT count(*) FROM v_sod_violations',                                    3),
            ('v_dormant_accounts',         'SELECT count(*) FROM v_dormant_accounts',                                  12),
            ('v_unowned_service_accounts', 'SELECT count(*) FROM v_unowned_service_accounts',                          3),
            ('v_privileged_overdue',       'SELECT count(*) FROM v_privileged_overdue',                                2)
        ) AS t(label, q, expected)
    LOOP
        EXECUTE r.q INTO v_actual;
        IF v_actual <> r.expected THEN
            v_bad := v_bad || format(' %s=%s(expected %s)', r.label, v_actual, r.expected);
        END IF;
    END LOOP;
    IF v_bad <> '' THEN
        RAISE EXCEPTION 'seed self-check failed:%', v_bad;
    END IF;
END $$;

COMMIT;

ANALYZE department, person, system, account, role, entitlement, role_entitlement, role_assignment,
        sod_rule, dept_birthright_role, lifecycle_event, audit_log, security_event;
