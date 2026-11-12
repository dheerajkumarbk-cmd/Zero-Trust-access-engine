-- isolation_holders.sql : prints the live holder count of the demo role (rule: at most 3).
SET search_path = iga, public;
SELECT count(*) AS live_holders,
       string_agg(a.username, ', ' ORDER BY a.username) AS holders
  FROM role_assignment ra JOIN role r USING (role_id) JOIN account a USING (account_id)
 WHERE r.name = 'demo_iso_priv' AND ra.revoked_at IS NULL;
