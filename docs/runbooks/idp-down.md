# Runbook: the identity provider is down

*Layer 5 part B. For the SOC on duty and the platform administrator. Keep a printed copy: if the
identity provider is down, the wiki that holds this file may be out of reach too.*

## 1. Why this needs a runbook

Dwarpal never trusts a login without fresh, key-bound MFA signed by the identity provider (IdP):

| Rule | Where | Effect while the IdP is down |
|---|---|---|
| A session opens only with fresh, verified, key-bound MFA | Policy Administrator (X3, `MfaAtOpenTest`) | **No new sessions**, for anyone |
| Re-authentication every 8 h / 4 h / 1 h / 15 min by classification | Policy Administrator (S9) | Open sessions end at their next re-authentication |
| Every ADMIN action needs fresh MFA (P-05) | Reference policy | **No admin actions**, even with an approved elevation |
| Elevation requests need WebAuthn at most 5 min old | PAM (A4) | No new elevation |
| Break-glass gives the role for 30 min | PAM (A6) | The role is granted, **but P-05 still blocks each admin action** |

So break-glass does not get anyone around an IdP outage, by design: a stolen break-glass credential
plus a "the IdP is down" story must not be enough to administer production. The way out is to bring
the IdP back, not to switch MFA off.

## 2. Is it an outage or an attack?

Decide this first; everything after depends on it.

| Sign | Points to |
|---|---|
| Logins fail for everyone at once; the IdP's health check fails; its host or network is down | Outage |
| Logins fail with "signature does not verify" or "unknown key" for MFA proofs | IdP key rotated without updating the key ring, **or an attacker's IdP answering** |
| Successful MFA for people who are asleep; MFA prompts nobody asked for (`mfa-fatigue` alerts) | IdP or authenticators compromised |
| Many `STEP_UP` then `DENY` across the company, deny storms from one address | Outage seen by clients retrying, or a spray hiding in the noise |

If there is any sign of compromise, go to section 5.

## 3. Outage: what to do (in order)

1. **Declare an incident** and note the start time (audit time). Page the platform administrator.
2. **Do not weaken Dwarpal.** Never build a Policy Administrator with `allowLoginWithoutMfa()` (it exists
   for engine-path tests only), never install a policy without the MFA constraint, never widen key
   validity "to get people working". Each of these outlives the outage.
3. **Restore the IdP** through its own management path, which must not depend on Dwarpal sessions:
   the console of the host it runs on, reached from the administration network. For the development
   IdP (`DevIdpServer`) that means restarting it on its host with its user file and key; its signing
   key must be the one in the key ring (`IDENTITY_PROVIDER`, bound to the issuer name).
4. **Keep the SOC loop calm.** The outage will raise alerts (deny storms, many step-ups, login failures):
   - Close them as **BENIGN** (real, but expected). Do not mark them TRUE_POSITIVE: the playbooks would
     revoke and deny innocent people. Do not mark them FALSE_POSITIVE either: that verdict means
     "the detection was wrong" and lifts actions.
   - Never deny the IdP's address or the office egress in the signal feed. The egress is on the
     shared-address list, so a deny there needs two analysts anyway.
   - The playbooks' rate limits (20 destructive actions an hour overall, 10 per analyst) stop a
     panicking or compromised analyst from locking out everyone, but they are a last line, not a
     procedure.
5. **Tell people what still works.** Open sessions keep working until their next re-authentication
   (up to 8 h for INTERNAL data, 15 min for RESTRICTED). Nobody can log in again, elevate, or perform
   an admin action until the IdP is back.
6. **If an admin action cannot wait** (for example, the IdP host itself must be reconfigured): do it on
   the host's local console under the four-eyes rule, outside Dwarpal, and write down who did what,
   when and why. Break-glass will not help here (section 1), so do not use it; a break-glass use pages
   the SOC and must be reviewed, which costs time during an incident.

## 4. After the IdP is back

1. Check the IdP signs with the key in the key ring: one test login by an analyst.
2. Check the audit chain is intact across the outage (part A's chain check, or `AuditCursor` with the
   key); a break during an outage is treated as an attack (section 5).
3. Review every break-glass use during the incident (`pendingReviews()`); each needs a signed verdict
   from someone else, `justified` or `misuse`.
4. Close the incident's alerts that are still open (BENIGN), and check no playbook action is still in
   force on someone because of the outage (cases with `holdsActions`): if there is one, the alert was
   wrong for this person, so a FALSE_POSITIVE verdict lifts it (two analysts if two confirmed it).
5. Write up: start, end, cause, what was done outside Dwarpal and by whom.

## 5. Suspected IdP compromise

An attacker who holds the IdP's signing key can mint MFA for anyone. Treat it as the worst case:

1. **Stop trusting the key.** Remove (or end the validity of) the `IDENTITY_PROVIDER` key in the key
   ring and restart the components that hold it. From then on no MFA verifies: this is the outage of
   section 3, on purpose, and the same rules apply.
2. **End sessions opened since the suspected start.** Revoke the people who logged in during the window
   (`revokeSubject`, which also ends their elevation grants), starting with privileged accounts. These
   are destructive actions, so on privileged accounts they need two analysts; that is intended.
3. **Watch, do not deny, the broad population.** A watch (for example x10, half-life one day) raises
   everyone's risk for a while without locking anyone out; deny only confirmed attackers.
4. **New key, new trust.** The IdP gets a new signing key, generated on its host; the key ring gets the
   new public key with a short validity window. Every person re-enrols their authenticator if the
   authenticator store may have been read.
5. Review the audit trail from the suspected start: `SESSION_OPENED`, `ELEVATION_*`, `SIGNAL_*`,
   `VERDICT_*` and `RESPONSE_*` records.

## 6. What this runbook does not cover

- An offline MFA method for emergencies (one-time codes printed in a safe, a second IdP). Dwarpal has
  none; adding one is a design change with its own threat model (residual risk in the threat model).
- The IdP's own high availability (a second instance with the same key): an operations matter.
