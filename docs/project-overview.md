# Dwarpal: whole-project overview (notes style, for analysing and fine-tuning)

Written 2026-11-10 from the code and the per-layer reports. Short on purpose; details are in the files named in section 20.
Numbers (tests, lines) are from the final gate of 2026-11-09.

## 0. Status: is it complete?

**Built (all of it, committed locally):**
- Layers 1-2 core engine + 10 scorers, Layer 3 sessions + PAM, Layer 4 enforcement points (SASE edge), Layer 5 SOC loop,
  Layer 5.2 SOC platform, Layer 6 lab + browser console.
- Phase 2 (IAM): Stage 0 setup, 1 PostgreSQL directory + HR user, 2 saved audit trail + real time, 3 joiner / leaver / access
  request, Step A second admin + elevation, 4 monitoring, 5 real device passkeys, 6 vault + emergency passwords + notices,
  7 docs + final gate.
- Scale-up round (branch `scale-up`, see docs/scale-up-proposal.md and docs/scale-up-report.md): case-insensitive sign-in
  names; engine readiness endpoint + engine-down alarm + fail-closed drill; installed policy / playbook bundles kept across
  restart and reset; elevation for PAM request / approve / revoke and lab reset; read-only team-activity view.
- Gate (2026-11-10): 1,438 tests, 0 failed. With the database: 0 skipped, 95.7% lines / 86.7% branches. Without a database
  (the GitHub CI case): 83 skipped, 91.1% lines / 83.6% branches. Gate minimum 80%; SpotBugs + FindSecBugs 0 findings;
  secret scan of tree + whole history clean. (Older figures of 95.7% were database runs only.)

**Pending (not code):**
- **Merge.** Layer 6, Phase 2 and the scale-up round are on GitHub as branches `layer6/integration` and `scale-up`
  (tag `demo-ready` = the demo version). `main` is still Layer 5.2 (07ef8ba). GitHub CI / CodeQL runs only on pushes to
  `main` and on pull requests, so a pull request is what makes them run.
- Your own checking, Windows Hello registration on the Profile page (Dana, Spector, Cleo, Ana, Ben), a dry run of the demo.

**Known gaps (decide if you want them closed):**
- Team activity (people only, latest 2,000 trail records) is shown to administrators and the lead; the lead cannot tell
  analysts from other non-administrators.
- New joiner gets first password/PIN only at the NEXT lab start (no first-sign-in flow).
- SOC service knows only ana, ben, cleo (new analysts can sign in but cannot act as SOC analysts).
- LDAP not built (PostgreSQL directory instead). Real Windows Hello not exercised by me on a physical device.
- SOC world restarts from day zero at each lab start (directory, vault, notices, passkeys, credentials, audit trail and
  installed policy / playbook bundles are kept; sessions, elevations, cases, behaviour history are not).
- Policy / playbook approve and install and the break-glass review still use fresh password + PIN + passkey each time, on
  purpose; PAM request / approve / revoke and lab reset use an open elevation.
- Not done on purpose: post-quantum hybrid signatures, real SSO, Vercel static showcase, containers, sensor heartbeats.

## 1. What it is

Dwarpal ("gatekeeper") = explainable Zero Trust Policy Decision Point (NIST SP 800-207) + SASE enforcement edge + SOC
platform + IAM administration, all in Java 25, free tools only, home-built to enterprise-style design.
Question per request: may THIS person, on THIS device, do THIS action on THIS resource, NOW? Answers:
ALLOW / ALLOW_LIMITED (read-only) / STEP_UP (prove again) / DENY, always with reasons.
NIST map: Policy Engine = L1+L2; Policy Administrator = L3; Policy Enforcement Points = L4; continuous diagnostics / SIEM = L5, 5.2;
lab = L6; identity admin = Phase 2.

## 2. Size and timeline

| Item | Number |
|---|---|
| Java main | 352 files, ~50,000 lines, 33 top-level packages under `dev.dwarpal` |
| Java tests | 206 files, ~38,000 lines, 1,438 tests |
| Console front end | 40 JS files ~5,100 lines + ~430 CSS lines; no framework, no external file |
| Runtime dependencies | PostgreSQL JDBC 42.7.14 (BSD-2), SnakeYAML 2.7 (Apache-2). Everything else = JDK |
| Git | 90 commits on branch `scale-up` (from `layer6/integration`), all pushed; `main` is Layer 5.2 |

| When (2026) | What | Tests after |
|---|---|---|
| Nov 1-2 | Layers 1-2 (engine, scorers); docs; CI | 196 |
| Nov 2 | Layer 3 (sessions, PAM) | 267 |
| Nov 4 | Layer 4 (gateway, SWG, CASB, engine API) | 531 |
| Nov 5 | Layer 5 SOC loop, Layer 5.2 SOC platform | 749 -> 974 |
| Nov 6-7 | Layer 6 lab + console, team guide | ~1,174 |
| Nov 8-9 | Phase 2 stages 0-7 (PostgreSQL, IAM, passkeys, vault) | 1,251 -> 1,354 -> 1,394 |
| Nov 10-11 | Scale-up round: five items (names, readiness, kept bundles, admin elevation, team activity) | 1,438 |

## 3. Layer map

| Layer | Packages | One line |
|---|---|---|
| 1 core | domain crypto pip engine risk decision policy audit admin runtime | 7-stage decision pipeline, signed evidence, policy, audit chain, 2-person policy install |
| 2 scorers | risk.scorers behavior | 10 scorers -> evidence (log-likelihood ratios); learning loop with anti-poisoning |
| 3 PA / PAM | session pam guard | key-bound sessions, continuous evaluation, JIT admin, break-glass |
| 4 edge | wire edge api gateway agent devidp swg casb | engine API (mTLS 1.3), ZTNA gateway, SWG proxy, CASB/DLP guard, dev IdP, client agent |
| 5 SOC loop | soc siem response analytics | encrypted audit store + anchor, 10 detection rules, cases, signed verdicts, playbooks, What-If, calibration |
| 5.2 SOC platform | siem.platform ueba soar socapi | collectors, search language, correlation rules, UEBA, SOAR, cases/SLA, device isolation, SOC API (mTLS) |
| 6 lab | lab lab.scenarios sim console* | simulated company (60 users), scenario clock, 9 attack scenarios, CA, browser console, launcher |
| Phase 2 IAM | directory console.access console.vault console.admin | PostgreSQL directory, HR flows, approvals, elevation, passkeys, vault, notices, monitoring |

## 4. The decision path (Layer 1) - the main decider

Request (identifiers + signed evidence) + signal snapshot -> `LearningDecisionPoint` -> `AuditedDecisionPoint` -> `PolicyEngine`:

| # | Stage | What |
|---|---|---|
| 1 | Evidence | posture / login proofs verified with KeyRing (unsigned = hint only) |
| 2 | Hard gates | freshness, honeytoken, deny-lists -> instant DENY |
| 3 | Attributes | roles, classification, "managed" come from directory (PIP), never from request |
| 4 | Risk | 10 scorers -> Bayes (M3) -> cost-optimal action (M2) |
| 5 | Policy | YAML grants / constraints, effect = floor |
| 6 | Step-up resolution | verified, fresh, device-bound MFA counts as evidence (only allowed loosening) |
| 7 | Obligations | read-only session may only READ |

- Final: outcome = max(gate, cost-optimal(p), policy floor) over ALLOW < ALLOW_LIMITED < STEP_UP < DENY, then step-up
  resolution, then obligations. Any exception -> DENY. Audit write fails -> DENY ("no audit, no access").
- Wrapping order `learning(audited(core))`: never learn from a decision the audit refused.
- Decision object: outcome, restricted, deviceVerified, matched policy id + version, risk (prior, factors, posterior), reasons,
  time. `userMessage()` generic (teaches attacker nothing); `analystReport()` full.

## 5. Evidence, keys, crypto

| Thing | Choice |
|---|---|
| Signatures | Ed25519 (JDK SunEC), deterministic, canonical encoding = length-prefixed fields with domain tag (no ambiguity, no cross-use) |
| Signed messages | device posture v1, authentication v2/v3 (device- and key-bound), policy bundle v1, analyst verdict, device ack, endpoint batch, session proofs ... (10 types) |
| KeyRing | key id known -> purpose matches (DEVICE_AGENT / IDENTITY_PROVIDER / POLICY_SIGNER / ...) -> owner binding -> validity window -> not >2 min in future -> not older than max age (posture 24 h, login 15 min) -> signature. Verify cache LRU 10,000, failures never cached |
| Posture assurance | SELF_REPORTED, AGENT_SIGNED, HARDWARE_ATTESTED (reserved, cannot be claimed) |
| Audit | HMAC-SHA256 chain, genesis 64 zeros, head anchored elsewhere (second HMAC key) |
| Audit store at rest | AES-256-GCM per record bound to position (L5); console trail separate keys (3 keys) |
| Transport | TLS 1.3, mutual TLS between PEPs / SOC API / engine API, certificate pinning, private lab CA (30-day certs, renewed after 20) |
| Passwords / PINs / typed passkeys | salted one-way hashes, PBKDF2-HMAC-SHA256 (console credentials and dev IdP); plain values only in the owner-only first-secrets file until changed |
| Vault | AES-256-GCM, random nonce per save, key in separate folder |
| Post-quantum | not done; plan = hybrid Ed25519 + ML-DSA-65 (JDK 25 has it) |

## 6. Maths (all implemented as written; reference config: prior 0.001, attack cap ln 1000, reassurance cap ln 10, C_B 1000, C_F 1, C_D 20, beta 0.05)

Core idea: each scorer gives LLR l_k = ln( P(x|attack) / P(x|legit) ); they add up (log-odds).

| Id | Model | Formula / rule | Parameters |
|---|---|---|---|
| M3 | Bayes with base rate | logit P(attack|x) = logit(prior) + sum l_k; P = sigmoid | prior 0.001 (logit -6.907); caps +6.91 / -2.30 per factor |
| M2 | Cost-optimal action | L(ALLOW)=p*C_B; L(STEP_UP)=p*beta*C_B+(1-p)*C_F; L(DENY)=(1-p)*C_D; pick min, tie -> stricter | step-up when p > C_F/(C_F+C_B(1-beta)); deny when p > (C_D-C_F)/((C_D-C_F)+beta*C_B) |
| M9 | MFA strength (beta) | beta = chance attacker passes; push fatigue: 1 - prod(1-q_i) | WebAuthn 0.01, number-matching push 0.05, plain push 0.30 (stated parameters, not measured) |
| - | MFA as evidence | P(attack|passed) = p*beta / (p*beta + (1-p)) | e.g. p=0.05: push -> 0.0155 (ask again), WebAuthn -> 0.00053 (allow) |
| M1 | Novelty | P(new|legit) = (k+1)/(w+2) over last w<=200 logins; back-off IP -> ASN -> country; new adds ln(Pa/Pl), known adds ln((1-Pa)/(1-Pl)) and stops | P(new|attack): IP 0.99, ASN 0.90, country 0.60, device 0.95 |
| M4 | Beta reputation | E=(g+1)/(g+b+2); evidence l = ln((b+1)/(g+1)) | good / bad weighted counts |
| M5 | Exponential decay | weight = 0.5^(age/T) | half-life 30 days (reputation); per-watch half-life (SOC) |
| M6 | Login time | von Mises kernel density on 24 h circle vs uniform; l = -(n/(n+10)) * ln(2*pi*f(theta)) | kappa 8 (~81 min), >=8 logins, shrinkage 10 |
| M7 | Impossible travel | haversine d (R=6371.0088 km); v = max(0, d - a1 - a2)/dt; if v > 1000 km/h l = ln(0.60/0.02) = 3.40 | a1,a2 = GeoIP accuracy radii (own correction) |
| - | Poisson rate tests | l = max(0, k ln(la/ll) - (la - ll)), clamp 0 (never reassuring) | brute force 15 min la 5 / ll 0.2 (k>=2); spray la 10 / ll 0.5 distinct accounts per IP (k>=4); surge la 200 / ll 20 org-wide, cap ln 10 |
| - | IP reputation | fixed LR, strongest category only | abuse list x50 (3.91), Tor x20 (3.00), hosting x10 (2.30, humans only) |
| M8 | Change impact | replay recorded requests through old vs new policy (frozen clock, no side effects), count diffs | What-If before approving a policy edit |
| - | Audit chain | mac_n = HMAC(K, canonical(domain, seq, time, type, actor, payload, mac_{n-1})) | head compared with anchor |
| - | Policy bundle | sig_i = Ed25519(canonical(domain, seq, SHA-256(policy text), t_i)); >=2 distinct owners, <=7 days old, seq increasing | two-person rule |
| L5 | Calibration / accuracy | Beta posteriors, MFA-beta and cost sensitivity, confusion table, ROC, expected cost | reports always state their data (simulated) |
| L5.2 | UEBA | z-scores, rule of succession, half-lives in log-odds; every contribution listed; rank P1-P4 from severity, entity risk, asset criticality, provenance | checkable by hand |

Thresholds (reference costs): WebAuthn step-up above 0.00101, deny above 0.655; number-match push 0.00105 / 0.275; plain push 0.00143 / 0.0596.
Worked: normal login z ~ -9.21 -> P ~ 0.0001 ALLOW. Takeover from abroad: +14.87 -> z +7.97 -> P 0.9997 DENY.
Base-rate lesson: 99% detector, 1% false alarms, 1-in-1000 attacks -> alert wrong ~91% of the time.
Honest limits: scorers assumed independent (naive Bayes; caps limit double counting); betas and rates are assumptions; simulated
data written by same team -> consistency, not real-world accuracy.

## 7. The ten scorers (Layer 2) - evidence only, never decide

network-novelty, device-novelty (only signature-proven ids count), impossible-travel, login-time, subject-trust, device-trust,
brute-force, password-spray, attack-surge, ip-reputation. Stores (all bounded): login history (100k users, 200 logins), trust ledger
(200k entities, 1,000 events), failure log (120 one-minute buckets; recent evidence not evictable by flooding), threat intel (2M entries,
snapshot swapped whole).
Learning loop rules: learn only from full ALLOW; skip events >5 min from engine clock; reputation only if P<=0.01; device "known" only if it
proved identity; honeytoken blame only on proven devices; learning errors counted not thrown.

## 8. Policy (deciders in writing)

- YAML, closed language (no code): effects PERMIT, PERMIT_LIMITED (grants); REQUIRE_STEP_UP, DENY (constraints, only tighten);
  17 condition operators; combining DENY_OVERRIDES (default) or FIRST_APPLICABLE; default DENY. A read-only grant survives constraints.
- Safe loader: SnakeYAML SafeConstructor, no aliases/anchors/global tags, 256 KiB, depth 16, 10k nodes, 1000 policies, duplicate keys
  rejected, strict schema, symlinks not followed, linter errors (conflicts) and warnings (shadowed rules) fail load.
- Reference set (v2026.11.03-1): P-01 humans use internal private apps; P-02 finance uses confidential; P-03 confidential+ only healthy
  agent-signed device; P-04 restricted -> step-up; P-05 admin actions -> step-up; P-06 admin only with JIT `admin` role; P-10 public web;
  P-20/P-21 SaaS (unmanaged device = read-only); P-90 P(attack)>0.9 -> DENY.
- Changes: two different administrators sign (Ed25519) -> `PolicyInstaller`; rollback guard; What-If first.

## 9. Sessions (Policy Administrator) and PAM (Layer 3)

| Item | Design |
|---|---|
| Token | 256-bit random, only SHA-256 stored |
| Proof of possession | client Ed25519 session key signs every use (session, request id, subject, device, resource, action, time), <=2 min old, single-use (replay cache 4 min) |
| Binding | device agent signs the session key; IdP signs key thumbprint into MFA proof (authentication/v3) |
| Continuous evaluation | engine decides every use again; deny-list / honeytoken / rising risk ends session |
| Limits | idle 30 min; lifetime 10 h; re-auth 8 h / 4 h / 1 h / 15 min for PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED; 5 per user, 100k total |
| Revocation | by session, user or device; removed first, audited second |
| JIT admin | eligible person, <=1 h, reason, WebAuthn <=5 min old single-use, DIFFERENT person signs; lapses after 30 min; exposure 8,760 h -> ~156 h/year |
| Break-glass | sealed credential, 30 min, SOC paged at once, mandatory review by someone else; 3 uses / account / day |
| Rate limits | 5 requests / person / hour, 20 approvals / approver / hour (only authenticated actions count) |

## 10. Enforcement points - SASE edge (Layer 4)

PEPs never decide; they ask the engine API (mTLS 1.3, caller known by exact certificate subject with role + resource scope, per-caller rate
limits, 64 KiB strict JSON, generic errors, every call audited) and enforce. `RemoteSessionAuthority` pinned to API cert; any failure = deny.
- ZTNA gateway: reverse proxy; path -> resource, method -> action; only GRANTED forwarded; client `Dwarpal-*` headers stripped.
- Client agent + dev IdP: per-app Ed25519 session key; password (PBKDF2) + simulated WebAuthn over single-use challenge.
- SWG: forward proxy by host name; canonical host, block lists, categories, look-alike names, raw IPs refused, resolved address vs internal
  ranges (SSRF guard), no TLS interception.
- CASB / DLP: validated detectors (Luhn, Verhoeff, PAN, IFSC, keys, tokens); block / redact / audit by classification; values never logged.
- Session opens only on fresh verified MFA bound to the session key; each proof opens one session.

## 11. SOC loop and platform (Layers 5, 5.2)

```
decisions + logs -> keyed audit chain -> detection rules / correlation -> alerts -> rank P1..P4 -> cases (SLA)
engine <- signal feed <- playbooks (guard rails) <- signed analyst verdict (single use)
```
- Collectors: syslog, signed endpoint batches, cloud JSON; per-source quotas, event-time checks; refusals are evidence.
- Search: one query language for analysts and rules. Correlation: YAML (threshold, sequence, absence), MITRE ATT&CK tags.
- 10 built-in rules (break-glass, honeytoken, stolen token, deny storms, MFA fatigue, impossible travel then allow, DLP spikes, PAM refusals).
- Verdict counts only if signed by that analyst's key, once; privileged people need two analysts.
- Playbooks = data, signed by two admins; deny always with end (<=30 days), watch (fading), revoke; false positive undoes denies.
- Device isolation only when the device signs its own acknowledgement. SOC API = mTLS, analyst by certificate.
- **Provenance rule:** alert resting only on forgeable evidence (syslog, cloud export) may be shown / ranked / open a case but never triggers
  a destructive action. Enforced in collector, ranker, playbook linter, SOAR; one end-to-end test checks agreement.
- Scenarios: A1 stuffing, A2 cloud-server login, A3 residential proxy, A4 impossible travel, A5 Tor, A7 spray (engine stops these); A6 stolen
  laptop, A8 beaconing, A9 mass download + share (alerts/cases); look-alikes L5 (quarter-end downloads), L6 (signed backup script), QUIET.

## 12. The lab and the console (Layer 6) - front end and management shell

**Lab core:** `LabWorld` = composition root of all SOC parts; simulated company (60 users default, seed 7); scenario clock (60x); events go
through real collectors; private CA kept between runs; `LabSession` can reset to day zero; launcher `bin\lab.cmd` builds one shaded jar.

**Console server** (`dev.dwarpal.console`, JDK HttpsServer, TLS 1.3, loopback only):
- login = password + security-key PIN; `__Host-` cookie; CSRF header; idle / absolute session limits; login throttle (growing wait);
  per-route role checks (module minimum hierarchical; built-in SOC routes stay analysts+leads only - admins are not analysts);
  step-up freshness 5 min for privileged writes; exact security headers + strict CSP; every action audited; signed one-call assertion when
  acting for an analyst on the SOC API; event stream for live updates; weekly password/PIN rotation (7 days).
- Passkey gates: 15-min shared window (cases + entity + hunt), 5-min audit-explorer unlock, one-use entry for risky actions (response
  actions, report export, every step-up route). Passkey = real device (WebAuthn) or `--passkey typed` fallback.
- Plugin shape: `ConsoleModule` (id, title, minimum role, routes, optional `hidden`), mounted at `/console/api/<id>/...`; host notifies, audits.

**Front end** (`src/main/resources/console`): plain ES modules, no framework, no CDN, no `innerHTML`, no inline style, no external address
(enforced by `ConsoleSourceTest`, `SourceHygieneTest`, `ConsoleScriptsParseTest`). Files: `shell.js` (router, unlock / elevation /
step-up dialogs, footer countdown, notices button), `api.js`, `webauthn.js`, `dom.js`, `view.js`, `table.js`, `chart.js`, `globe.js`
(sign-in globe), `toast.js`, `format.js`, `glossary.js`, `prefs.js`; `views/` = login, home, overview, queue, case, hunt, entity,
response, audit, attack (ATT&CK), scans, profile, statusbar; `modules/` = guide, lab, admin, access, monitor, vault (+ css). Fonts local.

**Pages by role** (menu is built from the role; hidden module = plain "not found"):
analyst: Overview, Alert queue, Cases, Hunt, Entity, Response, Audit explorer, ATT&CK, Scans, Scenario lab, Guide, Administration (only
"Why was I denied?"), Access, Profile. Lead: + reports, run export, hard-item approvals, Monitoring (vault log). Admin: Scenario lab, Guide,
Administration (Policy, Playbooks, Privileged access, Directory, Access requests, Sessions and devices, Lab), Access, Monitoring
(Administrators), Vault, Profile. HR: Home, Access (People requests), Profile. User: Home, Access, Why was I denied, Profile.

## 13. IAM and management (Phase 2)

**Directory:** PostgreSQL 18 behind one data-access layer (`dev.dwarpal.directory`; only package with JDBC; every query a PreparedStatement;
standard SQL; `DirectorySourceTest` enforces). Tables: directory_person(+role), access_item, access_role_template, access_request(+item),
access_grant, access_approval. Migrations V001-V003 (`MigrateMain`). Logins: `dwarpal_migrator` (tables, tests), `dwarpal_app` (rows only; cannot
create/alter/drop, cannot delete people). Databases `dwarpal` (lab) and `dwarpal_test` (wiped by tests). Passwords from env vars or
untracked `db/local.properties`. Lab refuses non-local DB hosts. Admin "Directory" tab = read-only view (no address / user / password).

**Flows:**
- Joiner: HR raises (fresh password+PIN) -> administrator sees role defaults pre-ticked -> ticks / unticks -> saves under elevation -> one
  grant row per ticked item; person created; vault makes switched-off emergency password. Refusal needs reason, creates nothing.
- Access request (any non-admin): SIMPLE items (email, wiki, VPN, CRM, console) granted automatically if directory shows active; HARD items
  (finance, prod DB, analyst / lead console) need administrator AND lead; for a joiner the admin's save counts as the admin approval, lead is second.
  Nobody approves own request. Console-role grants take effect at once and end the old session.
- Leaver: HR raises -> no approval -> in one DB transaction all grants removed (from grant records, not recalculated), roles removed, open
  requests cancelled -> sessions end, sign-in shut -> vault deletes emergency password (+ admin's own entry). HR cannot remove an administrator.
- Privileged change (between the two admins): create admin, give / take admin role, own access change -> goes only to the OTHER administrator;
  asker can never decide; last active administrator can never be removed; admin own request carries no console role.

**Elevation (small PAM):** PIN + passkey + reason (5-200 chars), 10 REAL minutes (not scenario clock), footer countdown, "End now", one
session only, admins and leads only; ELEVATION_STARTED / ENDED / FAILED records; wrong PIN / passkey / missing reason give same answer.
Guards access decisions, privileged changes, every vault call.

**Passkeys:** real WebAuthn, JDK-only verification (strict CBOR reader, `PasskeyStore` public keys only, `WebAuthnStepUp`): per-person
single-use challenge (2 min), origin + rpId (`localhost`), UP + UV flags, ES256 / RS256, counter monotonic; attestation not evaluated.
Behind one function `PasskeyStepUp` (typed fallback swapped for real without touching callers). Passkey gates vault + elevation, never sign-in.

**Vault + emergency passwords:** hidden (404 for non-admins), AES-256-GCM, key in separate folder (`console/vault-key`; lose it = vault
unreadable, lab refuses to start). Per person: random `XXXX-XXXX-XXXX-XXXX` emergency password, OFF until an admin switches ON; works once on the
recovery page, person must set new password + PIN, sessions end, password replaced by new OFF one; passkey untouched. Admin may type own
(10-64 chars, readable until used). Admin own password + PIN entry readable only by that admin. Every call: open elevation + reason + fresh
second factor + passkey again; record written FIRST (no record = nothing happens); admin can never act on self. Shown secrets hide after 60 s.
Other admin + leads get notices (notified, not asked); person told on switch-on and use. Cross-admin recovery replaces paper backup codes.

**Notices:** `NoticeBoard` (file, keep 500, never a secret, 30 s polling). **Monitoring:** read-only, no write route (see section 0 gap).
**Audit trail (console):** `ConsoleTrail` on disk with own keys, checked at each start, refuses a tampered / cut / deleted trail; no route or
method edits or deletes a record; real time + scenario time; `VAULT_` records hidden from analysts, leads see action + target only.

**People (demo):** dana, spector = administrators (two accounts, one tester, code treats as two people); cleo = SOC lead (+analyst); ana, ben =
analysts; hana = HR; uma = ordinary user. First secrets in `lab\console\people.txt`.

## 14. Who decides what (all deciders in one place)

| Decision | Decider | Rule |
|---|---|---|
| Allow / limit / step-up / deny a request | PolicyEngine | max(gate, cost-optimal, policy floor), then step-up resolution + obligations |
| Open / keep / end a session | Policy Administrator + engine every use | key-bound, continuous, revocable |
| Policy change | two different administrators | signed bundle, What-If, rollback guard |
| Admin role at runtime | PAM approver (different person) | JIT <=1 h; break-glass + review |
| Alert -> action | analyst signed verdict + playbook guard rails | provenance rule, 2 analysts for privileged, deny has end |
| Isolate device | device's own signed acknowledgement | - |
| Simple access | automatic | directory shows active |
| Hard access | administrator + lead | nobody approves own |
| Admin account / admin role change | the other administrator | last admin protected |
| Joiner access | administrator under elevation | pre-ticked role template |
| Emergency password | any admin acts, other admin + lead notified | elevation + reason + passkey |
| Anything sensitive | audit record first | no record -> no action (deny) |

## 15. Security controls and evidence

- Principles: default deny; each stage only stricter; never trust client; signed evidence only; bounded everything (stores, bodies, sessions);
  fail closed; generic errors outward, detailed inward; domain-separated signatures; single-use proofs; separation of duties; two-person rules;
  least privilege (DB roles, module roles); audit before action; no secrets in code / logs / commits.
- Tests: unit + abuse cases + red-team probes per layer + cross-part probes (8 in L6) + source rules (JDBC only in directory, no innerHTML,
  no external address, no bidi characters, scripts parse). Static analysis SpotBugs + FindSecBugs = 0. CI: GitHub Actions + CodeQL
  security-extended + secret scanning (on pushed layers). Pre-commit hook (keys, tokens, bidi). SBOM via CycloneDX.
- Docs: STRIDE threat model (`threat-model.md`, v1.5), standards baseline (OWASP ASVS, NIST 800-53 / 800-207, SOC 2, ISO 27001, CIS, MITRE ATT&CK).
- Bugs found and fixed while building (shows testing works): header-size attack, count query leaking activity, audit check missing
  rewritten-then-extended history, reserved name stopped launcher, SOAR/collector findings from red team, blank-page glossary apostrophe.

## 16. How it differs from enterprise products

Glass-box decisions (every reason + number), signed evidence only, tamper-evident chain with anchor, two-person changes everywhere, no
standing admin, free to run. Enterprise ahead on: real SSO (OIDC / SAML), hardware attestation, hundreds of connectors, HA / separate
services / database for SOC state, real endpoints, ML at scale, global threat intel. Dwarpal: simulator, three collectors, one process.

## 17. Technology stack

Java 25 (Temurin), Maven 3.9 (offline-capable), JDK HttpsServer / HttpClient, SunEC Ed25519, PostgreSQL 18 + pgjdbc, SnakeYAML (safe), JUnit 5,
JaCoCo (min 80%), SpotBugs + FindSecBugs, CycloneDX, Maven Shade (lab jar), Node.js (optional, one test), plain HTML / CSS / ES modules.
Run: `bin\lab.cmd` (needs DB set up: `docs/setup.md`). Gate: `mvn -o verify spotbugs:check` (~13 min).

## 18. Tuning knobs (where to adjust behaviour)

| Want to change | Where |
|---|---|
| Prior, caps, costs, betas (risk vs friction) | engine settings / `MfaSettings`, cost model in `decision` |
| Scorer strength | each scorer's parameters (section 6-7) |
| Policy rules | `src/main/resources/policies/default-policy.yaml` (lint, What-If, 2 signatures) |
| Session / re-auth times | `SessionLimits` |
| JIT / break-glass limits | `PamSettings` |
| Console timeouts, step-up freshness, rotation days | `ConsoleSettings`, `--rotate-days` |
| Access catalogue + role templates | migration V002 (`access_item`, `access_role_template`) |
| Elevation length (10 min), vault display (60 s), reason lengths | `ConsoleServer` / `ConsoleRoutes`, `vault/index.js` |
| Lab size, speed, seed | `--users --speed --seed --warmup-days` |
| Playbooks, detection rules | YAML data (two-admin signed) |

## 19. Enhancement ideas (priority guess)

1. Pull request into `main` so CI / CodeQL run on layers 6 + Phase 2 + scale-up; fix anything it finds.
2. First-sign-in flow for joiners (no restart needed) and a simple way to add a new analyst to the SOC service.
3. (Done in the scale-up round: team activity view.) Next: analyst-versus-other role lookup for the lead's view.
4. Persist SOC state across lab restarts (rebuild cases / risk from audit trail).
5. Measure/calibrate betas, rates and priors on real or replayed logs; correlation-aware weighting instead of naive Bayes.
6. Real SSO (OIDC) + hardware attestation of devices (TPM); hybrid post-quantum signatures.
7. (PAM and reset under elevation: done.) Add automated test for "passkey stays required after emergency password".
8. (Case-insensitive names: done.) Push-style notices instead of polling; LDAP read interface over the directory.
9. Static replay site (Vercel) and container recipe for showing without Java.
10. Sensor heartbeats so the "sensor went silent" rule can fire; more collectors.

## 20. Where to read more

| Need | File |
|---|---|
| Everything in order (maths derivations, constants) | `docs/project-state.md` (sections 8-9 maths, 18 config) |
| Layer reports | `docs/layer-3-report.md`, `layer-4-report.md`, `layer-5-report.md`, `layer-5-2-report.md`, `layer-6-report.md`, `report-layers-1-2.md` |
| Team talk-through | `docs/team-guide.md` |
| Threats | `docs/threat-model.md` |
| IAM build, roles, limits | `docs/iam-architecture.md`, `docs/iam-stage-links.md` |
| Requirement-by-requirement proof | `docs/requirements-coverage.md` |
| Setup / dependencies / demo | `docs/setup.md`, `docs/dependencies.md`, `docs/demo-walkthrough.md`, `docs/runbooks/lab.md` |
