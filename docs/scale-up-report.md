# Dwarpal scale-up report

Branch `scale-up` (local only), built on `demo-ready` (38022b4). Plan and reasoning: `docs/scale-up-proposal.md`.
Sources [S1]-[S26] are the list at the end of the proposal: each page was opened by one worker and checked a second time by
another (24 supported their claim and 3 only partly, which were reworded).

## Verification state (2026-11-10/11)

| Check | Result |
|---|---|
| Full gate with database | 1,438 tests, 0 failed, 0 skipped; line 95.72%, branch 86.67%; coverage check met |
| Full gate without database (CI case) | 1,438 tests, 0 failed, 83 skipped; line 91.11%, branch 83.57%; coverage check met |
| SpotBugs | both gate runs found 2 issues (exposed mutable list in `InstalledBundles.Saved`); fixed in 4491028, SpotBugs rerun gives 0. The tests were not rerun in full after this one-line constructor fix |
| Demo smoke check | PASS 3/3 after every item and at the end: the lab starts, scenario A1 launches, sign-in works |

Corrected fact: the 95.7% coverage quoted in the older docs is the database figure. CI has no database and measures 91.1%.
Earlier no-database numbers were inflated by left-over coverage data.

## Phase 0

- **Two database test classes** (`AccessLeaverEndToEndTest`, `ElevationEndToEndTest`) crashed in cleanup when the database
  was absent. The fix guards the cleanup with `if (f != null)`. Commit 3873eba.
- **Requirements spot-check:** 17 of 19 requirements are backed by a named test. The 60-second vault hide is checked by hand
  only, and the rollback-halfway test covers the joiner but not the request or leaver paths. The table is in
  `.scale-up-scratch/p0-requirements.md`.
- **Restart facts:** sessions, elevations, behaviour, risk and SOC state, admin-installed bundles and settings are memory
  only. The trail, vault, credentials, passkeys, notices and certificates are kept as files, and the directory and access
  records are kept in PostgreSQL. Details are in `.scale-up-scratch/p0-persistence.md`.

## Built items

### 1. Case-insensitive sign-in names (89b0640)
- **What:** sign-in and recovery fold the typed name to ASCII lower case at one edge function, `ConsoleAuth.typedName`.
  Non-ASCII names are refused, never mapped.
- **Why:** person ids are already `[a-z][a-z0-9._-]{1,31}`, so "Dana" simply failed, and every letter-case variant had its
  own lockout counter. PRECIS (RFC 8265 [S21]) defines case mapping for Unicode user names. Dwarpal's ids are ASCII by
  design, so only the ASCII part applies. Unicode mapping is refused because the Kelvin sign lower-cases to "k" and
  Cyrillic look-alikes would reach real names.
- **Rejected:** full PRECIS handling (ids are ASCII); a database migration or `citext` (no stored data can be upper case).
- **Tests:** `SignInNameTest` (4): any letter case signs in; one shared lockout; non-ASCII refused; recovery in any case.
- **Limits:** only sign-in and recovery fold the name. Other inputs (HR forms) still require the exact lower-case id.

### 2. Readiness, engine-down alarm, fail-closed drill (fa9af01)
- **What:**
  - `GET /v1/ready` on the engine API runs the registered checks and answers 200, or 503 with the names of the failing
    checks only. `/v1/health` stays the liveness check.
  - `RemoteSessionAuthority`, the enforcement point's engine client, tells an `EngineAlarm` once after 5 failures in a row
    and once when the engine answers again. An alarm that throws never changes an answer.
  - `FileEngineAlarm` writes fixed-text JSON lines, capped at 1 MiB.
- **Why:** the readiness and liveness split [S12]; Envoy's external authorization fails closed by default [S11].
  Dwarpal already denied when the engine was unreachable, but nothing reported it and the health check always said ok.
- **Rejected:** an offline emergency token (the gateway would decide alone, which breaks the decision-point model);
  external load balancers (HAProxy has no Windows build, nginx on Windows is beta).
- **Tests:** `FailClosedDrillTest` (5). The engine is stopped, and open, use and decide are all DENIED within the timeout
  plus 1 s. The alarm fires once and writes its file line. A new engine on the same port is used again and "back" fires once.
  Readiness names only the failing checks, and a throwing check means not ready.
- **Limits:** the lab demo does not start the engine API or the gateway, so this hardens components that their own tests
  start. No readiness checks are registered by default; a deployment supplies them.

### 3. Installed policy and playbook bundles survive restart and reset (f99ea26, 4491028)
- **What:**
  - After a successful two-admin install, `InstalledBundles` saves the bundle under the lab folder. It is sealed with
    HMAC-SHA256 under an owner-only key in a separate folder and written atomically.
  - At start and on reset, `LabWorld` restores the bundle through `PolicyInstaller.restore` and `PlaybookInstaller.restore`.
    That path works once and only at start, recompiles the text through the same checks, and writes an audit record first.
  - A saved file that is present but refused stops the lab from starting.
- **Why:** losing a signed policy at restart is a silent rollback. OPA likewise keeps versioned bundles and can persist
  them to disk [S10]. The admins' signer keys are new at every lab start, so the original signatures cannot be checked
  again; the local seal plus the original approval record replace that check.
- **Rejected:**
  - falling back to the defaults on a bad file (a silent rollback);
  - storing the bundle in PostgreSQL (it must work with `--db off`);
  - persisting the signer keys (that widens key custody).
- **Tests:**
  - `InstalledBundlesTest` (7): a flipped byte at every position is refused, and a wrong or missing key is refused.
  - `PolicyRestoreTest` (5) and `PlaybookRestoreTest` (5): a restore works once only, never after an install, and needs a
    higher sequence and an accepted audit.
  - `InstalledBundlesEndToEndTest`: two admins install; a new lab and a reset both use the installed bundle; a changed byte
    stops the start.
- **Limits:** anyone holding both the lab folder and the seal key can plant a policy for the next start (the same trust
  level as the vault key). Moving the folder aside returns the lab to the defaults; that is an operator action outside the
  console. Threat model B1-B6.

### 4. Elevation for administrator actions (b70d5b4)
- **What:**
  - PAM request, PAM approve, PAM revoke, and lab reset (admin page and lab page) now need an open 10-minute elevation
    (PIN, passkey and reason) instead of a fresh password, PIN and passkey for each action. Without one the answer is 423,
    and the console's existing elevation dialog opens.
  - Policy and playbook approve and install, and the break-glass review, keep their fresh proofs.
- **Why:** this is the same privilege model as the vault and access pages: least privilege with privileged functions
  logged (NIST AC-6, as reported by the researcher; that page was not checked a second time), one prompt per window, and
  every action carries the elevation id. The kept actions change what the engine enforces or use a signing key.
- **Rejected:** elevation for every action (it weakens the signing actions); requiring both proofs everywhere (twice the
  friction for no gain on reversible actions).
- **Tests:** `AdminElevationTest` (7), on the real server: without an elevation the answer is 423 and nothing changes;
  inside one the action works and the record carries the elevation id; after 10 minutes and 1 second it is 423 again; the
  kept routes still need a fresh step-up; an analyst is refused. Existing tests were updated for these five routes only.
- **Limits:** a hijacked session inside an open elevation can act for at most 10 minutes. The admin page's elevation
  dialog was not clicked through in a browser (it needs an admin passkey). Threat model E1-E5.

### 5. Read-only team-activity view (84f271b, with a word-rule fix fd280da)
- **What:**
  - `GET monitor/team` and a "Team activity" tab show what people did, from the console trail: newest first, 100 rows a
    page over the latest 2,000 records, filtered by person and type, with paging.
  - Administrators see everyone except themselves. The lead sees everyone who is not an administrator.
  - Machine actors are never listed, vault rows keep the lead view, and page views are left out. There is no write route.
- **Why:** this closes the "see what team members do" gap. Audit logs that cannot be changed, with reader roles, are how
  Entra presents its audit log (reported by the researcher; that page was not checked a second time).
- **Rejected:** showing every trail row, including machine actors and access decisions. That is not team activity, and it
  would widen what the lead sees.
- **Tests:** `TeamActivityTest` (10) covers who sees whom, filters, pages that don't overlap, malformed input (400), vault
  rows never showing a secret, and no machine actors. A browser check as the lead confirmed the view renders in the theme
  using only existing classes.
- **Limits:** the 2,000-record window, and the lead cannot tell analysts from other people who are not admins (the host has
  no role lookup for that). Threat model T1-T5.

## Proposals not built

| Item | How it would be done | Effort | Main risks |
|---|---|---|---|
| OIDC: verifier and fake IdP, then console login, then IdP assurance into evidence | JDK-only discovery, JWKS client and JWT checks (alg allow-list, iss, aud, nonce, exp) [S1][S5]; an in-JVM fake IdP with negative cases; code flow with PKCE S256, single-use state, exact redirect match and the iss response parameter [S2][S3][S4]; acr and amr into evidence [S6]; local admin password kept as break-glass; Keycloak 26 zip [S7] for a manual check only (about 1250 MB [S8], needs a download approval) | L-XL, 3 sessions | home-built token checks; new callback route; IdP key compromise |
| Persistent SOC state and behaviour events | reversible migrations (down scripts, an up-down-up test) plus a `pg_dump -Fc` gate [S18]; tables for cases, verdicts, playbook runs and isolation, trail first and reconciled by checkpoint; insert-only behaviour events with row HMACs, written only after the learning gates; warm-up data tagged synthetic | L-XL, 3 sessions | poisoning lasts beyond a restart; two stores can drift; replay side effects |
| Shadow mode and calibration | candidate engine via `withPolicySet`/`withCostModel` after the live decision; a `ShadowResult` type that enforcement cannot accept; a best-effort `SHADOW_DECISION` record; promotion through the two-person install; Brier and reliability report, recommend-only, with floors and replay of the attack scenarios [S13][S14][S11] | M + S-M | labels exist only for alerted cases; an extra CPU cost per decision |
| Directory: LDAP client, SOC analysts from the directory, joiner first sign-in | JNDI search-only adapter with RFC 4515 escaping [S20], LDAPS, timeouts and fail-closed caching; the analyst set from directory roles; a one-time hashed activation code valid 24 h shown once to the admin | M each | LDAP injection, JNDI remote objects; activation-code theft |
| One-node load test | JDK-only open-model driver (fixed arrival rate, latency from the intended send time [S15]); first targets 200 decisions/s with p95 under 50 ms and p99 under 150 ms, gateway overhead p95 under 25 ms | M | a laptop measures one node only and the numbers are noisy |
| Record passkey attestation | ask for `direct` attestation and store the format and AAGUID; verifying packed or tpm needs pinned roots and FIDO MDS [S24] | S, then M-L | privacy (the model batch is identifiable) |
| Multi-node high availability | sessions and revocations in PostgreSQL (Pomerium pattern [S9]); policy polled by version and hash; an audit chain per node merged by signed heads | XL | the audit chain is a single writer today |
| WebSocket and streaming at the gateway; streaming DLP | a raw-socket path with a decision at the handshake plus periodic re-evaluation; chunked scanning with overlap | L each | memory per connection; detector boundaries |
| Agent identities | a non-human directory row with a sponsor; a key-bound Ed25519 task token valid for minutes; `act` delegation chain [S23]; MCP OAuth 2.1 profile [S26] | S design, M+L build | prompt-injection misuse; key custody |
| SCIM | `/Users` with PATCH `active=false` onto the joiner and leaver paths [S22] | M | no caller in the lab |
| SAML | not planned; broker through an OIDC IdP if ever required | - | signature wrapping |

## What still stands between this and production

1. **Identity:** there is no standard login (OIDC) yet. Passkeys have been tested with a software authenticator only, not
   real Windows Hello. LDAP is not built.
2. **State:** a restart still loses real SOC work and behaviour history (only bundles are kept). There are no down
   migrations or backup gate.
3. **Availability:** one process, one laptop. There is no multi-node deployment and no measured load figure. With the
   engine down there is no access, which is accepted by design, with no tested operations drill beyond the automated test.
4. **Keys:** lab signer keys are made at start, and keys live in files under the lab folder (there is no HSM or key
   service). Device trust has no hardware attestation.
5. **Process:** nothing on `scale-up` is pushed, so GitHub CI and CodeQL have not run on these commits. There is no
   independent security review or penetration test.
