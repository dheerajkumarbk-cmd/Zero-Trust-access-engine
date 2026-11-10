# Dwarpal scale-up proposal (Phase 1)

Status: proposal only, no code. Written 2026-11-10 on branch `scale-up` (from `demo-ready` = 38022b4).
Evidence files (not committed): `.scale-up-scratch/p1-a..h-*.md`, source check `p1-sourcecheck.md`, Phase 0 facts
`p0-*.md`. Sizes: S < half a day, M about 1 day, L 2-3 days, XL more. Anything above M is split into parts that each fit
one session.

## 0. Phase 0 facts this proposal rests on

- No-database gate (the CI case) passes: 1,394 tests, 0 failed, 83 skipped. Clean coverage is **91.0% lines / 83.4%
  branches**. The 95.7% / 86.7% in the docs came from coverage data left over from earlier database runs.
- 17 of 19 requirements have a named test. The 60-second vault hide is checked by hand only. The access request and
  leaver have no rollback-halfway test (the joiner has one).
- What is lost on restart: console sessions and elevations, PAM grants, behaviour history, trust ledger, UEBA, all SOC
  state (alerts, cases, verdicts, playbook runs, isolation), policy and playbook bundles installed by an admin, and settings.
  What is kept: the audit trail, vault, credentials, passkeys, notices and certificates (files), and the directory and access
  records (PostgreSQL). Warm-up regenerates the synthetic SOC world from the seed, so real analyst work is lost.
- The Bayesian prior, MFA betas and cost weights are Java constants, not data.

## 1. Decisions in one place

| # | Decision | Why (short) |
|---|---|---|
| D1 | Dwarpal's role is **both**: the engine stays a policy decision point behind an identity provider, and the console becomes an OIDC relying party. | The products we checked split authentication (IdP) from the per-request decision (Entra Conditional Access, Pomerium, Cloudflare Access, Keycloak Authorization Services). Dwarpal already takes login evidence signed by an IdP. |
| D2 | OIDC is built **JDK-only**; SAML is **not built**. | The repo already has a strict bounded JSON reader and JDK ES256/RS256/Ed25519 verification. SAML carries XML-signature-wrapping risk with no requirement for it. An IdP broker (Keycloak or Dex) can translate SAML to OIDC if ever needed. |
| D3 | Console sessions **stay in memory**: a restart signs everyone out, and elevations are never restored. | NIST SP 800-63B says session secrets should not survive an application restart. Restart is a trust-reset event, and fail-closed is the project's stance. |
| D4 | What is persisted first is what a person **decided**: installed bundles, cases, verdicts, isolation and behaviour events (insert-only). Simulated warm-up data stays apart. | Losing an admin's signed policy on restart is a silent rollback. Losing analyst work is the real gap. Synthetic data must never mix with real labels. |
| D5 | High availability is **designed, not built**. What is built is readiness, an engine-down alert, a tested drill and a load test on one node. | One laptop cannot measure multi-node behaviour. Readiness and alerting are the parts every real deployment needs first. |
| D6 | Shadow mode runs a **candidate engine beside the live one** and never alters the live decision. Calibration only **recommends**. | Every product we checked separates evaluation from enforcement. Labels are biased (only alerted cases get labels) and logs can be poisoned. |
| D7 | Device attestation: **record** the attestation format and the authenticator model id (AAGUID) only. Full TPM attestation is design only. | Real TPM attestation needs native code or paid services. Recording is cheap, honest groundwork. |
| D8 | Agent identities get a **design only** (with an optional narrow build later). **SCIM is not built.** | The engine already has `SubjectType.WORKLOAD`, but there is no upstream HR system or IdP to drive SCIM in the lab. |

## 2. Ranking (value for real-world use against effort)

Recommended build order. Each row is one approval unit with one local commit (split rows get one commit per part).

| Rank | Item | From | Size | Value | Why this rank |
|---|---|---|---|---|---|
| 1 | Case-insensitive sign-in names | g | S | medium | Cheap; removes a real usability and lockout-counter gap |
| 2 | Readiness, engine-down alert, fail-closed drill | c | M | high | Operations basics; no state change; finishes the fail-closed story |
| 3 | Keep installed policy and playbook bundles across restart | b | S-M | high | Closes a silent rollback; reuses the signed bundle as-is |
| 4 | Elevation for admin actions (per-action rule) | g | S-M | medium | Consistent privilege model; small change |
| 5 | Team-activity monitoring (read-only) | g | M | high | Meets the original "see what team members do" |
| 6 | OIDC: verifier and fake IdP, then console relying party, then IdP assurance into evidence | a | L-XL (3 parts) | very high | Standard login is the first thing a real organisation asks for |
| 7 | Shadow mode (candidate engine) and calibration report | e | M + S-M | high | Lets policy changes roll out safely; makes the maths checkable |
| 8 | Persistent SOC state and behaviour events, reversible migrations and backup gate | b | L-XL (3 parts) | high | Real analyst work survives; needs the migration safety first |
| 9 | Directory: LDAP client, SOC analysts from the directory, joiner first sign-in | d | M each (3 parts) | medium-high | Real directories; ends the fixed three analysts |
| 10 | One-node load test (JDK-only driver) with targets | c | M | medium | Measured numbers instead of claims |
| 11 | Record passkey attestation format and AAGUID | f | S | low-medium | Groundwork for hardware trust |
| - | Designs only: multi-node HA, TPM attestation, agent identities, SCIM | c f h | S each (write-up) | - | See section 4 |
| - | Rejected: SAML; external load balancer; Keycloak as a permanent part of the lab | a c | - | - | See each item |

Note: today is the project deadline (2026-11-10). Ranks 1-5 are safe before a demo. Ranks 6 onward change sign-in or
state, so they belong on `scale-up` after the demo version (`demo-ready`) has been shown.

## 3. Items

Each item gives what real practice does, the proposal, rejected alternatives, size, risks, tests and threat-model changes.
Every built item ends with the relevant tests, the no-database gate once per phase, the demo smoke check
(`smoke-run.sh`: lab starts, scenario launches, sign-in works) and one local commit.

### 3.1 (a) Standard login: OIDC

**Practice.** The IdP authenticates and the decision point decides per request with the IdP's signals (Entra Conditional
Access evaluates its policies at sign-in [S13]. Pomerium splits authenticate / authorize / proxy / databroker, and
Cloudflare Access is the relying party to your IdP and issues its own signed token to the app. Those two were read by
one worker only and have no link here.)
**Proposal (D1, D2), in three parts:**
- **6a Verifier and fake IdP (M-L).** `dev.dwarpal.oidc`: discovery (issuer must equal the configured issuer exactly),
  JWKS client (https only, configured issuer only, cache, refetch on an unknown `kid` with a rate limit, size and time caps),
  JWT verification with an algorithm allow-list tied to key type (RS256 with keys of 2048 bits or more, ES256 in raw R||S
  form, EdDSA). The token's own `alg`, `jku`, `x5u` or embedded `jwk` are never trusted, and `none` is never accepted.
  Checks: `iss`, `aud` contains the client id, `azp`, `exp`, `iat` (2-minute skew, the same as KeyRing), `nonce`,
  `auth_time` when `max_age` was sent, and the token type, so a logout token is never taken as an ID token. [S1][S5]
  Tests use an in-JVM fake IdP on `com.sun.net.httpserver` with negative cases: wrong iss, aud, nonce or state; `alg`
  none; swap to HS256 with the public key; expired; future `iat`; unknown or rotated `kid`; tampered payload.
- **6b Console as relying party (L).** Authorization code flow only, PKCE S256, `state` tied to a cookie and used once,
  exact redirect-URI match, the `iss` response parameter checked against mix-up attacks, and tokens kept server-side.
  The browser gets only the existing opaque session cookie. [S2][S3][S4] The local password plus PIN stays as the
  break-glass sign-in for admins (an IdP outage must not lock out the operators). Passkey step-up for the vault and
  elevation is unchanged.
- **6c IdP assurance into evidence (S).** `acr`, `amr` and `auth_time` become IdP-signed login evidence under the existing
  `IDENTITY_PROVIDER` key purpose. `hwk` or `swk` plus user verification count as phishing-resistant; a missing `amr`
  means password only. They feed risk and step-up, never ALLOW directly. [S6]
**Test IdP.** Keycloak 26.x runs from the zip with `bin\kc.bat start-dev`, with no container. [S7] Its sizing guide speaks of
about 1250 MB per instance [S8], so it does not fit a laptop with under 1 GB free. It is used only for a one-off manual
check with the lab stopped, and the download needs your approval. The automated tests never need it.
**Rejected:** Nimbus JOSE+JWT (Apache-2.0, but it breaks the JDK-only crypto rule and saves only about 300 lines). SAML
(D2). Role B alone, an external gateway in front (a new product, XL, RAM). Implicit flow (forbidden by the security best
practice). [S2]
**Risks.** Home-built token checks are security-critical, so the negative-test list is the acceptance bar. The callback
adds a new public route. Logout (RP-initiated or back-channel) is not in this scope; sessions still end by idle or absolute
timeout.
**Threat model (new surfaces).** The callback route, the JWKS fetch (SSRF is limited to the configured issuer), IdP key
compromise, token replay, mix-up attacks, and the break-glass local sign-in.

### 3.2 (b) Persistent state

**Practice.** The server enforces the idle timeout and renews the session id after a privilege change. [S16] NIST says
session secrets should not persist across a restart. [S17] Keycloak keeps user sessions in its database by default (one
worker read this; it has no link). That is the opposite choice, rejected for D3. Event sourcing (append-only events, replay with side effects switched off) and the
transactional outbox are the standard ways to keep a projection consistent with a log.
**Proposal:**
- **Rank 3, installed bundles (S-M).** The last accepted signed policy bundle and playbook bundle, with their sequence
  numbers, are stored under `--dir` and verified again in full on load (signatures, two signers, rising sequence). A bundle
  that fails is refused and the lab starts on defaults and says so, so a tampered file can never install itself.
  This works with `--db off`.
- **Rank 8a, reversible migrations and backup gate (M).** Each `Vnnn__x.sql` gets a `Vnnn__x.down.sql`.
  `Migrator.rollbackTo(n)` runs as the migrator role, newest first, one transaction per script, with checksums for the down
  scripts too. The migration command refuses to run unless a fresh `pg_dump -Fc` backup exists. [S18] A test runs up,
  then down, then up, and compares the schema. Flyway undo was rejected (a new dependency [S19]), and so was Liquibase
  (also a new dependency).
- **Rank 8b, SOC state (L).** Tables for cases, case alerts, verdicts, playbook runs and isolation, each with a `source`
  column (sim or live). The order is the trail first (it already fails closed), then the database. A checkpoint sequence
  lets the next start reconcile from the trail. Alert ids make replay idempotent. Replay never runs actions again.
  Isolation is restored (fail-closed means a device stays isolated).
- **Rank 8c, behaviour and trust events (M).** An insert-only event table, written only inside `learn()` after the existing
  anti-poisoning gates. The app role gets INSERT and SELECT only. Each row carries an HMAC, and a bad row means "no history"
  (higher risk), never trust. `forget` becomes a tombstone row, so a poisoned baseline stays forgotten after restart.
  There is a retention window of 90 days. Warm-up data is tagged synthetic and never stored.
- **With `--db off`:** the in-memory stores behave as today, and the console says persistence is off.
**Rejected:** persisting sessions or elevations (D3). Stateless signed cookies (cannot be revoked without new state).
Rebuilding everything from the trail alone (trail records do not carry whole alerts). Storing behaviour aggregates
(a tampered row would silently poison, and a code change could not rebuild them).
**Risks.** Persistence turns "poisoning lasts until restart" into "poisoning lasts", which is why the gates, the row HMAC,
the retention window and `forget` matter. Writing to two stores means drift, handled by the checkpoint reconcile.
The test matrix doubles (database and no database).
**Threat model.** The new tables and their grants, tampering with stored events, replay side effects, and the bundle file
under `--dir`.

### 3.3 (c) High availability and load

**Practice.** The common pattern is one authoritative store, a local cached copy, versioned policy, and last-known-good
on disconnect. OPA distributes versioned policy bundles and can persist them to disk [S10]. Pomerium's in-memory store is single-instance only and
PostgreSQL gives HA [S9]. Envoy's external authorization fails closed by default [S11]. Readiness ("can serve now") is
kept separate from liveness ("restart me"). [S12]
**Today.** The engine being unreachable already means DENIED (`RemoteSessionAuthority.java:157`). `/v1/health` is a fixed
"ok". Nothing alerts when the engine is down, and the gateway buffers whole bodies and drops `Upgrade`, so WebSockets
and streaming are not supported.
**Proposal:**
- **Rank 2 (M).**
  - `/v1/live` is the process only.
  - `/v1/ready` checks that keys are loaded, a policy with version and hash is present, the audit store can append, and
    the database answers when it is on. It returns 503 with a reason code, never details.
  - The gateway counts engine-unreachable refusals; past a threshold it writes an alert through the existing connector and
    shows a console notice.
  - A scripted drill test stops the engine and checks three things: every request class is DENIED within the timeout, the
    alert fires, and recovery works.
  - **No offline emergency token.** With the engine down, access stays shut. The existing PAM break-glass covers
    privileged roles while the engine is up. This choice is documented as the emergency path.
- **Rank 10 (M).** A JDK-only open-model load driver (`java.net.http`, fixed arrival rate, latency measured from the
  intended send time to avoid coordinated omission [S15], a log-bucket histogram), run outside the gate. The first targets
  on this laptop are proposals to adjust after a baseline:
  - 200 decisions/s through the TLS API with p95 under 50 ms, p99 under 150 ms, and no errors;
  - gateway overhead p95 under 25 ms;
  - recovery within 10 s after 60 s at three times the knee.
  It also checks the limits, which are refused cleanly and not supported:
  - 1 MiB request and 8 MiB response limits;
  - the CASB 8 MiB inspection cap;
  - slowloris cut at 30 s;
  - 200 held SWG tunnels;
  - a WebSocket upgrade refused cleanly.
- **Design only (in the report):** several engine nodes, sessions and revocations in PostgreSQL, policy polled by
  version and hash, the audit chain per node with signed heads merged by the anchor, and WebSocket support with a
  decision at the handshake plus periodic re-evaluation.
**Rejected:** HAProxy (no Windows support in its docs), nginx on Windows (beta, one worker), Envoy (a new product), k6
(AGPL and a new binary), and an offline emergency token (it would let the gateway decide alone, which breaks the PDP model).
**Threat model.** The readiness endpoint (no detail leaks; behind the same mTLS), alert flooding, and a documented
"engine down means no access" availability risk.

### 3.4 (d) Directory

**Practice.** The access system reads the corporate directory (it is a source of attributes), and does not serve it.
**Proposal:**
- **9a LDAP client (M).** A JDK JNDI adapter behind `pip/AttributeDirectory`, read-only:
  - search only, never `lookup` of anything influenced by input;
  - RFC 4515 escaping of filter values [S20], and an empty password is refused (it can be an anonymous bind);
  - LDAPS or StartTLS with a dedicated trust store, referrals ignored;
  - connect and read timeouts, size and time limits;
  - a short cache with a maximum age; when the directory is down past that age, attributes are missing, which means DENY.
  Tests use a small in-JVM fake LDAP responder (BER subset), so no new dependency. A manual check against ApacheDS (Apache-2,
  Windows installer, but a 2023 milestone release) needs your approval for the download.
- **9b SOC analysts from the directory (M).** The analyst set comes from directory people holding the analyst role, not
  from the fixed ana, ben and cleo. New analysts act through the console's delegation path. Personal verdict-signing keys
  for new analysts are a later step (they need key custody), so their verdicts are recorded as console-delegated.
- **9c Joiner first sign-in (M).** When HR saves a joiner, the admin's response shows once a one-time activation code:
  random, stored only as a hash, valid for 24 h, bound to that person, throttled, and used once. The first sign-in forces a
  new password, a PIN and a passkey. The code never goes on the notice board, because notices forbid secrets.
**Rejected:** Dwarpal as an LDAP server (XL, low value); UnboundID (a new dependency); `citext`.
**Threat model.** LDAP injection, JNDI remote objects, a rogue directory or referral, activation-code theft or guessing,
and directory outage behaviour.

### 3.5 (e) Shadow mode and calibration

**Practice.** Entra report-only evaluates at sign-in and logs without enforcing [S13]. Istio dry-run [S14] and Envoy shadow
mode [S11] also evaluate without enforcing. They log the would-be result beside the enforced one.
**Proposal:**
- **7a (M).** A candidate engine built with the existing `withPolicySet` / `withCostModel` runs after the live decision on the
  same request and signal snapshot:
  - it returns a `ShadowResult` type that enforcement code cannot accept;
  - its failures are swallowed and counted, and it has a time budget;
  - it writes a separate `SHADOW_DECISION` record (request id, candidate hash, live and candidate outcome, and the
    difference: same, stricter or looser), with full detail only when they differ, and on a best-effort basis;
  - a shadow failure never changes the live decision;
  - hard gates, honeytokens, deny-lists, freshness, the vault and the audit chain are never shadowed;
  - starting a candidate needs one admin plus a rate limit, and promoting it needs the existing two-person signed install.
  The acceptance test is that the live decision is byte-identical with shadow on and off across all lab scenarios.
- **7b (S-M).** A calibration report, recommend-only: a Brier score against the base-rate predictor, a reliability table with
  log-spaced bins and intervals, Beta updates with stated informative priors for the MFA betas, and the cost ratio implied
  by a chosen false-alarm budget. Poisoning guards: floors on the prior and the betas, a per-entity contribution cap, and
  replay of the 9 attack scenarios, which must still be refused under any candidate.
- **Later (L, not in this round):** prior, costs and betas as a signed, versioned parameter bundle with its own installer.
**Rejected:** a per-policy `mode: shadow` field in YAML (L; its semantics in deny-overrides combining are unclear);
OPA, Istio or Envoy as sidecars (dependencies).
**Risks.** Labels exist only for alerted cases, so the prior is a lower bound. The published MFA figures (Microsoft:
about a 99.2% reduction in compromise [S25]) measure "any MFA against none", not a per-method bypass rate.
**Threat model.** Shadow-log flooding, a candidate as a covert channel (it cannot reach enforcement by type), and poisoning
of calibration.

### 3.6 (f) Device trust

- **Rank 11 (S).** Ask for `direct` attestation at passkey registration and record the format and AAGUID, without
  verifying them. The console shows "attestation: none / packed / tpm". The `HARDWARE_ATTESTED` level stays unreachable,
  and that is honest.
- **Design only:**
  - `packed` verification with pinned roots (M);
  - `tpm` verification of the attestation structures (M-L);
  - the FIDO metadata (MDS3) signed file loaded offline, terms to be read first [S24];
  - attestation of the agent's device key by the TPM, which needs Windows CNG calls through JDK 25 FFM or an external
    tool (L-XL);
  - PCR quotes (XL, fragile).
- **Rejected:** Intune, Chrome Verified Access, Apple attestation (tenants or paid). A simulated TPM vendor CA in the lab is
  possible (M-L) but proves only the verifier, so it is not proposed.

### 3.7 (g) Smaller gaps

- **Rank 1, names (S).** Fold sign-in and recovery input to ASCII lower case (`Locale.ROOT`) at one edge function. Login
  throttle keys use the same fold, because today "Dana" and "dana" get separate lockout counters (`LoginThrottle.java:119`).
  Non-ASCII input is refused, not mapped (the Kelvin sign U+212A lower-cases to "k"). No migration is needed: ids are already
  forced to `[a-z][a-z0-9._-]{1,31}` (`DirectoryPerson.java:32`). A database CHECK can be added later with the migration
  work in 8a. RFC 8265 full PRECIS handling [S21] was rejected because ids are ASCII by design.
- **Rank 4, elevation for admin actions (S-M).** Per-action rule:
  - PAM approve, deny and revoke, and lab reset: accept an open elevation instead of fresh password, PIN and passkey;
  - policy and playbook approve and install: keep fresh proofs plus the two-person signature, because these change what
    the engine enforces.
  Each accepted action records the elevation id. `AdminModuleTest` and `LabModule` tests change.
- **Rank 5, team-activity monitoring (M).** The monitoring page shows the trail rows of every team member, not only the
  other admin. Today `MonitorModule.java:80` keeps only administrators.
  - Filters: person, record type, time; paging with a cap.
  - Redaction: vault rows keep their lead view, and secrets and reasons never appear.
  - Who sees what: admins see everyone except themselves, and the lead sees analysts plus the restricted vault log.
  - Nobody can change a row, because there is no write route. Admins watching admins is unchanged.
  - New interface parts use only the colour variables.
  `MonitorEndToEndTest` changes.

### 3.8 (h) Agent identities and SCIM

- **Agents (design only, S).** The engine already has `SubjectType.WORKLOAD`. The design (in the report):
  - a non-human directory row with a human sponsor;
  - a Dwarpal-signed Ed25519 task token bound to the agent's key, valid for minutes, with one task id, audience and scope;
  - the delegation chain recorded as in RFC 8693 `act` [S23];
  - the same per-request decision with its own behaviour baseline;
  - a kill switch, rate limits and an audit record per tool call;
  - the engine never trusts the agent's own stated intent (prompt injection).
  MCP's OAuth 2.1 profile with PKCE is the reference for tool calls [S26]. A narrow build (M plus L) is possible after the
  design is approved.
- **SCIM: not built.** RFC 7644 `/Users` with PATCH `active=false` maps onto the existing joiner and leaver paths [S22],
  but nothing in the lab would call it. A design note only.

## 4. Proposals not built in this round (summary; full steps go in the final report)

Multi-node HA, WebSocket and streaming support in the gateway, a streaming DLP scan, signed parameter bundles,
TPM and `packed` attestation, personal signing keys for new analysts, an agent task token, SCIM, OIDC logout, SAML.

## 5. What I need from you

1. Approve, reorder or drop items by rank (for example "build 1-5 now").
2. Downloads: Keycloak (for a manual OIDC check) and ApacheDS (for a manual LDAP check) are optional. Say yes or no.
3. Confirm D3: a restart keeps signing everyone out.

## Sources (opened by a worker and checked a second time by a different worker; see p1-sourcecheck.md)

- [S1] https://openid.net/specs/openid-connect-core-1_0.html : ID token validation (3.1.3.7): iss, aud, nonce.
- [S2] https://www.rfc-editor.org/rfc/rfc9700.html : OAuth 2.0 security best practice: PKCE, no implicit, exact redirect match.
- [S3] https://www.rfc-editor.org/rfc/rfc7636.html : PKCE S256, verifier of 43-128 characters.
- [S4] https://www.rfc-editor.org/rfc/rfc9207.html : `iss` in the authorization response against mix-up.
- [S5] https://www.rfc-editor.org/rfc/rfc8725.html : JWT best practice: algorithm allow-list, no `none`.
- [S6] https://www.rfc-editor.org/rfc/rfc8176.html : `amr` values (pwd, otp, mfa, hwk, swk).
- [S7] https://www.keycloak.org/getting-started/getting-started-zip : Keycloak 26.8.2, OpenJDK 25, `kc.bat start-dev`.
- [S8] https://www.keycloak.org/high-availability/single-cluster/concepts-memory-and-cpu-sizing : about 1250 MB per instance.
- [S9] https://www.pomerium.com/docs/internals/data-storage : in-memory store single instance only; PostgreSQL for HA.
- [S10] https://www.openpolicyagent.org/docs/latest/management-bundles/ : versioned bundles, persist to disk.
- [S11] https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/ext_authz/v3/ext_authz.proto : fail closed by default; shadow mode.
- [S12] https://kubernetes.io/docs/concepts/configuration/liveness-readiness-startup-probes/ : readiness against liveness.
- [S13] https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-report-only : report-only evaluates and logs without enforcing.
- [S14] https://istio.io/latest/docs/tasks/security/authorization/authz-dry-run/ : dry-run annotation, experimental.
- [S15] https://grafana.com/docs/k6/latest/using-k6/scenarios/concepts/open-vs-closed/ : open against closed models, coordinated omission.
- [S16] https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html : server-side idle timeout, id renewal on privilege change.
- [S17] https://pages.nist.gov/800-63-4/sp800-63b/session/ : session secrets should not persist across an application restart.
- [S18] https://www.postgresql.org/docs/current/app-pgdump.html : consistent backups while in use, `-Fc` with pg_restore.
- [S19] https://documentation.red-gate.com/flyway/reference/commands/undo : undo of the latest versioned migration with a U script.
- [S20] https://www.rfc-editor.org/rfc/rfc4515.html : escaping in LDAP filter values.
- [S21] https://www.rfc-editor.org/rfc/rfc8265.html : PRECIS UsernameCaseMapped.
- [S22] https://www.rfc-editor.org/rfc/rfc7644.html : SCIM /Users, /Groups, PATCH.
- [S23] https://www.rfc-editor.org/rfc/rfc8693.html : token exchange, `act` delegation claim.
- [S24] https://fidoalliance.org/metadata/ : FIDO Metadata Service signed BLOB.
- [S25] https://arxiv.org/abs/2305.00945 : Microsoft study, MFA cuts compromise risk by 99.22% (98.56% with leaked credentials).
- [S26] https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization : MCP authorization on OAuth 2.1 with PKCE.

Not cited, because no page could be read or checked a second time: the NIST SP 800-207 body (the PDF came back
unreadable; only the abstract was read), Elkan 2001, the Google 2019 MFA study, Cloudflare and Pomerium architecture
pages, Okta.
