# Layer 4 part B: ZTNA gateway and client agent

*Notes file of the part B session. Read [layer-4-plan.md](../layer-4-plan.md) first; keep this file up to date.*

## What was built

| Package | Class | What it does |
|---|---|---|
| `gateway` | `ZtnaGateway` | Reverse proxy (JDK `HttpServer`, optional HTTPS TLS 1.3 with device certificates). `POST /.dwarpal/v1/sessions` opens a session; every other request on a route is checked through `SessionAuthority.use` and forwarded only on GRANTED / GRANTED_LIMITED (401 + challenge on STEP_UP, 403 on DENIED / REJECTED). Virtual threads, in-flight limit (503), login rate limit per address (429), size limits (413 / 431), upstream errors 502, any exception a 403 |
| | `LoginGuard` | A login must carry fresh, step-up-grade MFA signed by a trusted identity provider, bound to this login's session key, never used before (B1, B7) |
| | `GatewaySessions` | Sessions this gateway opened: subject, device, resource come from here, never from client headers; only the token hash is kept; bounded, at most 5 per subject (B6) |
| | `RouteTable`, `RequestPath` | Route prefix to resource and upstream; download/admin sub-paths (case-insensitive, B3); strict paths with exactly one reading (no `..`, `%`, `;`, `//`, `\`) |
| | `HeaderPolicy` | Strips `Authorization`, every `Dwarpal-*` / `X-Dwarpal-*` (case and `_` insensitive), hop-by-hop and `Connection`-listed headers, client `Forwarded` / `X-Forwarded-*`; refuses method-override headers and `_method` (B4); rewrites redirects to the app's own address (B5); drops Dwarpal names and `WWW-Authenticate` from app responses |
| | `ClientEvidence` | `Dwarpal-Evidence` header: posture + signed evidence, parsed with `WireFormat.readRequest` |
| | `NetworkResolver`, `GatewayConfig` | Network from the socket address only; safe defaults (loopback, bounded sizes, secret redacted) |
| | `SampleApp` | Wiki (read, edit, download, admin settings, redirect) and vault; loopback only; requires the gateway secret (constant-time). Deliberately behaves like common servers: case-insensitive paths, honours `X-HTTP-Method-Override`, absolute self-redirects |
| `devidp` | `DevIdentityProvider`, `DevIdpServer` | Password (PBKDF2-HMAC-SHA256, salted, `UserFile`) plus simulated WebAuthn over a single-use 2-minute challenge; issues `authentication/v3` proofs bound to the session-key thumbprint; signed failure reports to a sink (`FailureReportReceiver`); per-address limits, lockout counts failures only, per subject at one address; same PBKDF2 cost for unknown users; HTTP server on loopback |
| | `SoftwareAuthenticator`, `WebAuthn` | Software security key scoped to one relying-party id (phishing resistance), monotonic signature counter (clone detection) |
| | `UserFile`, `IdpWire`, `IdentityProvider` | User file format, strict JSON, client interface |
| `agent` | `ClientAgent` | Fresh Ed25519 session key per resource; login at the IdP bound to that key; device binding; signs every request (`ClientProofs.sign`, fresh request id); on 401 re-authenticates and retries once; drops ended sessions |
| | `DeviceAgent`, `HttpIdentityProvider`, `AgentMain` | Simulated endpoint agent; IdP over HTTP (any failure = no proof); CLI `enrol`, `device-key`, `request` |

## Design decisions and why

- **Subject and device come from the gateway's own session table**, filled when the gateway opened the session, so a client cannot name another user; the PA checks them again.
- **The gateway states time, network and region** of every request (from its clock and the socket); the agent sends placeholders in the login body because `WireFormat` requires them (see requests).
- **Strict paths instead of normalisation**: refusing anything with two readings is simpler and safer than guessing how each application decodes.
- **Login requires verified MFA at the gateway** (B1), because the PA treats authentication only as risk evidence.
- **Agent and gateway share `RouteTable`**, because the signed proof covers the action.
- **Virtual threads plus a semaphore** for concurrency: excess load gets 503 at once instead of queueing without bound.
- **Lockout counts failures only, per subject and address** (Layer 3 lesson R7): no one, not even the user, locks a user out by logging in.
- The CLI's authenticator counter starts at the current epoch second (no state file): at most one login per second per authenticator.

## Threats and mitigations (STRIDE)

| # | STRIDE | Threat | Mitigation in code | Test |
|---|---|---|---|---|
| T1 | S | Stolen token used from another client | Proof of possession with the session key (PA); token hash check at the gateway | `GatewayAbuseTest.aStolenTokenIsUselessFromAnotherClient` |
| T2 | S | Client claims another identity with `X-Dwarpal-Subject` | `EdgeHttp.clientOnly` stripping; subject from the session table | `injectedIdentityHeadersNeverReachTheApp` |
| T3 | S | Login without real authentication | `LoginGuard` (B1) | `GatewayRedTeamTest.b1...` |
| T4 | T | Path tricks (`..`, `%2F`, double encoding, `;`) | `RequestPath` | `pathTricksAreRefusedBeforeAnyDecision` |
| T5 | T | Method override, case variants of admin routes | `HeaderPolicy.overridesMethod`, case-insensitive classification | `b3`, `b4` |
| T6 | R | Replay of a request or a login | PA nonce per request id; single-use login MFA proof | `aReplayedRequestIsRefused`, `b7` |
| T7 | I | Internal address leaked by redirects; analyst detail in answers | Location rewrite (B5); generic bodies | `b5`, `stepUpIsAnsweredWith401AndAChallenge` |
| T8 | I | Secrets in logs or `toString` | Secret and password redacted; token never stored in clear | `configurationRefusesUnsafeValuesAndHidesTheSecret`, `theWireFormatIsStrictBothWays` |
| T9 | D | Oversized headers, bodies, responses; floods | 431 / 413 / 502, in-flight 503, login 429, IdP per-address limits, bounded tables (B6, B8) | `oversizedHeadersAndBodiesAreRefused`, `overloadIsAnsweredBusyAndABugIsADeny`, `b6`, `b8` |
| T10 | D | Upstream down or slow | Timeouts, 502, nothing forwarded | `oversizedResponsesAndAnUnreachableAppAreBadGateway` |
| T11 | E | Direct access to the app around the gateway | Loopback only + constant-time gateway secret | `theSampleAppTrustsOnlyTheGateway` |
| T12 | E | Phished or cloned authenticator | rpId scoping, origin and rpId-hash checks, counter must rise | `theAuthenticatorIsPhishingResistantAndClonesAreCaught`, `tamperedAssertionsAreRefused` |
| T13 | S | Password guessing | PBKDF2, lockout per subject and address, signed failure reports to the brute-force detectors | `failuresLockOutOneSubjectAtOneAddressOnly`, `everyFailureIsGenericAndReportedSigned` |

## Red-team findings

Each one first reproduced as a working probe, then fixed, then kept as a regression test (`GatewayRedTeamTest`). Before the fixes the probe run gave `Tests run: 9, Failures: 8`; after, all 9 pass.

| # | Breach | Root cause | Fix | Test |
|---|---|---|---|---|
| B1 | A login with no MFA, or with MFA signed by an attacker key, opened a session as alice (201) | PA treats authentication as evidence, not a requirement | `LoginGuard`: verified, fresh, key-bound MFA required | `b1LoginWithoutVerifiedAuthenticationIsRefused` |
| B2 | The login endpoint opened a session for `web:general` (not fronted): a login oracle for other enforcement points | No check that the resource is routed | Logins only for routed resources | `b2LoginOnlyForResourcesThisGatewayFronts` |
| B3 | `POST /wiki/Admin/settings` was authorised as WRITE and changed admin settings (200) | Case-sensitive classification, case-insensitive app | Case-insensitive download/admin matching | `b3RouteClassificationIsCaseInsensitive` |
| B4 | `GET` with `X-HTTP-Method-Override: DELETE` deleted a page under a READ grant | Override headers forwarded | Refused with 400 (headers and `_method`) | `b4MethodOverrideHeadersAreRefused` |
| B5 | Redirect revealed `http://127.0.0.1:<port>/...` | App Location headers copied as is | Rewritten to gateway-relative paths | `b5RedirectsNeverRevealTheInternalAddress` |
| B6 | 8 logins by alice filled an 8-slot table; carol got 503 | Sessions closed by the PA (per-user limit) stayed in the gateway table | Per-subject limit of 5 in `GatewaySessions` | `b6OneUserCannotFillTheGatewaySessionTable` |
| B7 | A captured login from a device without an agent replayed 5 times opened 5 sessions and closed the victim's | No single-use check without device binding | Login MFA proof single-use | `b7ACapturedLoginCannotBeReplayed` |
| B8 | One address took all 10,000 IdP challenge slots; nobody else could log in | Global cap only | 30 challenges per minute per address | `b8OneAddressCannotExhaustTheIdentityProvidersChallenges` |

Held without changes: MFA bound to another key; a wiki session used on the vault; a token presented with another session's id; stolen token; replay; READ proof spent on a write; header injection; path tricks.

## Tests and results

| Measure | Result |
|---|---|
| New tests | 63 (gateway 42, devidp 12, agent 9); whole project **364, all passing** |
| Coverage | `gateway` 94.2% lines / 85.5% branches; `agent` 93.5% / 85.7%; `devidp` 98.7% / 89.1%; whole project 96.4% / 88.1% |
| SpotBugs + FindSecBugs | 0 findings (9 found and fixed: single-use `SecureRandom`, exposed intrinsic locks, mutable bind address, two regexes flagged ReDoS replaced by character loops) |
| Compiler | `-Xlint:all -Werror` clean |
| Latency added by the gateway (p99, agent through gateway minus direct to the app, localhost) | 6.9 ms when the test runs alone; 18.1 ms during the full parallel build (through gateway p50 7.8 ms, p99 23.0 ms). Target 20 ms: met when run alone, borderline under load, so the test asserts a 50 ms limit (as part A does) to avoid random failures on a busy laptop |

## Requests to integration

1. **PA should require verified MFA at `open`** (defence in depth for B1), and make the login MFA proof single-use (B7), so every enforcement point gets this, not only the gateway.
2. `EdgeHttp`: add `EVIDENCE = "Dwarpal-Evidence"`; `WireFormat`: public `evidence(...)` / `readEvidence(...)` for posture + evidence, so `ClientEvidence` need not wrap a placeholder request.
3. `WireFormat`: a client login body without `timestamp`, `network`, `pepRegion` and `action` (the gateway sets them; the agent now sends placeholders).
4. Deployment config must give the gateway a `KeyRing` holding the identity provider's public key (`IDENTITY_PROVIDER`).
5. Slow-loris limits of the JDK server are JVM-wide system properties (`sun.net.httpserver.maxReqTime`, `maxRspTime`, `idleInterval`); the demo launcher should set them. Not set or tested in this part.
6. Pre-commit hook: also refuse `*.authenticator` key files written by `AgentMain enrol` (or name them `.key`).
7. Consider `AssuranceSettings.challengeMethod = WEBAUTHN` for the demo; the agent always answers a challenge with WebAuthn.
8. Threat model: add B1 to B8.
9. No new dependencies.
