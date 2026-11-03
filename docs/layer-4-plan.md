# Layer 4 build plan: enforcement and the SASE edge

*Plan for building Layer 4 in parallel: one integration session (this one) and three part sessions.*

## 1. Goal of Layer 4

Layers 1 to 3 decide, run sessions and grant privileges, but only as Java code. Layer 4 builds the
**Policy Enforcement Points**: the components that stand in front of real traffic and enforce those
decisions.

| Part | Builds | Packages |
|---|---|---|
| **0. Contracts** (integration session, first; **done**) | Shared interfaces, wire format, strict JSON, TLS setup, development PKI, test fixtures | `dev.dwarpal.wire`, `dev.dwarpal.edge` |
| **A. Secure engine API** | HTTPS service in front of Layers 1 to 3 with mutual TLS 1.3, plus a client for it | `dev.dwarpal.api` |
| **B. ZTNA gateway and client agent** | Reverse proxy in front of a sample internal app; client agent; development identity provider | `dev.dwarpal.gateway`, `dev.dwarpal.agent`, `dev.dwarpal.devidp` |
| **C. SWG and CASB/DLP-lite** | Outbound web filter; SaaS data control with sensitive-data detection | `dev.dwarpal.swg`, `dev.dwarpal.casb` |

## 2. Why Part 0 comes first

Without shared contracts, three parallel sessions each invent their own JSON handling, TLS setup and
request mapping, and the merge becomes a rewrite. Part 0 is small (a few hours) and is done here, then
pushed. The three part sessions start from that commit.

The key idea: parts B and C never call the HTTP API directly. They call a Java interface,
`SessionAuthority`. Part 0 provides an in-process implementation (wrapping `PolicyAdministrator`), so B
and C can be built and tested without waiting for A. Part A later provides a second implementation
that talks HTTPS. At integration they are swapped, and the end-to-end tests run over the network.

```
client agent (B) --HTTP + token + proof--> ZTNA gateway (B) --SessionAuthority--> in-process (0)  [build time]
                                                               \--SessionAuthority--> HTTPS client (A) --mTLS--> API server (A) --> Layers 1-3  [integration]
browser --> SWG proxy (C) --DecisionPoint / SessionAuthority--> ...
SaaS upload/download --> CASB (C) --> DLP detectors (C) + SessionAuthority
```

## 3. Part 0: contracts (this session)

**Status: built and tested (301 tests green).** Everything below exists on `main`; build on it.

| Item | Where | What it gives you |
|---|---|---|
| `SessionAuthority` | `dev.dwarpal.edge` | `open(login, sessionKey, deviceBinding)`, `use(token, proof, request)`, `decide(request)`. Never throws for bad input or internal failure: answers DENIED or REJECTED |
| `LocalSessionAuthority` | `dev.dwarpal.edge` | In-process implementation over `PolicyAdministrator`. Fills subject, resource and "managed" from the directory; treats claimed posture as self-reported; threat signals come from an engine-side supplier; refuses requests more than 2 min from its clock (also for `decide`) |
| `EdgeRequest` | `dev.dwarpal.edge` | What an enforcement point sends: ids, claimed posture, resource id, action, network, region, evidence. **No roles, classification or managed flag**, by design |
| `EdgeResult`, `EdgeGrant` | `dev.dwarpal.edge` | What an enforcement point gets back: status, reference, generic user message, read-only flag, challenge (STEP_UP only), grant (OPENED only), session-ended flag. No analyst detail. `EdgeGrant.toString()` redacts the token |
| `EdgeHttp` | `dev.dwarpal.edge` | Header names; `status(result)` (201/200/401/403); `challengeHeader(method)`; `action(method, downloadRoute, adminRoute)` (unknown methods have no action: refuse them); `bearerToken`, `proof` (strict header parsing); `safeHeaderValue` (no CR/LF/NUL); `clientOnly(name)`: true for `Authorization` and **every** `Dwarpal-*` / `X-Dwarpal-*` name (case and `_` insensitive): strip these before forwarding |
| `ClientProofs` | `dev.dwarpal.edge` | `sign(sessionKey, sessionId, request, at)` (proof of possession) and `bindDevice(agentKey, keyId, login, sessionKey, at)` (device binding). Use these; never build signed messages by hand |
| `WireFormat` | `dev.dwarpal.edge` | JSON v1 for requests, proofs, results and the `OpenBody` / `UseBody` / `DecideBody` API bodies, with a strict schema (unknown, missing or wrong-typed members are errors; messages never echo values). `UseBody.toString()` redacts the token |
| `TlsContexts` | `dev.dwarpal.edge` | `create(keyStore, pw, trustStore, pw)`, `serverParameters` (TLS 1.3, AEAD suites, client certificate required), `clientParameters` (plus host-name check), `peerPrincipal(session)` and `component(name)`: identify callers by **exact** principal equality, never by parsing names |
| `JsonReader`, `JsonWriter`, `JsonValue`, `JsonLimits`, `JsonException` | `dev.dwarpal.wire` | Our own strict JSON (no new dependency): 64 KiB, depth 16, 4,096-char strings, 256 members, 1,024 elements, 32-char numbers, 10,000 values; duplicate keys, invalid UTF-8, BOM, lone surrogates, NUL and trailing content are errors. The writer escapes control, line-separator and bidi characters |
| `DevPki` (test) | `src/test/java/dev/dwarpal/edge` | A private CA plus component certificates (EC P-384, serverAuth + clientAuth, SAN localhost / 127.0.0.1), made with the JDK's `keytool` in a temporary directory; `Leaf.expired(name)` for negative tests. Never commit key stores |
| `EdgeFixtures` (test) | `src/test/java/dev/dwarpal/edge` | One shared world: people, devices, resources (including `web:general`, `web:uncategorised`, `web:malicious`), keys, engine, PA, PAM, `LocalSessionAuthority`, a hand-moved clock, engine-side signals; `world.request()` builds an `EdgeRequest`, `world.open(...)` / `world.use(...)` run a session |
| Notes files | `docs/layer-4/part-a.md`, `part-b.md`, `part-c.md` | One per part; fill in as you go |

Changes made while building Part 0 that parts must know:

- The reference policy is now version `2026.11.03-1`: P-02 (finance) covers private apps only.
- There is no `tools/dev-pki.sh`; use `DevPki` in tests. A script for running the demo by hand comes at integration.

## 4. Rules for every part session

1. **Start from `main` after Part 0 is pushed**, on your own branch: `layer4/part-a-api`,
   `layer4/part-b-gateway`, `layer4/part-c-swg-casb`.
2. **Own only your packages and your notes file.** Do not edit shared files: `pom.xml`,
   `SignedMessages`, `KeyPurpose`, `docs/threat-model.md`, `README.md`, `SECURITY.md`,
   `docs/project-state.md`, other parts' packages. If you need a change there, write it under "Requests
   to integration" in your notes file; the integration session applies it.
3. **Build on the contracts**, not around them: use `SessionAuthority`, `JsonCodec`, `WireFormat`,
   `Headers`, `TlsContexts`. If a contract is missing something, say so in your notes rather than
   making a private copy.
4. **Same engineering bar as Layers 1 to 3:** fail-closed; input allow-lists and size limits; no secrets
   in logs; Java 25, `-Xlint:all -Werror`; tests with every feature; abuse cases first; a red-team pass
   where each weakness is first reproduced as a working probe, then fixed, then kept as a regression
   test; at least 80% line and branch coverage for your packages; SpotBugs and FindSecBugs clean;
   `mvn verify spotbugs:check` green.
5. **Zero cost, home laptop:** only the JDK and free, open-source tools; no Docker, no cloud accounts,
   no paid feeds, nothing to buy. Hardware (security keys, TPM) is simulated in software.
6. **Do not merge into `main`.** Commit and push your branch, then open a pull request. The project
   owner reviews and tells the integration session to evaluate it.
7. **Notes file must contain:** what was built, design decisions and why, threats and mitigations
   (STRIDE table, like `docs/threat-model.md`), red-team findings, test results, and requests to
   integration.

## 5. Part A: secure engine API

**Goal:** a network service in front of Layers 1 to 3, safe enough to expose to enforcement points.

| Component | Requirements |
|---|---|
| `api.ApiServer` | JDK `HttpsServer` (no framework); TLS 1.3 only; **client certificate required**; certificates must chain to the development CA; bounded thread pool; request body at most 64 KiB; read timeouts |
| Caller identity | From the client certificate: `TlsContexts.peerPrincipal(session)` compared exactly with configured principals (`TlsContexts.component("gateway")` and so on), mapped to a caller role: `pep` (gateway, SWG, CASB), `admin-console`, `soc` |
| Endpoints (v1) | `POST /v1/sessions` (open), `POST /v1/sessions/use`, `POST /v1/decisions`, `POST /v1/sessions/revoke` (soc, admin-console), `POST /v1/pam/requests`, `/v1/pam/approvals`, `/v1/pam/break-glass`, `/v1/pam/reviews` (admin-console), `GET /v1/health` (no data) |
| Authorisation | Each endpoint lists the caller roles allowed; everything else is 403; unknown paths 404 with no detail |
| Errors | Generic bodies (`{"error":"invalid request"}`), detail only in the audit trail; any exception is a deny, never a 500 with a stack trace |
| Abuse limits | Per-caller rate limits (`guard.RateLimiter`); JSON limits from `JsonLimits` via `JsonReader`; at most N concurrent requests |
| Audit | Every API call recorded (caller, endpoint, result), throttled for refusals |
| `api.RemoteSessionAuthority` | Client implementation of `SessionAuthority` over HTTPS with the gateway's certificate, pinned to the development CA, with timeouts; **any network or parse failure is a deny** |
| Tests | Mutual TLS happy path; no certificate, wrong CA, expired certificate, wrong role; oversized, deeply nested, duplicate-key and malformed JSON; slow-loris style slow bodies; rate limits; fuzzing of every endpoint; latency of a session use over the API (target p99 under 20 ms locally) |

## 6. Part B: ZTNA gateway and client agent

**Goal:** the first time a real HTTP request is blocked or allowed by Dwarpal.

| Component | Requirements |
|---|---|
| `gateway.ZtnaGateway` | Reverse proxy (JDK `HttpServer` in front, JDK `HttpClient` to the app); routes map path prefixes to resource ids (`/wiki/**` to `wiki`); HTTP method and route map to the action (GET to READ, POST/PUT/PATCH/DELETE to WRITE, routes marked download to DOWNLOAD, routes marked admin to ADMIN) |
| Per request | Read token and proof headers; build the `AccessRequest` (network from the real client address; subject and device from the session, never from client headers); call `SessionAuthority.use`; forward only on GRANTED or GRANTED_LIMITED; on STEP_UP answer 401 with a challenge; on DENIED or REJECTED answer 403 with the generic message |
| Hygiene | Strip every header for which `EdgeHttp.clientOnly(name)` is true before forwarding; add `X-Dwarpal-Subject` and `X-Dwarpal-Session` for the app; drop hop-by-hop headers; cap request and response sizes; never follow redirects to other hosts |
| Upstream trust | The sample app listens on localhost only and accepts only requests carrying the gateway's identity (shared secret header from config, or mTLS) |
| `gateway.SampleApp` | A tiny internal app (wiki pages: read, edit, download, admin settings) for tests and the demo |
| `devidp.DevIdentityProvider` | Development identity provider: password check against a local user file (salted, PBKDF2), simulated WebAuthn (a software authenticator key), issues **key-bound** MFA proofs (`authentication/v3`) and signed failure reports |
| `agent.ClientAgent` | Library plus small command line: generates the session key; gets the device binding from the (simulated) device agent key; logs in through the dev IdP; opens the session; signs every request (fresh request id, proof); handles 401 step-up by re-authenticating |
| Tests | Full flow through real sockets; stolen token from another client; replayed request; header injection (`X-Dwarpal-Subject` sent by the client); path tricks (`/wiki/../admin`, encoded slashes, double encoding); oversized headers and bodies; upstream unreachable is a deny; app never sees Dwarpal headers; latency added by the gateway (target p99 under 20 ms locally) |

## 7. Part C: SWG and CASB/DLP-lite

**Goal:** the other two SASE pieces modelled in the policy language (`WEB`, `SAAS_DATA`).

| Component | Requirements |
|---|---|
| `swg.WebGateway` | HTTP forward proxy: plain HTTP requests and HTTPS `CONNECT` tunnels filtered by host name (no TLS interception, so no certificate needs installing); each destination becomes an `AccessRequest` with `ResourceKind.WEB` and a classification from its category |
| Categories and threat lists | A local category file (host to category); blocklists loaded from local files in the standard hosts or domain-list format; a small sample list bundled for tests. Free public lists may be downloaded by the user, never automatically |
| Host checks | Normalise before matching: lower case, trailing dot, IDN (punycode), IP literals, ports; block raw-IP destinations unless allowed; subdomain matching (`a.b.evil.example` matches `evil.example`) |
| `casb.DataGuard` | Decides SaaS data actions (`READ`, `DOWNLOAD`, `WRITE` uploads) through `SessionAuthority`; enforces read-only sessions; inspects uploads |
| `casb.Detectors` | Sensitive-data detectors with validation, not just patterns: card numbers (Luhn), Aadhaar (Verhoeff checksum), PAN, IFSC, email addresses, private keys and API tokens (the same patterns as the pre-commit hook); each finding has a type and position, never the value itself in logs |
| DLP decision | Configurable per classification: block, allow with audit, or redact; findings recorded as risk evidence in the audit trail |
| Tests | Blocked category; blocklisted domain and its subdomains; look-alike and IDN tricks; IP-literal bypass; CONNECT to blocked host; upload containing a valid card number (blocked) versus a random 16-digit number failing Luhn (allowed); Aadhaar valid and invalid checksums; detectors on large inputs within time limits (no catastrophic regular expressions); read-only session download refused |

## 8. Integration (this session, after the three pull requests)

1. Review each pull request against this plan and its notes file.
2. Merge in order: A, then B, then C; resolve conflicts; apply the "requests to integration".
3. Swap `LocalSessionAuthority` for `RemoteSessionAuthority` and add end-to-end tests: client agent to
   gateway to API over mutual TLS to the engine, and browser traffic through the SWG and CASB.
4. Cross-part red-team pass (attacks that only appear when parts meet, for example a gateway that
   trusts a header the API never checks).
5. Full gates: all tests, coverage, SpotBugs, `-Werror`; update threat model, README, SECURITY,
   project state; Layer 4 report.
6. Push only after the project owner approves.

## 9. Practical notes

- Three sessions building at the same time on an 8 GB laptop is fine for editing and unit tests; avoid
  running three full `mvn verify` builds at the same moment.
- Each session should read `docs/project-state.md`, `docs/layer-3-report.md` and this plan first.
- Dates: Part 0 now; parts A, B, C in parallel; integration before the submission on 2026-11-06,
  leaving time for the demo (Layer 6).
