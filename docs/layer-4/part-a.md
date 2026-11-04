# Layer 4 part A: secure engine API

*Notes file of the part A session. Read [layer-4-plan.md](../layer-4-plan.md) first; keep this file up to date.*

*Status 2026-11-03: built, red-teamed and green on branch `layer4/part-a-api`. Not merged.*

## What was built

Package `dev.dwarpal.api` (7 main files, 1,326 lines; tests 5 files, 1,211 lines), built on the Part 0 contracts
(`SessionAuthority`, `WireFormat`, `TlsContexts`, `JsonReader` / `JsonLimits`, `guard.RateLimiter`)
without copying or replacing any of them.

| Class | What it does |
|---|---|
| `ApiServer` | JDK `HttpsServer` in front of Layers 1 to 3. TLS 1.3 with a client certificate required (`TlsContexts.serverParameters`); bounded worker pool and queue; at most N requests in flight; a deadline per request (handshake, headers, body, work); per-caller rate limits; 64 KiB bodies read through `JsonReader`; exact routes; role checks; generic errors; audit of every call |
| `ApiServer.Endpoint` | The v1 endpoints, each with its method and the roles it serves |
| `Caller`, `CallerRole` | Configured callers: name, exact certificate subject (RFC 2253), role `PEP`, `ADMIN_CONSOLE` or `SOC` |
| `ApiSettings` | Every abuse limit in one record, with bounds checked at startup |
| `ApiBodies` | Strict v1 bodies of the administrative endpoints (revocation, PAM request, approval, break-glass, review), which `WireFormat` does not cover |
| `RemoteSessionAuthority` | The enforcement point's HTTPS client implementing `SessionAuthority`: pinned to the CA and to the API's subject, one deadline for the whole exchange, 64 KiB answers, answers checked against the question; every failure is a deny |
| `PinnedTls` | Client TLS context that trusts the Dwarpal CA **and** only one server subject (meant to move into `TlsContexts`, see requests) |

### Endpoints

| Method and path | Roles | Body in | Answer (200) |
|---|---|---|---|
| `POST /v1/sessions` | PEP | `WireFormat` open | `WireFormat` result (OPENED carries the grant) |
| `POST /v1/sessions/use` | PEP | `WireFormat` use | result |
| `POST /v1/decisions` | PEP | `WireFormat` decide | result |
| `POST /v1/sessions/revoke` | SOC, ADMIN_CONSOLE | `{"v":1,"scope":"session"\|"subject"\|"device","id","reason"}` | `{"revoked":n}` |
| `POST /v1/pam/requests` | ADMIN_CONSOLE | `{"v":1,"subjectId","deviceId","role","minutes","justification","authentication","authenticationProof"}` | `{"ok":true,"id"}` or `{"ok":false}` |
| `POST /v1/pam/approvals` | ADMIN_CONSOLE | `{"v":1,"requestId","approverId","approval"}` | same |
| `POST /v1/pam/break-glass` | ADMIN_CONSOLE | `{"v":1,"accountId","role","justification","sealed"}` | same |
| `POST /v1/pam/reviews` | ADMIN_CONSOLE | `{"v":1,"grantId","reviewerId","verdict","signed"}` | same |
| `GET /v1/health` | any configured caller | none | `{"status":"ok"}` |

### The order of checks (first failure answers)

| Step | Check | Answer |
|---|---|---|
| 0 | TLS 1.3 handshake with a certificate chaining to the Dwarpal CA, not expired | connection refused (no HTTP at all) |
| 1 | Certificate subject equals a configured caller's, exactly | 403 `forbidden` (also for unknown paths: an unknown caller does not learn the routes) |
| 2 | Caller within its rate limit | 429 `too many requests` |
| 3 | Raw path equals an endpoint path; no query string | 404 `not found` |
| 4 | Caller's role served by the endpoint; then the method | 403 `forbidden`; 405 `method not allowed` |
| 5 | Fewer than N requests in flight | 503 `busy` |
| 6 | `Content-Type: application/json`; at most 64 KiB (declared or counted); strict JSON; strict schema | 415, 413, 400 `invalid request` |
| 7 | The engine, Policy Administrator or PAM answers | 200; any unexpected exception is 403 `denied` |
| 8 | Audit record written (refusals throttled) | an **allowed** answer that cannot be audited becomes 403 `denied` |

## Design decisions and why

| Decision | Why |
|---|---|
| One context at `/`, exact string match on the raw path | `HttpServer.createContext` matches by prefix (`/v1/sessions` would also catch `/v1/sessionsX` and `/v1/sessions/use/x`); exact matching makes `..`, `//`, `%73`, trailing slashes and case tricks plain 404s |
| Engine answers are always HTTP 200 with the `EdgeResult`; HTTP errors only for requests that never reached the engine | The enforcement point maps the result with `EdgeHttp.status`; the client treats every non-200 as DENIED, so there is exactly one way to be allowed |
| Error bodies are one of seven fixed strings | Nothing about the cause leaks (no field names, no values, no stack traces); the cause goes to the audit trail as `detail`, and `JsonException` messages never echo input |
| PAM answers only `ok` and an id | PAM already audits its reasons; "not eligible for role X" or "approval rejected: wrong key" would help an attacker probing with a stolen console certificate |
| Revocation actor is `api/<caller name>` | Each revocation in the trail names which tool asked for it |
| Health requires a configured caller and says only `ok` | No version, no counts, nothing for an outsider; audited under the refusal throttle so monitoring cannot flood the trail |
| Per-caller rate limit keyed by the caller's name, before routing | A noisy or compromised enforcement point cannot lock out the SOC (each caller has its own window) |
| Bounded pool (`AbortPolicy`) plus semaphore | The JDK server closes the connection when the executor refuses a task (checked in `ServerImpl.Dispatcher.handle`), so a flood ends in closed connections or 503s, never unbounded queues |
| Deadline per worker task, enforced by interrupting the worker | See finding A2. The JDK's own `sun.net.httpserver.maxReqTime` would also work but is a JVM-wide static setting read once; the API must not depend on another part's server having started first |
| Client pinned to the API's subject in the handshake | See finding A1. Checking after the response would already have sent the token and proof to the impostor |
| Client: `sendAsync` plus one deadline, bounded body subscriber | See finding A3. `HttpRequest.timeout` stops at the response headers; the body could drip forever or be gigabytes |
| Client checks reference and status against the question | See finding A4; defence in depth against a misrouted or forged answer |
| `Caller` stores the subject as an RFC 2253 string | See finding A5; it also makes the record immutable (SpotBugs EI_EXPOSE_REP on `X500Principal`) |
| Audit log and PAM passed to `ApiServer.builder(audit, pam)` | Same pattern as `PolicyAdministrator.builder(audit)`: not optional, and keeps SpotBugs clean without suppressions |
| No new dependency, no `pom.xml` change | JDK `jdk.httpserver` and `java.net.http` only |

## Threats and mitigations (STRIDE)

| # | STRIDE | Threat | Mitigation in code | Test |
|---|---|---|---|---|
| API-1 | S | Caller without a certificate, with one from another CA, or an expired one | TLS 1.3 with `needClientAuth`, trust store with the Dwarpal CA only | `ApiRedTeamTest.noCertificateWrongCaAndExpiredCertificatesNeverReachAHandler` |
| API-2 | S | Valid Dwarpal certificate that is not a configured caller, or a look-alike subject (`CN=GATEWAY`, `CN=gateway,O=x`) | Exact RFC 2253 subject match; unknown callers get 403 everywhere | `aValidCertificateThatIsNotACallerGetsNothing`, `a5_...` |
| API-3 | S | Another component (compromised SWG, CASB) answering in the API's place | Client pins the API subject in the handshake | `a1_aCompromisedComponentCannotPoseAsTheApi` |
| API-4 | E | Enforcement point revoking, approving elevation or breaking glass; SOC or console opening sessions | Per-endpoint role sets; 403 | `eachEndpointServesOnlyItsRoles` |
| API-5 | T | Path tricks to reach another handler (`..`, `//`, encoding, prefixes, query strings) | Exact raw-path match; query refused | `onlyExactPathsAreRoutes` |
| API-6 | T | Smuggled fields (`"admin":true`), duplicate keys, wrong types, unsupported version | `WireFormat` / `ApiBodies` strict schemas; `JsonReader` rejects duplicates | `badBodiesGetAGenericAnswerAndTheDetailIsAudited`, `ApiBodiesTest` |
| API-7 | D | Oversized bodies (declared or chunked), deep nesting, huge strings | 64 KiB cap counted on read, `JsonLimits` depth 16 and sizes | `bodiesOver64KiBAreRefusedWhetherDeclaredOrChunked`, `badBodies...` |
| API-8 | D | Slow-loris: slow handshakes, headers or bodies holding every worker | Deadline per task (interrupt closes the channel); bounded pool | `a2_slowBodiesAndSlowHeadersCannotStarveTheServer` |
| API-9 | D | Request floods from one caller; many parallel requests | Per-caller `RateLimiter`; semaphore (503); bounded queue | `perCallerRateLimitsDoNotSpillOverToOtherCallers`, `aFloodIsAnsweredBusyNotByFallingOver` |
| API-10 | I | Error answers revealing causes, stack traces or values | Fixed generic bodies; detail only in the audit trail | `anExceptionInsideIsADenyWithoutDetail`, `fuzzingEveryEndpointNeverBreaksTheServer`, `ApiBodiesTest.messagesNeverEchoTheInput` |
| API-11 | I | Session token in the audit trail | Audit records hold caller, endpoint, status, result, reference only | `everyCallIsAuditedWithCallerEndpointAndResult` |
| API-12 | R | A call nobody can trace | Every call audited with the caller's name; revocations name `api/<caller>`; an allowed answer is not sent without its record | `everyCallIsAudited...`, `revocationOverTheApiEndsTheSessionAtOnce`, `noAuditNoAccess` |
| API-13 | D | Refusal floods flooding the audit trail | 20 records per caller and status per minute, the rest counted (`suppressedAuditEvents`) | `refusalAuditsAreThrottledButCounted` |
| API-14 | E | An internal failure turning into an allow | Every exception is 403 `denied`; the client maps every failure to DENIED | `anExceptionInsideIsADenyWithoutDetail`, `garbageFromTheServerIsADeny` |
| API-15 | D | Client hung or exhausted by a slow or huge answer | One deadline for the whole exchange; 64 KiB answer cap | `a3_theClientHasADeadlineForTheWholeAnswerAndASizeLimit` |
| API-16 | T | Client accepting an answer meant for another request, or a grant where none fits | Reference must equal the request id; status must fit the call | `a4_anAnswerMustBelongToTheQuestion` |
| API-17 | T | Redirects or proxies moving the client's traffic elsewhere | `Redirect.NEVER`, `NO_PROXY`, https origin without a path only | `garbageFromTheServerIsADeny`, `misconfigurationIsRefusedAtStartup` |
| API-18 | D | API unreachable | Deny, counted in `failures()` | `theApiUnreachableIsADeny` |

## Red-team findings

Each one first reproduced as a working probe against the first version of the code (all five probes
failed on that version: impostor answered GRANTED, server starved, client hung past 8 s, foreign
answer accepted, `CN=GATEWAY` resolved to `gateway`), then fixed, then kept as a regression test in
`ApiRedTeamTest`.

| # | Breach | Root cause | Fix | Test |
|---|---|---|---|---|
| A1 | A compromised web gateway (certificate `CN=swg` from the Dwarpal CA, SAN `localhost`) listening where the gateway expects the API answered GRANTED for `web:malicious`, and received the request body (in a session use: token and proof) | Every component certificate is valid for `localhost`; trusting the CA alone trusts every component as a server | `PinnedTls`: the CA's PKIX checks, then the server's exact subject, during the handshake; `RemoteSessionAuthority.connect(..., api, ...)` | `a1_aCompromisedComponentCannotPoseAsTheApi` (also asserts the impostor saw 0 bodies) |
| A2 | Two connections sending a body one byte short and two sending half a header line held both workers; the SOC's health check timed out (even the TLS handshake of a fifth connection timed out) | The JDK server reads the handshake, headers and body on the worker thread with no time limit (`maxReqTime` defaults to forever) | Each worker task gets a deadline; the watchdog interrupts the worker, which closes its interruptible channel; interrupts never leak into the next task; `timedOut()` counter | `a2_slowBodiesAndSlowHeadersCannotStarveTheServer` |
| A3 | A server dripping one byte every 100 ms kept `decide` waiting past 8 s (`timeout` was 1 s); a server sending 128 MB would have been buffered whole | `HttpRequest.timeout` ends at the response headers; `BodyHandlers.ofByteArray` has no limit | `sendAsync` with one deadline for the whole exchange, cancelled on expiry; a body subscriber that cancels at 64 KiB | `a3_theClientHasADeadlineForTheWholeAnswerAndASizeLimit` |
| A4 | A GRANTED answer for request `e-someone-else` was accepted as the answer to another request; a login answered with a bare GRANTED would have been passed on | The client checked only that the answer was a valid `EdgeResult` | Reference must equal this request's id; logins accept OPENED / STEP_UP / DENIED / REJECTED, requests anything but OPENED | `a4_anAnswerMustBelongToTheQuestion` |
| A5 | A certificate `CN=GATEWAY` (for example issued to a different machine by a careless operator) would be the gateway | `X500Principal.equals` compares canonical forms, which fold case | Callers keyed by the RFC 2253 string, compared exactly | `a5_callerSubjectsAreComparedExactlyNotCanonically` |

Attacks that held without changes: no client certificate, certificate from another CA with the same
name, expired certificate, valid certificate not configured, valid caller in the wrong role; every
path trick tried (14 variants); unknown and wrong methods; duplicate keys, unknown members, wrong
types, wrong version, 5,000-deep nesting, invalid UTF-8, trailing content; 70 KB bodies declared and
chunked; wrong content types; 480 fuzzed bodies over every endpoint (0 internal failures, only 200,
400 and 413, never a stack trace); 80 requests from 8 threads against 1 slot (only 200 and 503, and
fine afterwards); a broken authority (exceptions with secrets in the message: answered `denied`,
secret in neither answer nor audit); audit trail down (allowed answers withheld); replayed session
request over the network; garbage, empty, partial and error answers from the server; redirects; API
unreachable.

## Tests and results

| Measure | Result |
|---|---|
| New tests | 37: `ApiServerTest` 19, `ApiRedTeamTest` 10, `ApiBodiesTest` 4, `ApiPartsTest` 3, `ApiLatencyTest` 1 |
| Whole project | **338 tests, all passing** (301 after Part 0) |
| Coverage of `dev.dwarpal.api` | **97.2% lines (518 / 533), 92.7% branches (165 / 178)**; whole project 97.0% / 89.2% |
| SpotBugs + FindSecBugs | 0 findings, no suppressions added |
| Compiler | `-Xlint:all -Werror` clean |
| Latency of one session use over the API (mutual TLS 1.3, JSON both ways, PA, engine, two audit records), 1,000 uses after 200 warm-up, coverage-instrumented | p50 3.5 to 4.2 ms, **p99 9.8 to 11.5 ms** over four runs (target 20 ms; the test gate is 50 ms to stay stable on a loaded laptop) |
| Build | `mvn verify spotbugs:check` green with JDK 25.0.5 |

Test PKI: `ApiKit` creates one `DevPki` per test run in a temporary directory (api, gateway, swg,
console, soc, stranger, an expired old-gateway, and a rogue CA's gateway). Nothing is committed.

## Requests to integration

Changes needed in shared files or Part 0 contracts. Not made here.

| # | Where | Request | Why |
|---|---|---|---|
| R1 | `edge.TlsContexts` | Add a pinned client factory, for example `createPinned(keyStore, pw, trustStore, pw, X500Principal expectedPeer)`, then delete `api.PinnedTls` and use it from `RemoteSessionAuthority.connect` | Finding A1 applies to every client in Layer 4 (gateway to app if mTLS is used, agent to gateway): trusting the CA alone trusts every component as a server |
| R2 | `edge.TlsContexts.peerPrincipal` Javadoc | It says to compare with `new X500Principal("CN=gateway")`, that is with `equals`, which folds case. Add `samePrincipal(a, b)` comparing RFC 2253 strings and point to it | Finding A5; parts B and C may compare principals too |
| R3 | `edge.WireFormat` | Make the strict field helpers and `readAuthentication` public, or move `ApiBodies` (revoke and PAM bodies) into `WireFormat` | `ApiBodies` has a small private copy of the strict helpers; one schema definition is better |
| R4 | Launcher / demo script | Start the API JVM with `-Dsun.net.httpserver.maxReqTime=10 -Dsun.net.httpserver.maxRspTime=10 -Djdk.httpserver.maxConnections=1000` | Defence in depth beyond the per-task deadline (A2); these are JVM-wide, read once, so they must come from the command line, not from code |
| R5 | `docs/threat-model.md` | Add rows API-1 to API-18 and findings A1 to A5 from this file | Shared document |
| R6 | Test fixture `DevPki` | Reject leaf names that differ only in case | On Windows `Gateway.p12` and `gateway.p12` are the same file; keytool then fails with "alias already exists" |
| R7 | Cross-part red team | (a) Scope each PEP to its resource kinds (the SWG asks only about `web:*`, the CASB only about `SAAS_DATA`), with a resource-prefix list per `Caller`; (b) decide whether a session opened through one PEP may be used through another | Today any PEP certificate may ask about any resource and use any session it holds token and proof for; harmless while all PEPs are trusted equally, worth closing once B and C exist |
| R8 | `ApiServer` revoke | Decide whether `scope: subject` should also end the subject's PAM grants (`PrivilegedAccessManager.revokeSubject`) | Incident response usually wants both; kept separate here to match the PA's API |

No `pom.xml` change and no new dependency: the API uses only the JDK's `jdk.httpserver` and `java.net.http` modules.
