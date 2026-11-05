# Layer 6 part G: the console server

*Notes for the integration session. Code: `src/main/java/dev/dwarpal/console/` (everything except `ConsoleModule.java`).
Tests: `src/test/java/dev/dwarpal/console/`. Built to `docs/layer-6/contract.md` and `docs/layer-6/standards.md`.*

## 1. What it is

An HTTPS server (JDK `HttpsServer`, TLS 1.3 only through the existing `TlsContexts` constants, certificate leaf `console`
from the lab PKI, loopback by default) that serves the static console from a fixed allow-list read from the jar at start-up
and the JSON API of contract section 3. `ConsoleMain` starts a `LabWorld`, a `LabRunner` and the server, and prints the URL,
the certificate authority file the browser must trust, and the demo logins.

```
 browser --TLS 1.3--> ConsoleServer --pipeline--> routes ---> SocChannel --mTLS + signed delegation--> SOC API
                          |  Host, method, path, headers size, Origin, content type                       (as the analyst)
                          |  session (cookie), CSRF token, role, rate limits, step-up
                          |  audit: intent before a write, outcome after, sensitive reads before data leaves
                          +--> StreamHub (SSE)   +--> LabAudit (explorer)   +--> ConsoleModule routes (parts I, J)
```

| Class | Job |
|---|---|
| `ConsoleServer` | The pipeline in the order of its class comment. Owns threads, deadline watchdog, the poller that feeds the event stream |
| `ConsoleRoutes` | Built-in routes: session, me, modules, lab, stream, `soc/**`, `audit/**` |
| `ConsoleAuth` | Login and step-up through `DevIdentityProvider` (PBKDF2 password + simulated WebAuthn assertion); `LoginThrottle` |
| `ConsoleSessions` | Server-side sessions: 256-bit ids, idle 15 min, absolute 8 h, 3 per person, address and agent binding, rotation at step-up |
| `SocChannel`, `DelegatedSocChannel` | The only code that knows how an analyst is identified to the SOC API (the `console` certificate plus `Dwarpal-On-Behalf-Of`) |
| `VerdictSigner`, `LabVerdictSigner` | The seam for verdict signatures; first implementation signs with the lab's analyst key |
| `StreamHub` | Server-sent events: one per session, capped, bounded queue per stream, events carry no data |
| `StaticFiles` | The allow-list; the request path is never turned into a file path |
| `ConsoleAudit` | Writes into `LabWorld.org.audit`, sanitised, hashed session tag, failure counted and returned |
| `LabHandle` | The one place that says which lab is running, so a lab reset (new `LabWorld`) needs no change in the console |
| `ConsoleModuleProvider` | `ServiceLoader` seam: parts I and J list a provider in `META-INF/services/dev.dwarpal.console.ConsoleModuleProvider` and `ConsoleMain` loads their modules |
| `DemoPeople` | ana, ben (analysts), cleo (lead), dana (administrator), uma (user); random secrets in `<lab>/console/people.txt` (owner-only) |

### Decisions worth knowing

* **Second factor in the lab.** The browser holds no key. The "security key" is a `SoftwareAuthenticator` held by the console
  process; its local user check is a PIN printed at start-up. The IdP sees a real WebAuthn-style assertion over a fresh
  single-use challenge and checks password and assertion together, so the wrong PIN, the wrong password and an unknown user
  all give the same `login failed`. Step 1 (`login`) always answers with a login id, also for unknown users.
* **Login counts as a step-up.** Both factors were just proved, so a session starts with five minutes of freshness. A later
  step-up (`session/stepup`: password and PIN again) issues a **new session id and token**; the old identifier is dead.
* **Roles.** `satisfies(roles, minimum)`: `USER` is any signed-in person; `ANALYST` is analyst or lead; `LEAD` is lead; `ADMIN`
  is administrator. An administrator is not an analyst (segregation of duties): no SOC route, no audit explorer.
* **Every body is rebuilt.** The browser sends typed fields (`{"text"}`, `{"assignee"}`, `{"alertId","outcome"}`, ...), unknown
  fields are an error, and `DelegatedSocChannel` builds the SOC API body itself. Nothing in a request names who is acting.
* **Audit design.** A write records intent (`CONSOLE_WRITE phase=attempt`) before it runs and the result after; if the
  intent cannot be written the write does not happen. A sensitive read (`soc/cases/{id}`, `.../timeline`, `soc/risk/{kind}/{id}`,
  `soc/search`, `soc/counts`, `soc/reports/{name}`, `audit/records/{seq}`, `audit/verify`) is recorded before data is sent; if
  the record cannot be written the answer is 503 with no data. Search and counts record a hash and the length of the query,
  never its text; notes record their length, never their text.
* **Audit explorer.** Paging, one record and `verify` come from `LabWorld.auditView`. An analyst sees the full detail of the
  console's and the SOC API's own records and only the header of the rest (those contain facts about colleagues that the SOC
  API would not show them); a lead sees everything. Verify is limited to 6 per minute per person and recorded.
* **Static files.** `Cache-Control: no-cache` plus an `ETag` (there is no build step, so no hashed names exist to cache for
  long). Files of a module (`modules/<id>/...`) go only to a signed-in person who may see that module.
* **Time.** Sessions, throttles and step-up use the wall clock (injectable for tests); audit records carry scenario time, like
  the SOC API's.

## 2. Standards section 3, line by line: where each is tested

| Standards line | Test |
|---|---|
| HTTPS only, TLS 1.3, HSTS, no plain listener | `ConsoleHeadersTest` (`onlyTls13Works`, `thereIsNoPlainHttpListener`, `aClientThatDoesNotTrust...`, HSTS value) |
| Exact headers on every response | `ConsoleHeadersTest.theHeadersAreExactlyTheStandards...` (11 kinds of answer: static, 404, 401, 405, API, login errors, stream in `ConsoleStreamTest`) |
| Cache-Control | `ConsoleHeadersTest.apiAnswersAreNeverCached...`, `ConsoleStaticTest.filesRevalidateWithAnEtag` |
| Cookie `__Host-dwarpal` Secure HttpOnly SameSite=Strict Path=/ | `ConsoleHeadersTest.theSessionCookie...` |
| Idle 15 min, absolute 8 h, new id at login and step-up, logout destroys, session limit and list | `ConsoleSessionTest` (12 tests) |
| Binding of the session | `ConsoleSessionTest.aStolenCookieUsedFromAnotherBrowser...` |
| CSRF token + Origin + JSON, no CORS | `ConsoleRequestGuardTest`, `ConsoleRedTeamTest.a2` |
| Password + second factor, identical answers, throttling with visible lockout | `ConsoleSessionTest`, `ConsoleThrottleTest`, `LoginThrottleTest` |
| Step-up 5 min for privileged writes | `ConsoleSessionTest.stepUp...`, `ConsoleAccessTest.aVerdictNeedsAFreshStepUp...`, `...theHostChecksRoleCsrfAndStepUp...` |
| Server-side authorisation by role and object | `ConsoleAccessTest` (roles on every `soc/` and `audit/` route; the SOC API's own object rules pass through) |
| Strict input: size, unknown fields, identifiers, raw paths | `ConsoleRequestGuardTest.bodiesAreBounded...`, `...rawPathsAndQueryStringsAreStrict` |
| Errors never leak | `ConsoleRedTeamTest.a9`, `ConsoleAccessTest.aModuleThatThrowsLeaksNothing` |
| Static files: allow-list, exact names, content types, nosniff | `ConsoleStaticTest` (including the jar loader) |
| Audit of login, failed login, step-up, logout, writes, sensitive reads; session id hashed; audit failure surfaced | `ConsoleAuditTest` |
| Secrets not in URLs | `ConsoleRedTeamTest.a3` (the page-side half, no `localStorage` secrets, is part H's source test) |
| Rate limits, bounded sizes and concurrency, request timeout, bounded stream | `ConsoleRequestGuardTest`, `ConsoleStreamTest`, `ConsoleRedTeamTest.a6`, `a8`, `a13` |
| Host header (DNS rebinding) | `ConsoleRequestGuardTest.aForeignHostHeaderIsRefused` |

Not covered by this part: *session bound to TLS channel parameters* (the JDK server does not expose them; the address and
agent binding stands in, see section 5) and *no `innerHTML` anywhere* (part H, source test).

## 3. STRIDE and ASVS

| # | Threat (STRIDE) | Control | ASVS 4.0.3 | Evidence |
|---|---|---|---|---|
| S1 | **Spoofing**: guessing or brute-forcing a login | PBKDF2 password + key PIN through the IdP; generic answer; per account+address exponential lockout, per address cap; throttle also on step-up | V2.1.1, V2.2.1, V2.2.2, V2.5.4, V2.8.x | `ConsoleThrottleTest`, `ConsoleSessionTest` |
| S2 | Spoofing: fixation or stolen cookie | New id at login and step-up; 256-bit ids; address+agent binding ends the session; duplicate/malformed cookie ignored | V3.2.1, V3.2.3, V3.3.1 | `ConsoleSessionTest`, red team a3 |
| S3 | Spoofing: another origin's page acting as the user (CSRF) | Strict cookie + token + Origin + Sec-Fetch-Site + JSON | V4.2.2, V13.2.3 | `ConsoleRequestGuardTest`, a2 |
| S4 | Spoofing: DNS rebinding | `Host` must be one of the server's names | V14.5.x | `aForeignHostHeaderIsRefused` |
| T1 | **Tampering**: changing who acts, or smuggling fields | Person from session only; exact-field bodies; SOC body rebuilt; delegation signed per call | V4.1.2, V5.1.5, V13.2.x | `ConsoleAccessTest.theBrowserNeverNamesWho...`, a4 |
| T2 | Tampering: path traversal, request smuggling, odd encodings | Allow-list by exact name; strict raw path; JDK server handles framing; header size cap | V12.3.x, V14.5.x | `ConsoleStaticTest`, a7, a8 |
| T3 | Tampering: forged or injected audit lines | All values sanitised and JSON-escaped, flat map, actor validated | V7.3.1 | `ConsoleAuditTest.whatTheBrowserSendsCannotForgeARecord` |
| R1 | **Repudiation**: a person denies an action | Intent + result for each write, reads of sensitive objects, login/step-up/logout, under the person's id with a hashed session tag; chain is keyed and anchored, verifiable in the page | V7.1.x, V7.2.x | `ConsoleAuditTest` |
| I1 | **Information disclosure**: errors, caching, side channels | Four error shapes, no reasons, `no-store`, uniform login answers; unknown users cost the same hashing | V7.4.1, V8.2.1, V2.2.x | a9, headers tests |
| I2 | Disclosure: records about colleagues through the audit explorer | Analysts get headers only for records outside the console's/SOC API's own types; the SOC API enforces the case/risk/search rules | V4.2.1 | `anAnalystSeesTheConsolesRecordsInFull...` |
| I3 | Disclosure: SSE events | Events carry no ids, names or text; each follow-up request is checked | V13.x | `ConsoleStreamTest` |
| D1 | **Denial of service**: floods, slow clients, large inputs | Per-person and per-address rates; worker pool + semaphore + deadline; 16 KiB bodies; 16 KiB headers; stream cap; login-id cap; throttle table bound | V11.1.x, V13.x | a6, a8, a13, `ConsoleStreamTest` |
| E1 | **Elevation of privilege**: reaching a route above one's role | Role check on every route in the host, module routes included; module files gated by role | V4.1.1, V4.1.3 | `ConsoleAccessTest` |
| E2 | Elevation: a stolen session making a privileged write | Step-up (password + PIN) for verdicts and any module route that asks for it; signing only for the session's own person | V2.8, V4.3.x | `aVerdictNeedsAFreshStepUp...`, a4, a12 |
| E3 | Elevation: the console used to reach the SOC API as someone else | Console cert + one-use 60 s delegation per call, only for analysts; server pinned to `CN=soc-api` | V9.2.x | a10, a11 |

## 4. Red-team findings

Each attack was written as a probe and run against the build (`ConsoleRedTeamTest` and the other classes).

| ID | Attack | Result | Fix and regression test |
|---|---|---|---|
| **F-G1** | A 200 KB request header value | **Succeeded**: the JDK server limits the number of headers but not their size, and answered 200 | Header bytes counted in the pipeline, over 16 KiB is 431. `ConsoleRedTeamTest.a8` (also a 3 MB header: refused) |
| **F-G2** | Open four sessions for one person in the same instant | **Succeeded (a bug, found by the test of the session limit)**: "oldest" was chosen by random id when creation times were equal, so a new session could be the one ended | Sessions carry a creation counter; step-up keeps it. `ConsoleSessionTest.aPersonHasAtMostThreeSessions...` |
| F-G3 | Builder setters kept references to mutable objects (SpotBugs EI_EXPOSE_REP2); an unchecked queue offer (RV_RETURN_VALUE_IGNORED) | Found by the gate | Holders and a loop; no suppression |
| a1 | Stored XSS through a note | Failed: the API only returns `application/json` with `nosniff` and the strict CSP; the text comes back verbatim (escaping on output is part H, with its source test) | `a1_scriptInANoteComesBackAsJsonTextOnly` |
| a2 | One session's CSRF token in another session | Failed (403) | kept |
| a3 | Session id in query or `Authorization` | Failed (401) | kept |
| a4 | Step-up or login naming another person; using ben's secrets in ana's session | Failed (400, 401, still stale) | kept |
| a5 | One login id used by eight threads at once | Failed: exactly one session | kept |
| a6 | Flood of unfinished logins from one address | Bounded at 20 per address (see open issue 1) | kept |
| a7 | Content-Length plus Transfer-Encoding smuggling | Failed: no hidden request ran | kept |
| a8 | Twelve stalled request bodies (more than the 8 workers) | Bounded: a normal request was answered within the 5 s deadline plus margin | kept |
| a9 | 12 malformed requests looking for a stack trace, class name or path in an answer | Failed: only the four short shapes | kept |
| a10 | Asking for people without standing; pointing the channel at a server that is not the SOC API | Failed (empty / 503) | kept |
| a11 | A copied delegation header without the console's certificate | Failed: the TLS handshake is refused | kept |
| a12 | Signing for a lead or an administrator | Failed (no key) | kept |
| a13 | 300 parallel calls from 24 threads | Only 200/429/503, no hang | kept |
| (guard tests) | Path traversal forms (22 of them), foreign Host, cross-site fetch, text/plain and form posts, `OPTIONS` preflight | Failed | `ConsoleStaticTest`, `ConsoleRequestGuardTest` |

### Open issues (not fixed, named)

1. **Login flood on a shared address.** On the loopback every browser shares one source address, so someone who can reach the
   port can fill the 20 pending-login slots of that address for two minutes and make logins on it fail. A real deployment
   puts the console behind the gateway, where the source differs per user. Accepted for the lab; named in the report.
2. **A stalled body holds a worker up to the request deadline (5 s).** Eight workers means a determined local client can slow
   everyone. The anonymous limit (120 per minute per address) and the deadline bound it; a separate short read timeout for
   unauthenticated bodies would need a change in how the JDK server hands out the stream.
3. **Sessions are in memory.** A console restart logs everybody out (safe direction).
4. **The JDK server's header read time** (`sun.net.httpserver.maxReqTime`) is read once, when the server class first loads;
   `ConsoleMain` sets it to 30 s before anything else, but a test harness that loaded the server earlier keeps the default.

## 5. Differences from an enterprise product

| Enterprise web console | This console |
|---|---|
| SSO with OIDC or SAML, a hardware key or passkey in the browser, risk-based step-up | The development IdP; a *simulated* key whose PIN is checked on the server; step-up always asks again |
| Session bound to a device key (DPoP, mTLS-bound tokens) or to the TLS channel | Bound to address and a hash of the User-Agent, because the JDK server exposes no channel binding |
| Verdicts signed in the analyst's browser or key | Signed on the console server with the lab's key, after a fresh step-up, and the page says so (VerdictSigner is the seam) |
| Sessions in a shared store (cluster, survives restarts) | One process, in memory |
| Rate limits in an API gateway, a WAF in front, bot detection | In-process limits only; no WAF |
| Audit shipped to a separate SIEM the console cannot write to | Same keyed chain that the SOC reads, anchored to a file by the integration part |
| CSP violation reports collected; per-response nonces; `Clear-Site-Data` on logout | Strict `script-src 'self'` with Trusted Types, no reporting endpoint, no nonces needed (no inline script) |
| Certificates from a managed PKI with revocation | The lab CA, 30-day certificates |

## 6. Requests to the integration session

1. **Gate blocker in your file:** `SocApiServer.counts` (about line 599) trips SpotBugs `RCN_REDUNDANT_NULLCHECK_OF_NONNULL_VALUE`
   (`Redundant nullcheck of r`). It was in `layer6/integration`'s commit, so `mvn verify spotbugs:check` fails on that class
   until the null check is dropped or the variable restructured. (It is the only finding outside `dev.dwarpal.console`.)
2. **Lab reset (`LabSession`).** The console reads the world only through `LabHandle`. When `LabSession` lands, `ConsoleMain`
   should build it and pass `new LabHandle() { world() {...} runner() {...} }`; `DelegatedSocChannel` already takes
   suppliers for the SOC API address and the delegation issuer. `ConsoleMain` is mine; tell me, or change those three lines.
3. **Modules of parts I and J** are loaded by `ServiceLoader<ConsoleModuleProvider>`: a provider returns
   `List<ConsoleModule>` for a running lab. List it in `META-INF/services/dev.dwarpal.console.ConsoleModuleProvider`.
4. **`ConsoleModule.Role` ordering** is not defined in the interface; the host uses the rule in section 1 ("Roles"). If you
   want a different meaning of `minimum`, say so in `ConsoleModule.java`.
5. **Ports.** The console listens on 8443 by default (`--port`); the SOC API on a free port (`--soc-port`, default 0), since only
   the console calls it. `LabMain` still defaults the SOC API to 8443.
6. **Anchor state for the explorer** is whatever `LabAudit.verify()` says (`anchoredSeq`, `anchorAgrees`); no extra entry
   point is needed.
