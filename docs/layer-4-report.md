# Layer 4 report: enforcement points and the SASE edge

*Status 2026-11-04: Layer 4 complete (part 0 and parts A, B, C), integrated, red-teamed across parts,
reviewed and approved. Built on Layers 1 to 3.*

## 1. Where Layer 4 sits in the whole project

Dwarpal has **six layers**. Each one is usable on its own and is the base for the next.

| Layer | Name | In one or two sentences | Status |
|---|---|---|---|
| 1 | Core decision engine | Decides ALLOW / read-only / STEP_UP / DENY for one request from signed evidence, policy and Bayesian risk, and explains why. Protected by signatures, an HMAC audit chain and two-person policy changes. | Done |
| 2 | Behavioural risk scorers | Ten detectors (new network or device, impossible travel, odd hour, reputation, brute force, spray, attack surge, bad IPs) that turn a login into evidence for Layer 1, learning each user's habits without being poisoned. | Done |
| 3 | Policy Administrator | Turns the engine's "yes" into short, client-bound sessions re-checked on every request (part A), and replaces standing admin rights with just-in-time, approved, time-boxed elevation and break-glass (part B). | Done |
| **4** | **Enforcement and SASE edge** | **The enforcement points that stand in front of real traffic: an engine API over mutual TLS (part A), a ZTNA gateway with client agent and identity provider (part B), and a web gateway with SaaS data control (part C). They never decide; they ask Layers 1 to 3 and enforce the answer.** | **Done (this report)** |
| 5 | SOC loop and analytics | Ships the audit trail to a SIEM, raises alerts, lets analysts feed verdicts back (decaying signals, M5), replays recorded traffic against a proposed policy (What-If, M8), and calibrates the assumed probabilities. | Next |
| 6 | Console, demo and deployment | The web front end for users, admins and analysts, and the demo launcher. | When you ask for the demo |

Cross-cutting, after the college submission: hybrid post-quantum signatures (Ed25519 + ML-DSA).

## 2. What Layer 4 is about

A decision point on its own protects nothing: something has to stand in the traffic and say no.
NIST SP 800-207 calls that the **Policy Enforcement Point (PEP)**. The industry's SASE model (Secure
Access Service Edge) groups the enforcement points a company needs into three blocks, and Layer 4
builds all three on one engine:

| SASE block | What it protects | Dwarpal |
|---|---|---|
| **ZTNA** (Zero Trust Network Access) | Internal applications, without a VPN: the user reaches one application per session, never the network | `gateway`, `agent`, `devidp` |
| **SWG** (Secure Web Gateway) | Web browsing: known-bad sites, risky categories, look-alike domains | `swg` |
| **CASB / DLP** (Cloud Access Security Broker, Data Loss Prevention) | Company data in SaaS applications: who may read, download or upload, and what may leave | `casb` |

All three reach the engine through one **engine API** (`api`):

```
 client agent --HTTPS--> ZTNA gateway (B) ---+
 browser -----proxy----> web gateway  (C) ---+--mutual TLS 1.3--> engine API (A) --> Policy Administrator (sessions)
 SaaS upload ----------> data guard   (C) ---+                                   --> PAM (privileged access)
 SOC, admin console --------------------mutual TLS 1.3-------^                   --> engine (Layers 1 and 2)
```

## 3. How it was built

Layer 4 was the first layer built by several sessions at once, which needs one shared foundation so
the parts cannot drift apart.

| Step | What happened |
|---|---|
| Part 0 (contracts) | `SessionAuthority` (open, use, decide), `EdgeRequest` / `EdgeResult`, the header protocol (`EdgeHttp`), the strict wire format, TLS 1.3 settings and a strict JSON reader, plus a test world shared by all parts. Pushed to `main` first |
| Parts A, B, C | Built in parallel by three sessions on their own branches, each owning only its packages and a notes file; anything needed in shared code was written down as a "request to integration" |
| Review | Each branch reviewed against the plan, built and probed independently; one new weakness found and fixed in part B (slow logins), one unstable test fixed in part A |
| Integration | Merged A, B, C (no conflicts), applied the requests, connected every PEP to the engine through the real API, then a cross-part red-team pass |

## 4. Part A: the engine API

### 4.1 Who may call, and what

The API is a JDK `HttpsServer` (no framework). Every caller presents a certificate from Dwarpal's own
CA over **mutual TLS 1.3**, and is recognised by the exact certificate subject.

| Caller | Role | May call | Resources |
|---|---|---|---|
| ZTNA gateway | PEP | open, use, decide | `wiki`, `vault` |
| Web gateway | PEP | open, use, decide | `web:*` |
| SaaS data guard | PEP | open, use, decide | `drive` |
| SOC | SOC | revoke | none |
| Admin console | ADMIN_CONSOLE | revoke, PAM requests, approvals, break-glass, reviews | none |

### 4.2 Every request, step by step (the first failure answers)

| Step | Check | Answer |
|---|---|---|
| 0 | TLS 1.3 handshake, certificate from the Dwarpal CA, not expired | connection refused |
| 1 | Certificate subject is exactly a configured caller (`CN=GATEWAY` is not `CN=gateway`) | 403 |
| 2 | Caller within its rate limit | 429 |
| 3 | Path is exactly an endpoint (no prefixes, no query, no encoding tricks) | 404 |
| 4 | Caller's role may use the endpoint; then the method | 403, 405 |
| 5 | Fewer than 16 requests in flight | 503 |
| 6 | JSON, at most 64 KiB, strict schema (no unknown or duplicate members) | 415, 413, 400 |
| 7 | The resource is within the caller's scope | 403 |
| 8 | The engine, PA or PAM answers; any exception is a deny | 200 or 403 |
| 9 | The call is audited; an allowed answer that cannot be audited is not sent | 403 |

Every request also has a **5-second deadline** covering handshake, headers, body and work, so slow
clients cannot hold the workers. Error bodies are one of seven fixed strings; the reason goes only
to the audit trail.

### 4.3 The PEP's side: `RemoteSessionAuthority`

Each enforcement point talks to the API through this client. It trusts the Dwarpal CA **and** only
the API's exact certificate subject, checked during the handshake (every component certificate is
valid for `localhost`, so trusting the CA alone would let a compromised component answer in the
API's place). One deadline covers the whole exchange, answers are capped at 64 KiB, and the answer
must belong to the question (same request id, a status that fits the call). **Any failure is a deny.**

## 5. Part B: the ZTNA gateway, client agent and identity provider

### 5.1 Logging in

1. The **client agent** creates a fresh Ed25519 session key for this application.
2. It logs in at the **development identity provider**: password (PBKDF2-HMAC-SHA256, 600,000
   iterations, salted) plus a **software security key** (simulated WebAuthn) answering a single-use
   challenge. The security key is scoped to Dwarpal's relying-party id, so a phishing site gets
   nothing usable, and its counter must rise, so a cloned key is caught.
3. The identity provider signs an `authentication/v3` proof **bound to the session key's thumbprint**.
4. The **device agent** signs a binding of the session key to the device.
5. The gateway checks the MFA proof, then asks the PA to open a session; the PA checks it again and
   uses it once.

### 5.2 Every request, step by step

| Step | What the gateway does |
|---|---|
| 1 | One deadline (30 s) for the whole request, body included; at most 256 requests in flight |
| 2 | The path must have exactly one reading: no `..`, `%2F`, `%252e`, `;`, `//` or backslash |
| 3 | The route gives the resource (`/wiki` is `wiki`); method and route give the action (GET is READ, PUT is WRITE, `/wiki/download` is DOWNLOAD, `/wiki/admin` is ADMIN, case-insensitive) |
| 4 | Method-override headers (`X-HTTP-Method-Override`, `_method`) are refused |
| 5 | Subject and device come from the session the gateway opened, the network from the socket address: never from client headers |
| 6 | The client's signature over this request (session key, fresh request id) goes to the PA with the token; the engine decides again |
| 7 | Only GRANTED or GRANTED_LIMITED is forwarded; STEP_UP becomes 401 with a challenge, the agent re-authenticates and retries once |
| 8 | Every `Dwarpal-*` header from the client is removed; the gateway adds the subject, the session and its own secret for the app; redirects are rewritten so the app's internal address never leaks |

The **sample app** (wiki and vault) listens on loopback only and accepts only requests carrying the
gateway's secret, compared in constant time.

## 6. Part C: the web gateway and the SaaS data guard

### 6.1 Web gateway (SWG)

A forward proxy for plain HTTP and HTTPS tunnels, deciding by host name **without decrypting TLS**
(no certificate has to be installed on any laptop).

| Step | Check |
|---|---|
| 1 | The client must be known (no anonymous proxy users) |
| 2 | Strict HTTP head: no folded headers, no repeated `Content-Length`, no `Transfer-Encoding`, one request per connection (nothing that two parsers could read differently) |
| 3 | The host has **one canonical form**: lower case, no trailing dot, punycode, IP literals normalised; anything unclear (`2130706433`, `0x7f000001`, `127.1`, `@`, `\`) is refused |
| 4 | Port allowed; raw IPs refused unless allowed; block lists (hosts and domain-list formats, subdomains covered); categories from a local file; mixed-script look-alikes decided as malicious |
| 5 | The engine decides the web resource (`web:general`, `web:uncategorised`, `web:malicious`); **the stricter of the local filter and the engine wins** |
| 6 | The name is resolved once, every address is checked against internal ranges (loopback, private, link-local, cloud metadata, IPv6 and NAT64 forms), and the gateway connects to the address it checked |
| 7 | Time limits on the whole head and body, tunnel idle time (5 min) and lifetime (30 min), at most 256 connections |

### 6.2 SaaS data guard (CASB / DLP)

Reads, downloads and uploads of SaaS data go through **sessions** (token, proof of possession,
continuous evaluation), and read-only sessions stay read-only. Uploads are inspected:

| Data | Detector (validated, not just a pattern) | Default action |
|---|---|---|
| Card numbers | Luhn checksum, card-network prefix, not one repeated digit | Block (PUBLIC, INTERNAL), redact (CONFIDENTIAL), audit (RESTRICTED) |
| Aadhaar | Verhoeff checksum, first digit 2 to 9 | Same as cards |
| PAN | Holder-type letter in the fourth place | Same as cards |
| Private keys, AWS keys, GitHub and Slack tokens | The pre-commit hook's patterns | Block everywhere |
| E-mail, IFSC | Structure | Audit |
| Content that cannot be read (archives, Office, binary, over 8 MiB) | | Block |

Evasions handled: UTF-16 text, zero-width and other invisible characters, full-width and
Arabic-Indic digits, one space-like separator between groups. A finding is a type and a position,
**never the value**, so the audit trail cannot leak what it protects.

## 7. Integration: what changed when the parts met

| Change | Why |
|---|---|
| **The PA requires fresh, verified, key-bound MFA to open a session, and uses each MFA proof once** | Before, only the ZTNA gateway checked MFA at login; a stolen gateway certificate could open sessions straight at the API, and a captured login could be replayed through a second gateway |
| **Each PEP has a resource scope** | The web gateway's certificate could open and spend wiki sessions |
| **Single decisions only for web resources** | A gateway certificate could ask `/v1/decisions` about the wiki and get GRANTED with no session, no MFA and no proof of possession |
| **Revoking a person also ends their admin elevation** | Incident response: a compromised admin must lose both at once |
| Certificate pinning and exact name comparison moved into `TlsContexts` | Every component client should pin, not only the API's |

End-to-end tests now run the deployed shape: agent to gateway to API to PA over mutual TLS; browser
tunnels through the web gateway; SaaS uploads through the data guard; SOC revocation; and the API
going away (the gateway denies).

## 8. The maths of Layer 4

**Slow clients and slots.** A server with S slots, where one address may start r requests per
minute and each request may live at most D minutes, lets one address hold at most

```math
H = r \cdot D \quad \text{slots at once}.
```

For the ZTNA gateway, r = 30 logins per minute and D = 30 s give H = 15 of S = 256. Before the
per-request deadline D was unbounded, and one address filled every slot in S / r = 256 / 30, about
8.5 minutes, and kept them forever.

**Checksums.** Luhn (cards) and Verhoeff (Aadhaar) each let a random number pass with probability
1/10, so a validated detector raises 10 times fewer false alarms than a pattern alone. Luhn catches
every single-digit error and most swaps of neighbouring digits; Verhoeff catches **all** single-digit
errors and **all** neighbouring swaps (verified by `verhoeffCatchesEverySingleDigitErrorAndSwap`).

**Password cost.** Each guess costs k = 600,000 HMAC-SHA256 operations. With t about 1 µs per HMAC
on a laptop core, one guess takes about

```math
T_{\text{guess}} = k \cdot t \approx 0.6\ \text{s},
```

so a million guesses at a stolen user file take about a week of one core. Online guessing is cut off
much sooner: lockout counts failures per subject and address, and every failure is reported, signed,
to the brute-force and spray detectors of Layer 2.

**Scanning cost.** Every detector is one linear pass with no regular expressions, so the time grows
as O(n) with the upload size: the worst of 16 adversarial 8 MiB inputs takes 320 ms. One quadratic
step found by the red team (key markers without an end) had taken 32 s for 2 MB.

**Findings cap.** At most 1,000 findings per type are kept. A cap on the total let 10,500 harmless
e-mail addresses push an AWS key out of the report; per type, one kind cannot hide another, and a
truncated report under REDACT becomes BLOCK (redacting from an incomplete list would leave values
behind).

**Latency budget** (p99 on the laptop, coverage instrumentation on):

| Path | Measured | Target |
|---|---|---|
| Session use over the API (mutual TLS, JSON both ways, PA, engine, two audit records) | 7 to 13 ms | 20 ms |
| Added by the ZTNA gateway | 7 to 28 ms | 20 ms (test limit 50 ms) |
| Web decision (filter, engine, audit) | under 3 ms | 20 ms |

## 9. Red-team passes on Layer 4

Every breach below was first reproduced as a working attack, then fixed, and is now a permanent
regression test (details in [threat-model.md](threat-model.md), v1.0).

| Pass | Findings | Breaches (before the fix) |
|---|---|---|
| Part A | 5 | A compromised component posing as the API and receiving tokens; four slow connections starving the server; the client hung by a slow or huge answer; an answer for another request accepted; `CN=GATEWAY` accepted as `gateway` |
| Part B | 9 | Login without MFA; logins for resources the gateway does not front; `/wiki/Admin` in capitals skipping the admin check; `X-HTTP-Method-Override: DELETE` under a READ grant; redirects leaking the internal address; one user filling the session table; a captured login replayed 5 times; one address taking every login challenge; slow logins holding every slot |
| Part C | 10 | Numeric spellings of 127.0.0.1 as host names; a name resolving to the proxy's own machine (SSRF); Cyrillic look-alike domains; one byte per 250 ms holding a connection; a findings flood hiding a key; cards in UTF-16; cards hidden by invisible characters; a quadratic scan; redaction undone by forwarding the original; a lost 503 under load |
| Cross-part | 6 | Slow logins (X1, = part B's); a single decision standing in for a session (X2); sessions opened without MFA straight at the API (X3); a captured login replayed through another gateway (X4); the web gateway spending wiki sessions (X5); revocation leaving admin rights running (X6) |

Attacks that were tried and held without changes include: no certificate, another CA's certificate,
an expired one; 14 path tricks against the API; duplicate keys, 5,000-deep nesting, invalid UTF-8;
480 fuzzed bodies over every endpoint; 80 parallel requests against one slot; a stolen token used
from another client; a READ proof spent on a write; injected `X-Dwarpal-Subject`; `user@host`,
backslash and `#` tricks; IPv4-mapped IPv6 forms of blocked addresses; a `Host` header naming another
site; 2,000 random 16-digit numbers (no false alarm).

## 10. Tests and results

| Measure | Result |
|---|---|
| New tests in Layer 4 | 264 (part 0: 34; A: 37; B: 64; C: 112; integration: 17) |
| Whole project | **531 tests, all passing** (267 after Layer 3) |
| Coverage, Layer 4 packages (lines / branches) | `api` 97.1 / 94.9; `gateway` 94.6 / 85.5; `agent` 93.5 / 85.7; `devidp` 98.7 / 89.1; `swg` 98.0 / 91.2; `casb` 99.8 / 93.8; `edge` 97.8 / 91.5; `wire` 95.7 / 86.5 (gate: 80) |
| Static analysis | SpotBugs + FindSecBugs: 0 findings, no new suppressions |
| Compiler | `-Xlint:all -Werror`: clean |
| Dependencies | None added: JDK only (`jdk.httpserver`, `java.net.http`, `keytool` for the development CA) |
| Cost | Nothing to buy: security keys, device agent and CA are simulated in software |

## 11. How this compares with enterprise products

| Aspect | Typical enterprise (Zscaler, Netskope, Prisma Access, Cloudflare One) | Dwarpal Layer 4 |
|---|---|---|
| One policy model | Often separate modules with their own consoles for ZTNA, SWG and CASB | One policy language and one engine decide for private apps, the web and SaaS; the PEPs only enforce |
| Trust in connectors and gateways | Connectors authenticate to the vendor cloud and are trusted for what they forward | Each PEP has its own certificate, pinned both ways, limited to the resources it fronts, and cannot state roles, classification or device status |
| MFA at the edge | The identity provider's token is trusted | The PA verifies the identity provider's signature, the MFA's age and its binding to the session key, and uses each proof once |
| Request binding | Bearer cookies or tokens | Every request signed with a key the client holds; single-use request ids |
| Web filtering | TLS decryption and large commercial category feeds | Host names only, from local lists the organisation controls; look-alike and SSRF checks built in |
| DLP | Hundreds of trained classifiers, fingerprinting, OCR | A small set of validated detectors with linear-time scans and redaction |
| Failure behaviour | Configurable fail-open or fail-closed per connector | Always fail-closed: any failure at any PEP is a deny |
| Where they are ahead | Global points of presence, TLS inspection, huge threat feeds, browser isolation, mature consoles | Not built; the demo console is Layer 6 |

## 12. Remaining risks (stated, scheduled)

| Risk | Plan |
|---|---|
| The web gateway knows its users by source address | HTTPS-proxy mode with the device certificate as identity (built and tested) wired in the demo launcher |
| No TLS interception: page contents are not seen | Accepted, by design |
| DLP does not decode base64, compressed or Office/PDF content | Binary containers blocked by default; accepted otherwise |
| DLP findings reach the audit trail but not the behavioural scorers | Layer 5 |
| The JDK server's own slow-request limits are JVM-wide | Every server has its own deadline in code; the launcher also sets them on the command line |
| A compromised ZTNA gateway holds the app's shared secret | Mutual TLS from gateway to app (later) |
| Sessions and counters live in memory; one machine, no high availability | Accepted for this scale |

## 13. Files

| Path | Content |
|---|---|
| `src/main/java/dev/dwarpal/wire/`, `edge/` | Part 0: strict JSON, contracts, header protocol, wire format, TLS settings and pinning, `LocalSessionAuthority` (1,859 lines) |
| `src/main/java/dev/dwarpal/api/` | Part A: `ApiServer`, `RemoteSessionAuthority`, `Caller`, `CallerRole`, `ApiSettings`, `ApiBodies` (1,261 lines) |
| `src/main/java/dev/dwarpal/gateway/`, `agent/`, `devidp/` | Part B: `ZtnaGateway`, `LoginGuard`, `RouteTable`, `HeaderPolicy`, `SampleApp`, `ClientAgent`, `DeviceAgent`, `DevIdentityProvider`, `SoftwareAuthenticator`, ... (3,450 lines) |
| `src/main/java/dev/dwarpal/swg/`, `casb/` | Part C: `WebGateway`, `WebAccess`, `WebFilter`, `HostName`, `DomainList`, `CategoryMap`, `Addresses`, `DataGuard`, `Detectors`, `Inspection`, `DlpPolicy`, ... (3,199 lines) |
| `session/PolicyAdministrator` | MFA required at open, login MFA proofs single-use |
| `src/test/java/dev/dwarpal/integration/` | `E2eWorld`, `EndToEndTest`, `CrossPartRedTeamTest` |
| Docs | [layer-4-plan.md](layer-4-plan.md), part notes in [layer-4/](layer-4/), threat model v1.0, this report, README, SECURITY, project state |
