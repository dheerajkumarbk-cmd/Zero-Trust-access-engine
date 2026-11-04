# Layer 4 report: enforcement points and the SASE edge

*Dwarpal, Layer 4. Built in four parts: shared contracts (part 0), then the engine API (A), the ZTNA
gateway (B) and the web gateway with SaaS data control (C) in parallel, then integrated and
red-teamed together. The plan is [layer-4-plan.md](layer-4-plan.md); each part's own notes are in
[layer-4/](layer-4/).*

## 1. What Layer 4 adds

Layers 1 to 3 decide. Layer 4 makes the decisions bite: real network traffic is stopped or let
through by **policy enforcement points** (PEPs, NIST SP 800-207), and those PEPs never decide anything
themselves. They ask the engine, over one hardened API, and enforce the answer.

```
 client agent --HTTPS--> ZTNA gateway (part B) ---+
                                                  |
 browser ---proxy------> web gateway  (part C) ---+--mutual TLS 1.3--> engine API (part A)
                                                  |                     |
 SaaS upload ----------> data guard   (part C) ---+                     +--> Policy Administrator (sessions)
                                                                        +--> PAM (privileged access)
 SOC, admin console -------------------mutual TLS 1.3-------------------+--> engine (Layers 1 and 2)
```

These are the three building blocks of SASE (Secure Access Service Edge), the industry's name for
one policy model enforced at the edge for private apps, the web and SaaS:

| SASE block | Dwarpal package | What it protects |
|---|---|---|
| ZTNA (Zero Trust Network Access) | `gateway`, `agent`, `devidp` | Internal applications (the wiki, the vault): no VPN, no network access, only one application per session |
| SWG (Secure Web Gateway) | `swg` | Users' web browsing: block lists, categories, look-alike domains, raw IPs, internal addresses |
| CASB / DLP (Cloud Access Security Broker, Data Loss Prevention) | `casb` | SaaS data: reads and downloads through sessions; uploads inspected for cards, Aadhaar, PAN, keys and tokens |

## 2. How the parts fit

| Concern | Design |
|---|---|
| One contract | Part 0 defined `SessionAuthority` (open, use, decide), the wire format, the header protocol and the TLS settings before any part started. All three parts were built on it in parallel and merged without a single conflict |
| Transport | Mutual TLS 1.3, AEAD suites only, certificates from Dwarpal's own CA (EC P-384). Each PEP pins the API's exact certificate subject, so another component cannot answer in the API's place |
| Who may ask what | Each API caller is configured with its exact certificate subject, a role (PEP, admin console, SOC) and, for a PEP, the resources it fronts. The web gateway may ask about `web:*` only; it cannot open or spend a wiki session |
| Sessions | A session opens only on fresh, identity-provider-signed MFA bound to the client's session key, and each MFA proof opens one session. Every later request is signed with that key, used once and decided again |
| Single decisions | Only for web browsing, which has no session. Private applications and SaaS data are always reached through a session |
| Failure | Every PEP turns any failure (network, timeout, bad answer, exception) into a deny. The API turns any internal exception into a 403 and never answers without its audit record |
| Slow clients | Every server (API, ZTNA gateway, web gateway) has a deadline per request covering headers and body, so a few slow connections cannot hold every slot |

## 3. Security testing

Every part ran its own red-team pass, and the integration ran a cross-part pass with all components
connected through the real API. Each weakness was first reproduced as a working attack, then fixed,
then kept as a regression test.

| Pass | Findings | Examples |
|---|---|---|
| Part A (API) | 5 | A compromised component posing as the API; slow-loris starving the server; an answer for another request accepted; `CN=GATEWAY` taken for `gateway` |
| Part B (ZTNA) | 9 | Login without MFA; `/wiki/Admin` written in capitals skipping the admin check; `X-HTTP-Method-Override` turning a read into a delete; internal address leaked by redirects; slow logins holding every slot |
| Part C (SWG, CASB) | 10 | `2130706433` as a host name; a name resolving to the proxy's own machine (SSRF); Cyrillic look-alike domains; card numbers hidden by UTF-16 or zero-width spaces; a quadratic scan taking 32 s |
| Cross-part | 6 | A stolen gateway certificate getting GRANTED for the wiki by single decision (no session, no MFA); opening sessions without MFA straight at the API; replaying a captured login through another gateway; the web gateway spending wiki sessions; revocation leaving admin rights running |

All findings, with root causes, fixes and the tests that keep them fixed, are in the
[threat model](threat-model.md) (v1.0 section).

## 4. Results

| Measure | Result |
|---|---|
| Tests | 531, all passing (267 after Layer 3; 301 after part 0) |
| End to end | Agent to gateway to API to PA over mutual TLS; browser tunnels through the web gateway; SaaS uploads through the data guard; SOC revocation; API outage (deny) |
| Coverage, Layer 4 packages | 85% to 99% of lines and branches per package (gate: 80%) |
| Static analysis | SpotBugs + FindSecBugs: 0 findings; `-Xlint:all -Werror` clean |
| Latency (p99, laptop) | Session use over the API about 7 to 12 ms; added by the ZTNA gateway about 7 to 28 ms under load (target 20 ms, test limit 50 ms); web decision under 3 ms |
| Cost | Nothing: JDK only (`jdk.httpserver`, `java.net.http`, `keytool`); no new dependency |

## 5. Limits (stated, not hidden)

| Limit | Effect |
|---|---|
| Hardware is simulated | Security keys (WebAuthn), the device agent and the CA are software, by the zero-cost rule; the protocols are the real ones |
| The web gateway knows its users by source address | Fine on a protected network; behind NAT several users share one identity. HTTPS-proxy mode with the device certificate is built and tested, to be wired in the demo |
| No TLS interception | The web gateway sees host names, not page contents (deliberate: no certificate on every laptop) |
| DLP is "lite" | Base64, compressed and Office/PDF content is not decoded; binary containers are blocked by default |
| One machine, in memory | Sessions and counters reset on restart; no high availability |
| JDK HTTP server | Fine for this scale; no HTTP/2; JVM-wide slow-request limits must be set on the command line by the launcher |
