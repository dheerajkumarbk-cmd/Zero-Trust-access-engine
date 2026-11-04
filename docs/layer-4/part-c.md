# Layer 4 part C: SWG and CASB/DLP-lite

*Notes file of the part C session. Read [layer-4-plan.md](../layer-4-plan.md) first; keep this file up to date.*

*Status 2026-11-04: built, red-teamed, `mvn verify spotbugs:check` green (413 tests). Branch `layer4/part-c-swg-casb`.*

## What was built

Two packages, 25 classes, built on the Part 0 contracts (`SessionAuthority`, `EdgeRequest`, `EdgeResult`, `EdgeHttp`, `TlsContexts`) and the shared test world `EdgeFixtures`. Nothing outside `dev.dwarpal.swg`, `dev.dwarpal.casb`, their tests and this file was changed.

### `dev.dwarpal.swg`: the secure web gateway

An HTTP forward proxy that filters by host name. HTTPS `CONNECT` tunnels are relayed untouched: **no TLS interception**, so no certificate has to be installed on any client.

| Class | What it does |
|---|---|
| `WebGateway` | The proxy. `CONNECT host:port` tunnels and plain `GET http://host/...` requests (one request per connection). Needs a known client, decides the destination, then relays. Settings: head/body/response size limits, total time to send a request, tunnel idle time and lifetime, connection limit |
| `WebAccess` | One decision: local filter first, then `SessionAuthority.decide` for the `web:*` resource, and the **stricter of the two wins**. Counters per `BlockReason` |
| `WebFilter` | Parses the destination, checks port, blocklist, look-alike names and raw IPs, and looks up the category |
| `HostName` | The canonical form of a host: lower case, no trailing dot, punycode, IPv4 and IPv6 literals (IPv4-mapped IPv6 becomes IPv4); refuses anything that is not clearly a host. Detects mixed-script look-alikes |
| `DomainList` | Blocklist from a local file, in hosts format and/or domain-list format (`*.x`, `\|\|x^`); subdomains are covered |
| `CategoryMap` | Host to category from a local `domain category` file; the most specific entry wins; conflicting lines are rejected |
| `WebPolicy` | Category to `web:*` resource id, allowed ports, allowed raw IPs, allowed internal addresses |
| `Addresses` | Which addresses are "inside" (loopback, private, link-local, CGNAT, multicast, metadata service, IPv6 unique-local, NAT64 and 6to4 wrappers of those) |
| `HttpHead` | Strict HTTP/1.x request head parser |
| `ListFiles` | Reads list files the way the policy loader reads policy files: regular files only, no symlinks, strict UTF-8, size cap, line cap |
| `IdentityResolver`, `WebIdentity`, `HostResolver`, `Destination`, `WebVerdict`, `BlockReason` | Seams and result types |

Resource mapping used with the shared fixtures: category `news` and `search` map to `web:general` (PUBLIC, permitted by policy P-10); a blocklisted, look-alike or `gambling` host is decided as `web:malicious` (RESTRICTED); everything else is `web:uncategorised` (INTERNAL). The reference policy permits only PUBLIC web, so **uncategorised sites are denied by default** (default-deny); an operator who wants them open maps `uncategorised` to a PUBLIC resource.

### `dev.dwarpal.casb`: SaaS data control

| Class | What it does |
|---|---|
| `DataGuard` | `access(...)` for READ and DOWNLOAD, `upload(...)` for WRITE with content. Every call goes through `SessionAuthority.use` (token, proof of possession, continuous evaluation). Enforces read-only a second time. Inspects uploads and applies the DLP policy for the destination's classification, which comes from the directory, never from the client |
| `Detectors` | Single-pass detectors, no regular expressions: card numbers (Luhn, industry prefix, not one repeated digit), Aadhaar (Verhoeff, first digit 2 to 9), PAN (holder-type letter), IFSC, e-mail, private keys, AWS access keys, GitHub tokens, Slack tokens (the pre-commit hook's patterns). A finding is a type and a position, never the value |
| `Checksums` | Luhn and Verhoeff, plus the check-digit generators used by the tests |
| `Inspection` | Decodes content (UTF-8, or UTF-16 by byte order mark or by the pattern of zero bytes), runs the detectors, builds a redacted copy in the same encoding. Content that is too large or not text is "uninspectable" |
| `DlpPolicy`, `DlpAction` | Per finding type and classification: `BLOCK`, `REDACT` or `AUDIT`; separate setting for uninspectable content (never `REDACT`) |
| `GuardResult` | `ALLOWED`, `REDACTED`, `STEP_UP`, `REFUSED`; findings; `forward(original)` returns the bytes to send on |

Default DLP actions: cards, Aadhaar and PAN: block for PUBLIC and INTERNAL, redact for CONFIDENTIAL, audit for RESTRICTED. Private keys and tokens: block everywhere. E-mail and IFSC: audit. Content that cannot be inspected: block.

## Design decisions and why

| Decision | Why |
|---|---|
| **Stricter of local filter and engine; every valid host is sent to the engine** | A blocklisted host is decided as `web:malicious` and refused whatever the engine says, but the engine's audit trail and deny-lists still see the attempt. A misconfigured permissive policy cannot open a blocklisted host |
| **Host names refused when unclear** (`2130706433`, `0x7f000001`, `127.1`, `%`, `@`, `\`) | A filter that guesses what a name means can be bypassed by a spelling that the resolver reads differently. Last label numeric or hexadecimal: refuse |
| **Connect to the address that was checked** | The gateway resolves once, checks each address, and connects to that address, never to a second lookup (no DNS-rebinding window). Internal addresses are skipped unless the operator allowed them |
| **Strict HTTP head parsing, one request per connection** | Bare CR/LF, folded headers, repeated `Content-Length`, any `Transfer-Encoding`, non-ASCII: refused. Nothing that two parsers might read differently reaches an origin. Costs keep-alive |
| **The Host header is ignored; the decided destination sets it** | The absolute target decides where the request goes |
| **`EdgeHttp.clientOnly` plus hop-by-hop removal on forwarded requests** | Same hygiene as the ZTNA gateway: no `Authorization`, no `Dwarpal-*` / `X-Dwarpal-*` reach an origin |
| **Total time limit for a request, not only a per-read timeout** | A per-read timeout lets one byte every few seconds hold a slot for hours (slow-loris) |
| **Listener and upstream sockets are supplied, not created inside the gateway** | `start(ServerSocket)` takes a bound listener: a plain one on a protected interface, or an `SSLServerSocket` from `TlsContexts` for an HTTPS proxy (tested: TLS 1.3, client certificate required). Upstream sockets come from a `SocketFactory`; they are plain TCP by nature, because they carry the client's own TLS or plain HTTP. SpotBugs/FindSecBugs flag `new ServerSocket` and `new Socket` (`UNENCRYPTED_*`) in a forward proxy; the shared exclude file was not edited, so the code is structured so those decisions are the deployer's |
| **Detectors are validated, hand-written scans** | A pattern alone flags every 16-digit number; Luhn and Verhoeff cut false positives by 90%. No regular expressions means no catastrophic backtracking by construction |
| **Per-type cap on findings, with a `truncated` flag** | A cap on the total lets a flood of e-mail addresses hide a key. Redaction from an incomplete list would leave values behind, so a truncated result under REDACT becomes BLOCK |
| **Invisible characters ignored, other-script digits accepted, one space-like separator between groups** | Zero-width spaces and full-width digits cost an evader nothing; newlines and dots are not separators (columns of IDs and IP addresses would raise false alarms) |
| **Uninspectable content is blocked by default** | What cannot be read cannot be cleared (archives, Office files, binary, over 8 MiB, UTF-16 without ASCII pattern). Fail-closed; an operator may choose AUDIT |
| **Audit before the data goes through; block does not need the audit** | An upload that is allowed with findings is written to the audit trail (`casb.dlp`: types, positions, counts, classification, never values) first, and refused if the trail is down. Refusals are audited with a throttle of 20 per user per minute |
| **`GuardResult.forward(original)`** | `allowed()` is true for REDACTED; a caller who forwards the original instead of the redacted copy would undo the redaction. One method returns the right bytes |
| **An unterminated key marker covers the rest of its line** | Fail-closed: the finding runs to the end of the line (or the END marker if within 64 KiB) so redaction removes it |

## Threats and mitigations (STRIDE)

| # | STRIDE | Threat | Mitigation in code | Test |
|---|---|---|---|---|
| 1 | Spoofing | Request from an unknown client or by someone else's address | `IdentityResolver`; no identity means refusal before the destination is read | `connectionsWithoutAKnownClientAreRefused` |
| 2 | Spoofing | Token from another device used on SaaS data | `SessionAuthority.use` revokes the session as token theft; no content is inspected | `held_aStolenTokenFromAnotherDeviceEndsTheSession...` |
| 3 | Spoofing | Look-alike domain (mixed scripts, punycode) | `HostName.mixedScript` decides it as `web:malicious`; only IDNs not in the category file fall to the uncategorised rule | `r3_namesMixingWritingSystemsAreLookalikes` |
| 4 | Tampering | Host spelled to dodge a list (case, trailing dot, IDN, IPv4-mapped IPv6, numeric IPs) | One canonical form for entries and requests; unclear names refused | `blocklistCoversSubdomains...`, `held_ipv6AndMappedForms...`, `r1_...` |
| 5 | Tampering | `user@host`, backslash, `%00`, `#` tricks in the target | Characters outside host syntax refused; 400 | `held_userInfoAndBackslashTricks...` |
| 6 | Tampering | Request smuggling, header injection, Host header override | Strict head parser; one request per connection; Host rebuilt; client-only and hop-by-hop headers removed | `requestsThatCouldBeReadTwoWaysAreRefused`, `plainHttpIsForwarded...`, `held_theHostHeaderCannotChangeTheDestination` |
| 7 | Tampering | Redaction undone by forwarding the original | `forward(original)` | `r9_aCallerHasOneSafeWayToGetTheBytesToForward` |
| 8 | Repudiation | Sensitive data leaves without a record | Audit record before the data goes through; no audit, no upload; values never recorded | `auditOnlyFindingsPassAndAreRecordedWithoutValues`, `anUploadThatCannotBeAuditedIsRefused` |
| 9 | Information disclosure | The gateway reaches internal services for the user (SSRF, DNS rebinding) | Every resolved address checked; connect to the checked address | `r2_aNameThatResolvesToAnInternalAddress...`, `everyNonPublicRangeIsInternal` |
| 10 | Information disclosure | The reason for a block teaches an attacker | Generic message and reference; reasons only in counters and the audit trail | `blockedTunnelsGetAGenericRefusal` |
| 11 | Information disclosure | Card, Aadhaar, secret in an upload | Validated detectors; DLP policy by classification; UTF-16 and invisible-character evasions covered | `uploadWithAValidCardNumberIsBlocked`, `r6_...`, `r7_...` |
| 12 | Information disclosure | Findings or content in logs | `Finding` holds no value; `Inspection`, `GuardResult` and `EdgeGrant`-style `toString` print no content | `findingsNeverCarryTheValue` |
| 13 | Denial of service | Slow trickle of a request | Total time limit per request head and body; 408 | `r4_aSlowTrickleCannotHoldAConnectionOpen`, `aSlowBodyIsCutOffToo` |
| 14 | Denial of service | Connection flood, huge heads, bodies, responses, endless tunnels | Connection limit with a quick 503; head, header-count, body and response caps; tunnel idle time and lifetime | `tooManyConnections...`, `oversizedHeadsAreRefused`, `aTunnelIsClosedAfterItsLifetime...` |
| 15 | Denial of service | Input that makes the detectors slow | Linear scans, no regular expressions; key-marker search remembered; 8 MiB limit | `r8_...`, `DetectorPerformanceTest` |
| 16 | Denial of service | Findings flood hides a secret, or floods the audit trail | Cap per type with `truncated`; refusal audits throttled | `r5_...`, `refusalAuditsAreThrottled` |
| 17 | Elevation of privilege | Read-only session writes or downloads | Engine obligation plus the guard's own memory of read-only sessions; tunnels refused under read-only | `readOnlySessionCannotDownloadOrUpload`, `readOnlyIsRememberedEvenIf...`, `readOnlyAnswersAllowOnlyPlainReads` |
| 18 | Elevation of privilege | Client states classification or managed device | Not in `EdgeRequest`; classification from the directory | `held_theClientCannotClaimAClassificationOrManagedDevice` |
| 19 | Elevation of privilege | Engine unreachable or throwing, so the gateway fails open | Any exception, null or odd status is a refusal | `aFailingOrSilentAuthorityIsADeny`, `aFailingOrSilentAuthorityIsARefusal` |

## Red-team findings

Each one first reproduced as a working probe (the new test written to assert the secure behaviour was run against the unfixed code and failed), then fixed, then kept as a regression test. "Held" attacks were tried and never worked; they stay as tests too.

| # | Breach (before the fix) | Root cause | Fix | Test |
|---|---|---|---|---|
| R1 | With `uncategorised` permitted, `2130706433`, `0x7f000001`, `127.1`, `0177.0.0.1` passed as host *names* and skipped the raw-IP rule (the system resolver reads them as IPv4) | Name check allowed an all-digit or hex last label | Refuse names whose last label is numeric or `0x` hex; `BAD_HOST` | `SwgRedTeamTest.r1_...` |
| R2 | An allowed name resolving to 127.0.0.1 got a working tunnel to a server on the proxy's own machine (SSRF; same for the cloud metadata address) | `INTERNAL_ADDRESS` was defined but never enforced when connecting | `Addresses.internal` on every resolved address; connect to the checked address; skip internal ones unless allowed | `SwgRedTeamTest.r2_...`, `AddressesAndParsingTest` (35 internal and 24 public addresses) |
| R3 | `apple.example` with a Cyrillic first letter passed as an ordinary name | `LOOKALIKE` was defined but never used | `HostName.mixedScript` per label (Japanese, Korean and Chinese combinations excepted); decided as `web:malicious` | `SwgRedTeamTest.r3_...` |
| R4 | One byte per 250 ms held a connection slot indefinitely although the read timeout was 1 s | Timeout applied to each read, not to the whole request | Watchdog gives the head (and separately the body) `readTimeout` in total; 408 and close | `SwgRedTeamTest.r4_...`, `WebGatewayLimitsTest.aSlowBodyIsCutOffToo` |
| R5 | 10,500 e-mail addresses followed by an AWS key: the key was cut by the overall cap of 10,000 findings and the upload went through as "audit only" | Cap on the total, findings sorted by position | Cap of 1,000 per type, `truncated` flag; truncated plus REDACT becomes BLOCK | `CasbRedTeamTest.r5_...` (two tests) |
| R6 | A card number in UTF-16 text (no byte order mark) passed: the NUL bytes broke every digit run, and the content was still valid "UTF-8" | Decoder assumed UTF-8 | `Inspection.detect`: UTF-16 by BOM or by the zero-byte pattern, other NUL-bearing content is uninspectable; redaction keeps the encoding | `CasbRedTeamTest.r6_...` (two tests) |
| R7 | Card number written with zero-width spaces, no-break spaces, thin spaces, soft hyphens, full-width or Arabic-Indic digits was not found, and a redacted copy kept it | Detector accepted ASCII digits and ASCII separators only | Any Unicode decimal digit; invisible characters ignored; one space-like separator; PAN and IFSC ignore invisibles too | `CasbRedTeamTest.r7_...` (two tests) |
| R8 | 2 MB of key markers took **32 s** to scan (an 8 MiB upload would take about 9 minutes of CPU) | `indexOf` for the END marker restarted at every BEGIN marker: quadratic | Remember the position of the next END marker | `CasbRedTeamTest.r8_...`; the same input at 8 MiB now takes 137 ms |
| R9 | `allowed()` is true for a redacted upload; a caller using the original bytes undoes the redaction | API made the unsafe choice easy | `GuardResult.forward(original)` | `CasbRedTeamTest.r9_...` (design hardening; there is no exploit beyond the caller's mistake) |
| F1 | Found by the full build: under load the 503 for a busy gateway was sometimes lost (connection reset) | The refusal closed the socket with the client's request unread | Short lingering close on the busy path, as on the other refusal paths | `WebGatewayTest.tooManyConnectionsGetServiceUnavailable` (run repeatedly) |

Held: `user@host`, backslash, percent-encoded and `#` tricks in an absolute target (400); IPv4-mapped IPv6 forms of a blocklisted address; a `Host` header naming another site; a stolen token presented from another device (session ended); replayed proofs; 2,000 random 16-digit numbers failing Luhn; a column of numbers and ordinary dates, IP addresses and phone numbers (no false alarms in the tests).

## Tests and results

| Measure | Result |
|---|---|
| New tests | **112** (`swg` 62, `casb` 50). Whole project **413 tests, all passing** (301 before) |
| Coverage | `swg` 98.1% lines, 91.2% branches; `casb` 99.8% lines, 93.8% branches (gate and own target: 80%). Project 97.5% / 90.2% |
| Static analysis | SpotBugs + FindSecBugs: 0 findings. `-Xlint:all -Werror`: clean |
| Web decision latency (filter + engine + audit record, in process) | p50 0.04 ms, p99 0.19 ms (limit 20 ms); 400 parallel decisions on 16 threads all correct |
| Detectors, worst-case inputs of 8 MiB (16 kinds: digits, separators, `@`, key markers, token prefixes, ...) | 38 to 320 ms each; full inspect and redact of an 8 MiB upload with thousands of findings: 140 ms |
| Real sockets | CONNECT tunnel both ways (first bytes behind the CONNECT head kept), plain HTTP with body, 18 malformed or ambiguous requests, 503 at the connection limit, 502 for an unreachable destination, tunnel lifetime and idle cut-off, HTTPS-proxy mode over TLS 1.3 with a client certificate (and a client from another CA gets nothing) |
| Test data | Sample blocklist (hosts and domain-list formats mixed) and category file in `src/test/resources/dev/dwarpal/swg/`; no list is ever downloaded; no key store is committed |

## Known limits (stated, not hidden)

| Limit | Effect |
|---|---|
| Identity of a proxy client is by source address (`IdentityResolver.fixed`) | Fine on a protected network; behind NAT several users share one identity. See request 1 |
| No TLS interception | Only the host name is seen: no URL paths, no content of HTTPS pages; a good site on a shared host is as allowed as the host |
| Whole-script confusables (every letter Cyrillic, none Latin) are not detected | Such a name is not in the category file, so the reference policy denies it as uncategorised; an operator who allows uncategorised sites should keep a list of protected brands |
| HTTP/1.1 without keep-alive, no HTTP/2, no WebSocket upgrade, no chunked request bodies | Slower for many small requests; safer |
| A tunnel is decided once, when it opens | A revocation applies at the next CONNECT; tunnels end by idle time (5 min) or lifetime (30 min) |
| DLP: content in base64, compressed, encrypted or Office/PDF containers is not decoded | Binary containers are uninspectable and blocked by default; text encoded as base64 passes. A determined insider can always encode; this guards against accident and casual evasion |
| DLP: Verhoeff passes a random 12-digit number 1 time in 10, Luhn 1 in 10 | Aadhaar-like false positives exist (phone numbers with country code); context words are not used |
| Full-width or accented letters in a PAN or IFSC are not matched | Only ASCII letters |
| Findings from DLP go to the audit trail but not to the Layer 2 scorers | See request 4 |

## Requests to integration

Nothing in shared files was changed. Needed or suggested:

1. **Authenticated identity for the web gateway.** `IdentityResolver` is the seam. The tested alternatives: HTTPS-proxy mode with `TlsContexts` and `peerPrincipal(session)` mapped to a subject (listener is passed to `WebGateway.start`), or `Proxy-Authorization` carrying a session token and proof, checked with `SessionAuthority.use`. `SessionAuthority.decide` has no session, so a web decision is a single decision by an identity the gateway vouches for; Part B's agent or Part A's API should provide the proof. Please decide which, and wire it.
2. **Resource ids and categories.** The SWG expects `web:general`, `web:uncategorised` and `web:malicious` in the directory (as in `EdgeFixtures`), and the operator's category file maps categories to them through `WebPolicy`. With the reference policy only PUBLIC web is permitted, so uncategorised sites are denied. Confirm that is the intended default for the demo, or add a policy (for example a step-up for INTERNAL web).
3. **SpotBugs.** `UNENCRYPTED_SERVER_SOCKET` and `UNENCRYPTED_SOCKET` would fire on any forward proxy that creates its own sockets. Part C avoids them by taking the listener and a `SocketFactory` from the caller. If integration creates the plain listener in a main class, it will meet the same two findings there; a narrow exclusion on that class in `spotbugs-exclude.xml` (with the reason: a proxy's client leg is chosen by the deployer, its upstream leg carries the client's own TLS) is the honest way to handle it.
4. **DLP findings as risk evidence.** The plan says findings are recorded as risk evidence in the audit trail: they are (`casb.dlp` records: reference, resource, classification, action, types, positions, counts, never values). Feeding them back into the Layer 2 scorers (for example a bad mark on a user who tries to upload secrets) needs an engine-side change and belongs with Layer 5; the SIEM can already alert on the record type.
5. **Documents.** `docs/threat-model.md` (new rows from the STRIDE table above, residual risks from the limits table), `README.md` (packages `swg`, `casb`), `docs/project-state.md` (package map, test count 413, the red-team findings R1 to R9) and the Layer 4 report.
6. **Blocklists are operator-supplied.** `DomainList.load(path)` and `CategoryMap.load(path)` read local files only. The gateway takes `Supplier<DomainList>` and `Supplier<CategoryMap>`, so integration can add a reload (for example on file change) that swaps whole lists at once. Free public lists may be downloaded by the user and placed there; nothing downloads them.
7. **No new dependencies and no `pom.xml` change.** The tests that use `DevPki` need `keytool` from the JDK (as `TlsContextsTest` does); they take about 15 seconds together.
