# Layer 5.2 part F: SOAR, XDR response and SOC API

*Notes file of the part F session (branch `layer5-2/part-f-soar`, packages `dev.dwarpal.soar` and `dev.dwarpal.socapi`). Read [layer-5-2-plan.md](../layer-5-2-plan.md) (sections 1 to 4 and 7) first; keep this file up to date.*

## What was built

```
 detection (A, D) --alert--> CaseManager --(CaseBook, part B)--> cases
                               |  ranks each alert (AlertRanker, part E); SLA deadline, assignee, notes,
                               |  timeline, links
 analyst --mutual TLS--> SocApiServer --signed verdict--> Soar --(playbook version, mode)--> Playbooks (part B)
                               |                            |        guard rails: rate limits, two analysts,
                               |                            |        denies end, undo on false positive
                               |                            +--> DeviceIsolation --command--> sensor
                               |                            |        <--signed ack batch (DEVICE_AGENT key)--
                               |                            +--> Connectors (ticket, chat, email: files)
                               +--> EventSearch (D), EntityRisk (E), ReportSource (E)
 two administrators --signed bundle--> PlaybookInstaller --PlaybookCompiler (safe YAML, linter)--> Soar.activate
```

### `dev.dwarpal.soar`

| Class | What it does |
|---|---|
| `PlaybookCompiler` | Reads playbook files (safe YAML: `SafeConstructor`, no aliases, no duplicate keys, 64 KiB, nesting limit, strict schema, messages name places never content) and compiles each rule's steps into part B's `Play`. Steps: `revoke`, `deny`, `watch` (a likelihood ratio, turned into log-odds), `isolate` (becomes a device deny for the deployment's longest deny plus a device revoke, and the sensor-side extra), `notify` (a connector name and a fixed template). The linter refuses unknown or duplicate rules, steps beyond the guard rails (deny longer than `ResponseSettings.maxDeny`, watch above x1000 or half-life outside 1 minute to 90 days, more than 16 steps, a target the step cannot act on), destructive steps for rules whose evidence can be only collected, denying or isolating the person a rule names when that person is the one under attack, a destructive or notifying default play, unknown connectors or templates, more than 4 notifications, and anything that looks like a secret. Warnings (a known rule without a playbook, a repeated step) block in strict mode (deployment) |
| `RuleCatalogue` | The rules playbooks may name and what the linter must know about each: evidence (`VERIFIED`, `MIXED`, `COLLECTED_ONLY`) and whether the person named is the victim. `reference()` holds part A's 14 rules; part D adds its own with `with(...)` |
| `PlaybookSet` | A compiled file: plays per rule, the fallback play, extras (isolate, notifications), version and SHA-256. `watchOnly()` removes revokes, denies and isolation and caps watches at x10 with a half-life of at most one day |
| `PlaybookBundle`, `PlaybookInstaller` | Two-person approval like policy bundles: signatures of at least two distinct administrators (`POLICY_SIGNER` keys; one person with two keys counts once; the two-person rule cannot be configured lower) over `dwarpal/playbook-bundle/v1`, sequence, SHA-256 of the exact text and time; at most 7 days old; rising sequence (rollback refused); strict compile; audited before it takes effect; rejections audited, throttled |
| `reference-playbooks.yaml` (resource) | Part B's reference plays written as data, plus isolation of the device for `honeytoken-touched` |
| `CaseManager` | Case management on top of `CaseBook`, and the `AlertSink` detection writes to: each alert goes into the case book, is ranked, and the case gets the most urgent priority of its alerts, a first-response deadline per priority (SLA), assignee, sanitised bounded notes (audited as SHA-256 and length; the text stays out of the trail), a bounded timeline and links to cases about the same entities. Visibility and assignment rules (see design decisions) |
| `CaseSettings`, `CaseView`, `Analyst` | Service levels and limits; what an analyst sees of a case; analysts with role `ANALYST` or `LEAD` |
| `Soar` | Verdicts in, guard-railed action out: runs part B's `Playbooks` built from the installed playbook set, in full or watch-only mode, adds isolation, notifications and the timeline; keeps each case with the playbook version that first acted on it; red-team fixes F-R1 and F-R2 |
| `DeviceIsolation`, `IsolationCommand`, `SensorAck`, `Sensor`, `SimulatedSensor` | XDR-lite: after the play's device deny and revoke have run, an isolate command with a random single-use id goes to the sensor; the device counts as isolated only when its sensor answers with a batch signed by that device's own `DEVICE_AGENT` key (endpoint-telemetry message domain, body quoting the command byte for byte, batch number rising, at most 5 minutes old). Overdue acknowledgements are shown; undelivered commands can be sent again; release only after a signed false-positive verdict lifted the case's actions; a device isolated by two cases is released when the last is lifted. The simulated sensor signs real acknowledgements with keys made at run time |
| `Connector`, `FileConnector` | Outbound actions (ticket, chat, email) as an interface; the simulated connector appends one JSON line per notification to `<dir>/<name>.jsonl`, never opens a connection, is rate limited per minute and stops at 10 MB; notifications carry ids and fixed text only |

### `dev.dwarpal.socapi`

| Class | What it does |
|---|---|
| `SocApiServer` | The SOC API for the Layer 6 console: JDK `HttpsServer`, mutual TLS 1.3 via `edge.TlsContexts`, analysts by the exact RFC 2253 subject of their certificate. Reads: `GET /v1/health`, `/v1/queue`, `/v1/cases`, `/v1/cases/{id}`, `/v1/cases/{id}/timeline`, `/v1/risk/top`, `/v1/risk/{kind}/{id}`, `/v1/isolations`, `/v1/metrics`, `/v1/reports/{name}` (leads), `POST /v1/search`. Writes: `POST /v1/cases/{id}/notes`, `/v1/cases/{id}/assignment`, `/v1/verdicts` (signed by the calling analyst's own key, then part B's gate). Steps in order: caller 403, per-analyst rate limits (all calls, writes, searches) 429, exact route with plain-identifier parameters 404, method 405, capacity 503, JSON content type, 16 KiB, strict schema 415/413/400, visibility 404, work. Fixed generic error bodies; every call audited (`SOCAPI_CALL`, `SOCAPI_REFUSED`, refusals throttled and counted); an answer carrying data is not sent without its audit record; per-request deadline (Layer 4 finding A2) |
| `SocApiSettings`, `SocCaller`, `ReportSource`, `SocJson` | Limits; the analyst behind a certificate subject; where reports come from (part E); strict request readers (`{"v":1,...}` with exactly the listed members) and response writers |

## Design decisions and why

1. **Build on part B, do not replace it.** `Play.Step` is sealed in part B, so isolation is compiled into two ordinary steps (device deny, device revoke) that part B's guard rails govern (rate limits, two analysts, denies always end, undo on false positive); only the sensor command is part F's. The file is authoritative: every part A rule the file does not name gets the file's fallback play, not part B's built-in one.
2. **Collected evidence never acts destructively, checked twice.** At load time the linter refuses destructive steps for `COLLECTED_ONLY` rules; at run time a case is decided in watch-only mode when the ranked alert is not `actionable` (unknown counts as not actionable, and a ranker failure gives P2 and not actionable). A true-positive verdict on a collected-only alert in a case already decided in full mode is refused, so a forged line that joins a real case cannot ride on it.
3. **One playbook version per case.** A playbook install changes new cases only. Each case keeps the version and mode that first acted on it, so the second analyst confirms, and a false positive undoes, exactly what was done. Old versions stay alive while a case still uses them.
4. **The sensor's word, not the delivery, counts.** A delivered command proves nothing; only a batch signed by that device's own agent key, quoting the random command id, counts. Without it the isolation shows as overdue while the engine-side deny holds.
5. **Release only by a signed verdict.** `DeviceIsolation.isolate` and `release` are package-private; only `Soar` calls them, isolate after `APPLIED`, release after `UNDONE` (part B's signed, single-use, two-analysts-where-two-confirmed false positive). The engine-side deny still ends on its own after at most 7 days (part B's rule); the sensor stays isolated until the verdict.
6. **Nobody works their own case, and analysts are not each other's audience.** An analyst named in a case cannot see, take, annotate or decide it; cases, risk and events about any analyst are for leads only (never about the lead herself); an analyst sees unassigned cases, her own, and cases waiting for a second analyst; only leads assign to others or take a case from someone. "Not visible" is answered exactly like "does not exist" (404).
7. **Notes are refused, not cut, when too long**, and are sanitised (no line breaks, controls or bidi); the trail records their hash and length so the note cannot be quietly changed, without copying free text (which may hold personal data) into the chain.
8. **Ranking fails safe.** A failed or inconsistent ranker answer becomes P2, not actionable, with the reason listed; never low.
9. **Secrets stay out of playbooks** by construction (no field takes a URL, address or credential: connectors are configured by the deployment) and by the linter (secret words followed by `:` or `=`, private-key markers, long mixed key-like runs).
10. **Numbers in the API** are rounded to one decimal and written without exponents; times are ISO-8601 instants.

## Threats and mitigations (STRIDE)

| # | STRIDE | Threat | Mitigation in code | Test |
|---|---|---|---|---|
| F1 | Spoofing | Someone calls the SOC API as an analyst | Mutual TLS 1.3 with the Dwarpal CA only; exact RFC 2253 subject, case-sensitive; unknown subject 403 | `SocApiTest.onlyConfiguredAnalystsByExactCertificateSubject` |
| F2 | Spoofing | An analyst submits a colleague's captured verdict | `analystId` must be the caller; part B's gate checks the key and single use | `SocApiTest.verdictsMustBeSignedByTheCallingAnalyst` |
| F3 | Spoofing | A forged acknowledgement makes a device look isolated (or released) | Device-bound `DEVICE_AGENT` key, telemetry domain, exact body with random command id, rising batch, 5-minute freshness | `SoarTest.forgedReplayedOrStaleAcknowledgementsAreRefused`, `aReleaseCannotBeAcknowledgedWithAnOldBatchNumber` |
| F4 | Tampering | A playbook file removes the guard rails | Strict linter; two administrators; rollback refused; any edit voids approvals | `PlaybookCompilerTest`, `PlaybookInstallerTest`, `SoarRedTeamTest.aPlaybookFileWithoutGuardRailsDoesNotLoad` |
| F5 | Tampering | YAML attacks (object construction, alias bombs, duplicate keys, oversized files) | `SafeConstructor`, aliases 0, duplicates refused, size and depth limits, strict schema | `PlaybookCompilerTest.unsafeYamlIsRefusedWithoutEchoingIt` |
| F6 | Repudiation | An analyst denies a note, assignment or API call | Audited before the change (`CASE_NOTE` with SHA-256, `CASE_ASSIGNED`, `SOCAPI_CALL`); no audit, no change; no audit, no data | `CaseManagerTest.noAuditNoChange`, `SocApiTest.everyCallIsAuditedAndDataIsNotSentWithoutIt` |
| F7 | Information disclosure | An analyst reads cases, risk or events about herself or colleagues | Visibility rules, 404 for not visible, links and search counts filtered | `CaseManagerTest.casesAboutAnyAnalystAreForLeadsOnly`, `SocApiRedTeamTest` |
| F8 | Information disclosure | Errors or logs leak detail or secrets | Fixed error bodies; reasons only in the audit trail; YAML errors name places only; secrets refused in playbook files | `SocApiTest.bodiesAreStrict`, `PlaybookCompilerTest.secretsInPlaybookFilesAreRefused` |
| F9 | Denial of service | Slow or flooding clients, huge bodies, expensive searches | Bounded threads, queue, in-flight limit, 16 KiB bodies, strict JSON limits, per-analyst rate limits for calls, writes and searches, search window at most 31 days, per-request deadline | `SocApiTest.callsAreRateLimitedPerAnalyst`, `aSlowClientIsCutOffAtTheDeadline` |
| F10 | Denial of service | The SOC is turned against innocent people (forged syslog, own case, one analyst against an executive) | Provenance rule twice, watch caps and budget on collected evidence, two analysts for protected people and their devices, own-case rule | `SoarRedTeamTest` |
| F11 | Elevation of privilege | An analyst acts beyond her role (assigns others, acts directly without a verdict) | Assignment rules; no endpoint revokes, denies or isolates; everything destructive goes through a signed verdict and part B's guard rails | `SocApiTest.assignmentsFollowTheRoles`, `SocApiRedTeamTest.noEndpointActsWithoutAVerdict` |
| F12 | Denial of service | Connectors flood or fill the disk; a down connector blocks the response | Rate limit per minute, 10 MB per file, failures recorded and never fatal, no network | `ConnectorTest`, `SoarTest.aFailingConnectorNeverStopsTheResponse` |

## Red-team findings

*(each reproduced as a working probe first, then fixed, then kept as a regression test)*

| # | STRIDE | Breach (before the fix) | Root cause | Fix | Test |
|---|---|---|---|---|---|
| F-R1 | Denial of service (against the CEO) | A forged syslog line naming the CEO, confirmed by one analyst who believed it, put a x1000 watch on her (watch-only mode kept the play's watches as written: the probe measured log-odds 6.9 instead of at most 2.3); a few forged lines a day could keep her locked out without any destructive step | Watch-only mode removed destructive steps but trusted the watches' weights, and nothing limited repetition | On collected evidence a watch is at most x10 with a half-life of at most one day, and each entity gets at most one such watch a day (refused, audited, otherwise); one a day never sums past x100 | `SoarRedTeamTest.forgedSyslogLinesCannotLockTheCeoOutThroughWatches` |
| F-R2 | Elevation of privilege | One analyst confirmed a verified alert that named only the CEO's laptop, and the laptop was denied, its sessions ended and it was isolated (status `APPLIED` with one verdict) | Part B's two-person rule looks only at the people an alert names | Devices owned by a protected person (asset catalogue) or of criticality 5 need two analysts before part B sees the verdict; the same analyst twice, a different alert or a disagreeing second analyst do not count; the wait lapses after part B's second-analyst window | `SoarRedTeamTest.oneAnalystCannotIsolateTheCeosLaptopThroughAnAlertNamingOnlyTheDevice`, `aSecondAnalystWhoDisagreesCancelsTheProtectedDeviceWait` |
| F-R3 | Information disclosure | A search for "subject = ben" by ana hid ben's events but answered `"matched":4,"truncated":true,"hidden":3`, so she could count a colleague's activity | Hidden events were left out of the list but not out of the numbers | When anything is hidden, `matched` is what is shown, `hidden` is gone from the answer, `truncated` refers to the shown list; the audit record keeps the hidden count | `SocApiRedTeamTest.searchDoesNotRevealHowManyEventsAboutColleaguesMatched` |
| F-R4 | Information disclosure | Reading alice's case showed `"links":["case-1"]`, the id of a case about ben that shares an address; the timeline said the same | Links were computed for the whole SOC, not for the reader | Links and LINKED timeline entries are filtered by the reader's visibility | `SocApiRedTeamTest.caseLinksDoNotRevealCasesTheReaderCannotSee` |

Probes that held from the start and stay as regression tests: a forged syslog line never isolates the CEO's laptop; an analyst cannot act on, read or annotate her own case (in the SOAR and through the API); an analyst cannot read a colleague's case through any endpoint, and "not yours" looks like "does not exist"; a playbook file without guard rails does not load whoever signed it; no endpoint revokes, denies, isolates or releases without a verdict; a collected alert cannot ride on a case decided in full mode.

## Tests and results

*(filled in after the full gate; see below)*

## Requests to integration

1. **Signed message for playbook bundles** (`crypto`): move `PlaybookBundle.DOMAIN` / `signedMessage` into `SignedMessages.playbookBundle(sequence, sha256, signedAt)` so all signed domains live in one place; decide whether approvers keep `POLICY_SIGNER` keys (as now: the same administrators who approve policies) or get their own purpose.
2. **Part D's rules in the catalogue**: part D supplies `RuleCatalogue.Rule` entries for its rules (evidence `VERIFIED`, `MIXED` or `COLLECTED_ONLY`; whether the person named is the victim), so its playbooks are linted for provenance. Part D's own playbook entries can then be added to the reference file.
3. **Wiring** (launcher): `CaseManager` is the `AlertSink` for parts A and D (it wraps the `CaseBook`); part E's `AlertRanker` into `CaseManager`; part D's `EventSearch`, part E's `EntityRisk` and a `ReportSource` for part E's daily report into `SocApiServer`; the deployment's `AssetCatalog` into `Soar.Builder.assets` (needed for F-R2); a `PlaybookInstaller` with `Soar::activate`; analyst certificates and `SocCaller`s.
4. **Part B (`response`)**, optional improvements found here: (a) a builder option to share the destructive-action rate limiters between `Playbooks` instances: each installed playbook version (and its watch-only twin) has its own hourly counters, so an install restarts them (installs need two administrators, so this is not an analyst bypass, but the limits should be global); (b) consider protected devices in part B's two-person rule itself (part F does it before part B for now, F-R2); (c) `Playbooks.Result` could say whether a second analyst confirmed.
5. **Signed isolation commands**: a key purpose for the SOC responder and `SignedMessages.isolationCommand(...)`, so a real sensor can verify that an isolate or release command comes from Dwarpal; the simulated sensor trusts its channel.
6. **Layer 6 console**: note text, alert summaries and reasons are sanitised for control and bidi characters only; the console must HTML-escape everything it shows.
7. **Persistence** (as for part B): case management, isolation state, the protected-device waits and the collected-watch budget live in memory; a restart forgets them (the engine-side denies still end on their own; a sensor stays isolated until released).
8. **Threat model v1.4**: rows F1 to F12 and F-R1 to F-R4 above.
