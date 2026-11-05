# Layer 5.2 build plan: the SOC platform (SIEM, UEBA, SOAR, XDR-lite)

*Second round of Layer 5, built the same way as the first: one integration session (this one) builds the
shared contracts (part 0) and integrates; three part sessions build D, E and F in parallel on their own
branches.*

## 1. Goal

The first round gave Dwarpal a trustworthy SOC core: a proven, encrypted, anchored audit trail; ten
detection rules; cases, signed verdicts and guarded playbooks; analytics. Layer 5.2 turns that core into the
platform a SOC analyst works in, the way companies use a SIEM, UEBA, SOAR and XDR together:

1. **Collect** events from more than Dwarpal itself: a firewall, endpoint sensors, a cloud application.
2. **Normalise** them into one event format, so one rule or one search works across all sources.
3. **Correlate**: rules analysts write and change without Java (thresholds, sequences across sources,
   "A then B within 10 minutes"), tagged with MITRE ATT&CK techniques.
4. **Find anomalies** (UEBA): per-entity baselines and peer groups, with explainable statistics, no black box.
5. **Prioritise**: one risk score per person, device and address; alerts ranked by that risk and by how
   valuable the asset is.
6. **Respond** (SOAR): playbooks as data, full case management (assignee, notes, deadlines, timeline),
   device isolation for endpoints (XDR).
7. **Report** and **serve the dashboard**: scheduled SOC reports and a read-mostly SOC API that the
   Layer 6 console will draw.

Everything must work **together**, not side by side: the parts share one event format, one evidence space
(the audit chain), one alert sink, one risk view and one asset catalogue, all defined in part 0.

| Part | Builds | Package |
|---|---|---|
| **0. Contracts** (this session, first) | Common event format and its mapping to and from the audit chain; interfaces for search, entity risk, alert ranking and assets; MITRE technique ids; signed endpoint telemetry; a labelled multi-source simulation | `dev.dwarpal.soc` (additions), `dev.dwarpal.crypto` (one message type), test fixture `dev.dwarpal.sim.SimTelemetry` |
| **D. SIEM platform** | Collectors and normalisers (firewall syslog, endpoint telemetry, cloud audit JSON, Dwarpal's own trail); ingestion into the audit chain; an indexed event store and search language; a correlation rule language with MITRE tags | `dev.dwarpal.siem.platform` |
| **E. UEBA and prioritisation** | Baselines and anomaly detectors, peer groups, entity risk (implements `EntityRisk`), risk-based alert ranking (implements `AlertRanker`), MITRE coverage and scheduled reports | `dev.dwarpal.ueba` |
| **F. SOAR, XDR response and SOC API** | Playbooks as data (safe YAML), case management on top of part B's case book, device isolation, connectors (simulated), the SOC API over mutual TLS for the console | `dev.dwarpal.soar`, `dev.dwarpal.socapi` |

```
 firewall (syslog) --+
 endpoint sensors ---+--> D: collectors --> normalise --> SecurityEvent --> audit chain (SECURITY_EVENT)
 cloud app (JSON) ---+        (signed endpoint batches verified)                |
 Dwarpal's own trail ---------------------------------------------------------- +  (A: encrypted store, anchor)
                                                                                 |
                       AuditCursor --> SecurityEvents.fromAudit --> one stream of SecurityEvents
                                          |                    |                       |
                         D: event store + search      D: correlation rules     E: UEBA anomalies
                                          |                    |                       |
                                          |                 alerts ----------> E: entity risk, ranking
                                          |                    |                       |
                                          +----> F: SOC API <--+-- B: case book <-- F: case management
                                                  (console)          |
                                                          F: playbooks as data --> B: playbooks --> signal feed,
                                                                                    revoke, isolate device
```

## 2. Why part 0 comes first, and the key design decision

Three parts written at once would otherwise invent three event formats, three ways to point at evidence,
and three risk scores. Part 0 fixes them.

**One evidence space.** Every collected event is written into Dwarpal's audit chain as a `SECURITY_EVENT`
record before anything else reads it. Consequences:

- Alerts keep citing audit sequence numbers (`Alert.evidence`), so part A's store, anchor and exporters,
  part B's case book and part C's readers work on new sources unchanged.
- Collected events become tamper-evident from the moment they are ingested; a SIEM whose stored logs can be
  edited silently is useless as evidence.
- Every reader still goes through a keyed `AuditCursor`, so no part ever acts on a record it cannot prove.

**Provenance is part of every event**, because not all sources can be trusted equally:

| Provenance | Meaning | Example |
|---|---|---|
| `VERIFIED_AUDIT` | Written by Dwarpal's own code into the keyed chain | access decisions, sessions, PAM, DLP |
| `SIGNED_SENSOR` | Sent by a sensor and verified with its own key | endpoint telemetry batches signed by the device agent key |
| `COLLECTED` | From a source that cannot prove who sent it | firewall syslog over the network, cloud exports |

Rule for every part: **an alert supported only by `COLLECTED` events may watch, rank and open cases, but
must never trigger a destructive action (revoke, deny a person, isolate) on its own.** Anyone on the
network can send a syslog line naming the CEO.

## 3. Part 0: contracts (this session)

**Status: built and tested (2026-11-05).** Everything below exists on `main`; build on it. Threat model v1.3 rows P1 to P9.

| Item | Where | What it gives the parts |
|---|---|---|
| `SecurityEvent` | `soc` | `(id, at, dataset, category, action, outcome, provenance, entities, fields)`; bounded and validated; `Category` (authentication, access, session, privilege, network, process, file, data, cloud, SOC, system); `EventOutcome` (success, failure, challenged, unknown); `Provenance` as above |
| `SecurityEvents` | `soc` | `toAuditFields(event)` and `fromAudit(auditEvent)` (round trip for `SECURITY_EVENT` records), plus the mapping of Dwarpal's own audit types (decisions, sessions, PAM, break-glass, DLP, SOC actions) into events, so one stream covers all sources |
| `EventSource` | `soc` | What a collector offers: `poll(max)` of normalised events, `name()`, counters of refused input |
| `EventSearch` | `soc` | `search(query, from, to, limit)`; the query language is part D's, the API passes it through |
| `EntityRisk`, `RiskView` | `soc` | `view(entity, now)` and `top(n, now)`: a score 0 to 100, a level and the contributions that explain it; implemented by part E, read by part F |
| `AlertRanker`, `RankedAlert`, `Priority` | `soc` | `rank(alert, now)`: P1 to P4, a score, techniques and reasons; implemented by part E, used by F's queue |
| `AssetCatalog`, `Asset`, `InMemoryAssetCatalog` | `soc` | Criticality 1 to 5, owner and tags per person, device or resource; unknown assets are marked unknown, never silently low |
| `Technique`, `Techniques` | `soc` | Validated MITRE ATT&CK ids (for example `T1110.003`) and the catalogue of techniques Dwarpal's rules and scenarios use |
| `SignedMessages.endpointTelemetry` | `crypto` | What a device agent signs for a telemetry batch (device, batch number, time, SHA-256 of the body): bound to one device, single use by batch number |
| `SimTelemetry` (test) | `sim` | Raw firewall syslog lines, signed endpoint batches and cloud JSON for the simulated organisation, labelled, including attacks only visible across sources (section 8) |

## 4. Rules for every part session

As in [Layer 5](layer-5-plan.md) section 4, unchanged: own branch from `main` after part 0
(`layer5-2/part-d-siem-platform`, `layer5-2/part-e-ueba`, `layer5-2/part-f-soar`); own only your
packages and your notes file (`docs/layer-5-2/part-d.md`, `part-e.md`, `part-f.md`); build on the
contracts; fail closed; limits on everything; no secrets in logs; `-Xlint:all -Werror`; abuse cases first;
a red-team pass where each weakness is reproduced as a working probe, fixed and kept as a test, including
attacks on the SOC itself; at least 80% line and branch coverage; SpotBugs and FindSecBugs clean;
`mvn -o verify spotbugs:check` green; zero cost, nothing to buy; no secret-looking literals; push your
branch, do not merge, no pull request. Numbers state their data and are never real-world accuracy.

Two additions for 5.2:

1. **Correlate, don't duplicate.** Use the part 0 interfaces to reach the other parts and write test
   fakes of them; do not build your own version of another part's job.
2. **Explainable analytics only.** UEBA and ranking use statistics an analyst can check by hand (rates,
   baselines, z-scores, Beta and Poisson models, peer comparisons); every score lists what raised it.

## 5. Part D: SIEM platform (`dev.dwarpal.siem.platform`)

- **Collectors and normalisers** for the three simulated sources and Dwarpal's own trail: firewall syslog
  (RFC 5424 and a BSD-style line), endpoint telemetry batches (verify the device agent's signature, batch
  numbers single use and in order, device bound), cloud audit JSON lines. Strict parsing with limits;
  anything unparseable is counted and kept as a `parse-failure` event, never dropped silently.
- **Ingestion**: each normalised event goes into the audit chain (`SECURITY_EVENT`) through the existing
  `AuditLog`; per-source rate limits and quotas so one noisy source cannot starve the others; event time
  versus ingestion time checked (far future or far past refused or flagged).
- **Event store and search** (implements `EventSearch`): bounded in-memory indexes by entity, category
  and time over events read back through `AuditCursor`; a small query language (field comparisons,
  `and`/`or`/`not`, time range, `count by`), parsed without regular expressions on user input, with cost
  limits so no query can exhaust memory or time.
- **Correlation rule language**: rules as data (safe YAML), each with an id, severity, MITRE techniques,
  and one of: a match, a threshold over a window grouped by an entity, a sequence of matches across sources
  within a window (for example a phishing click, then an unusual process on the same device, then a large
  upload by the same person), or an absence (an expected heartbeat missing). Compiled, validated and linted
  like policies; bounded state; raises `Alert`s into the shared `AlertSink`. Express at least four of part
  A's rules in the language, plus the cross-source rules for section 8.

## 6. Part E: UEBA and prioritisation (`dev.dwarpal.ueba`)

- **Baselines and anomalies** over `SecurityEvent`s per entity: event volume per hour (Poisson or
  exponentially weighted mean and variance with a z-score), first-time-seen values (process, destination,
  resource, country) with the rule of succession (M1), time-of-day profiles, data volume (bytes
  downloaded or uploaded). Bounded memory; learning only from events that were not part of an alert, so
  an attacker cannot teach the model slowly.
- **Peer groups**: compare a person with others in the same role or department (the deployer supplies the
  grouping); "unusual for this person and for their peers" is stronger than either alone.
- **Entity risk** (implements `EntityRisk`): alerts, anomalies and watches add contributions with a
  severity weight and a half-life (M5), combined in log-odds and shown as 0 to 100 with every contribution
  listed. Risk can be lowered only by time or by a signed false-positive verdict, never by the entity's own
  activity.
- **Alert ranking** (implements `AlertRanker`): priority from alert severity, entity risk, asset
  criticality (`AssetCatalog`) and provenance (a `COLLECTED`-only alert is ranked, but labelled as such).
- **MITRE coverage and reports**: which techniques the rules and detectors cover; daily SOC report (alerts
  by priority, top risky entities, mean time to verdict, false-positive rate per rule) in text and JSON,
  stating its data source.

## 7. Part F: SOAR, XDR response and SOC API (`dev.dwarpal.soar`, `dev.dwarpal.socapi`)

- **Playbooks as data**: safe-YAML playbook files compiled into part B's `Play` objects and registered with
  `Playbooks.builder().play(rule, play)`; linted (unknown rule ids, steps beyond the guard rails, destructive
  steps on rules whose evidence can be only `COLLECTED`); two-person approval of playbook changes like policy
  bundles.
- **Case management** on top of `CaseBook`: assignee, status, notes (sanitised, bounded), deadlines by
  priority (SLA), a timeline of alerts, verdicts and actions, links between cases about the same entities;
  every change audited.
- **XDR-lite response**: device isolation as a playbook step (deny the device in the signal feed, revoke its
  sessions, and send an isolate command to the simulated sensor, which must acknowledge with a signed
  batch); release only by a signed verdict.
- **Connectors**: an interface for outbound actions (ticket, chat message, email) with simulated
  implementations that write to files; never real network calls; secrets never in playbook files.
- **SOC API**: an HTTPS server with mutual TLS (reuse `edge.TlsContexts`), analysts known by their exact
  certificate subject; read endpoints for the ranked alert queue, cases and their timelines, entity risk
  and timelines, search (passes to `EventSearch`), metrics and reports; write endpoints only for case notes
  and assignments and for signed verdicts (verified by part B's gate); strict JSON limits, rate limits,
  generic errors, every call audited. This is what the Layer 6 console will call.

## 8. Cross-source scenarios in the simulation (`SimTelemetry`)

The simulation adds three sources to the existing organisation (seed 7, 60 users) and new labelled
activity, including attacks that **only correlation can see**:

| Label | What happens | Visible in |
|---|---|---|
| `A6_STOLEN_LAPTOP_AT_HOME` (existing) | The engine allows it (known blind spot); now the laptop also runs an encoded PowerShell, mounts a USB drive and reads many finance files | endpoint, then access decisions |
| `A8_BEACONING` | Malware on a laptop: a new process connects to the same rare address every 60 seconds | endpoint (process) + firewall (flows) |
| `A9_CLOUD_EXFIL` | A person downloads 40 times their usual volume from the cloud app and shares a folder externally | cloud, DLP |
| `L5_BIG_LEGIT_DOWNLOAD` | A legitimate large download at quarter end (false-positive check) | cloud |
| `L6_ADMIN_POWERSHELL` | An administrator runs PowerShell as part of their job (false-positive check) | endpoint |
| `NORMAL` | Everyday processes, flows and cloud activity per person | all |

Success at integration: A6, A8 and A9 become prioritised cases (P1 or P2) through cross-source rules or
UEBA; L5 and L6 do not become P1; the stolen-laptop blind spot of Layer 2 is closed by correlation, not
by changing the engine.

## 9. Integration (this session)

1. Review each branch against this plan and its notes file.
2. Merge D, then E, then F; apply the requests to integration.
3. End to end: the simulation's raw lines go through D's collectors into the chain; D's rules and E's
   detectors raise alerts and anomalies; E ranks them; F's cases and playbooks act; the SOC API serves the
   queue; part A's store, anchor and exporters and part C's analytics still work on the same trail.
4. Cross-part red team: framing an innocent person with forged collected events; flooding a source to
   hide an attack; poisoning a baseline slowly; using the SOC API to read or act beyond an analyst's role.
5. Full gates; threat model, README, SECURITY, project state; Layer 5.2 report.
6. Push only after the project owner approves.

## 10. Practical notes

- Three sessions on an 8 GB laptop: avoid running three full `mvn verify` builds at the same moment.
- Each session reads `docs/project-state.md`, `docs/layer-5-report.md`, this plan and its own section.
- Dates: part 0 on 2026-11-05; D, E and F in parallel; integration by 2026-11-07, leaving time for
  Layer 6 (console and demo) before the submission on 2026-11-10.
