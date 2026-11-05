# Layer 5.2 part D: SIEM platform

*Notes file of the part D session (branch `layer5-2/part-d-siem-platform`, package `dev.dwarpal.siem.platform`). Read [layer-5-2-plan.md](../layer-5-2-plan.md) (sections 1 to 4 and 5) first; keep this file up to date.*

## What was built

```
 firewall syslog --> FirewallCollector --+                        (keyed AuditCursor)
 signed batches ---> EndpointCollector --+--> Ingestor --> audit chain --+--> EventStore (EventSearch, Query)
 cloud JSON -------> CloudCollector -----+   (SECURITY_EVENT,            |
 Dwarpal's own trail (decisions, PAM, DLP) -- already in the chain ------+--> CorrelationEngine (RuleBook)
                                                                                   |
                                                                         Alerts --> AlertSink (case book)
```

| Class | What it does |
|---|---|
| `FirewallCollector` | RFC 5424 and BSD syslog flow lines, parsed by hand: priority 0 to 191, version 1, time required, `key=value` message with each key once, `action`, `src`, `dst` required, ports and byte counts checked, addresses checked. `network.flow` events, `COLLECTED`, IP entities plus the device behind an internal address (DHCP leases). BSD lines have no year or zone: read as UTC in the year of arrival, moved back a year when more than a day ahead |
| `EndpointCollector` | Signed endpoint batches: size limits, then the device agent's signature (`DEVICE_AGENT` key bound to the named device, at most 2 h old, not from the future), then the batch number (single use, strictly increasing per device; a jump is a `telemetry.gap` event). Each line must name the batch's own device and a time inside the batch's hour. `SIGNED_SENSOR` events. `lastBatches(cursor)` rebuilds the used numbers from the trail after a restart |
| `CloudCollector` | Cloud audit export, one flat JSON object per line (Dwarpal's bounded `JsonReader`): `time`, `user`, `op` required, `op` becomes the action, `bytes` a whole number, nested values and duplicate keys refused. `COLLECTED`; subject, IP, device (lease) and resource entities |
| `CollectorBase` | What all three share: a bounded queue (10,000), unique ids (`<prefix>-<run>-<n>`), counters, and the rule that refused input is never dropped silently: a `parse.failure` / `telemetry.refused` event with the reason, the length and a SHA-256 prefix, never the raw text (which may hold secrets); queue overflow is counted and reported by one `collector.overflow` event |
| `Ingestor` | Writes every normalised event into the audit chain as `SECURITY_EVENT` under `collector:<dataset>`. One dataset per source, provenance no higher than the source was registered with (`VERIFIED_AUDIT` never), event time at most 5 min ahead and 7 days behind (refused), more than 1 h behind flagged `ingest.late` with the lag; token bucket per source, sources taken in turn; refusals summarised into the chain once per pump; if the audit write fails the events are held and nothing more is read |
| `Query` | The search language, also the `where` of every rule: comparisons (`=`, `!=`, `<`, `<=`, `>`, `>=`, `~` contains, `in (...)`), `and`/`or`/`not`, parentheses, `*`, `at` for event time, entity kinds as fields, `f.<name>` for fields named like built-ins, `| count by a, b`. Hand-written tokenizer and parser (no regular expression on user input); enum values checked when parsed, so a typo is an error, not a query that silently matches nothing; limits on tokens (256), depth (16), terms (128), list values (32), value length (256) |
| `EventStore` | Implements `EventSearch`. Reads the trail only through a keyed `AuditCursor`, keeps at most `capacity` events (oldest record evicted first), indexes by event time, entity, category and dataset; a search starts from the smallest index its required comparisons allow, walks newest first and stops after 200,000 events, saying so. `counts()` answers `count by` (at most 1,000 groups). Broken chain, evicted range and cost limit are reported in every answer |
| `RuleBook` | Correlation rules as safe YAML (SnakeYAML `SafeConstructor`, no aliases, no duplicate keys, 128 KiB, unknown keys are errors, parser messages never passed on). Each rule: id, title, severity, 1 to 8 MITRE techniques from `Techniques`, and one of `match`, `threshold` (count, distinct count or sum, by 1 to 3 fields, within 1 min to 24 h), `sequence` (2 to 8 steps with `min` events each, by key, within a window, across sources) or `absence` (a key that matched, then nothing for 5 min to 7 days). Lint ERRORs block the file: unknown technique, duplicate id, out-of-range values, and rules that can never fire (a dataset nobody writes, two different required values for one field, a provenance the dataset never carries). WARNINGs: broad rules, CRITICAL rules fed only by collected evidence |
| `CorrelationEngine` | Runs the rule book over the chain (keyed cursor; stops for good at a break), raises `Alert`s into the shared `AlertSink`. Event-time windows with events arriving out of order; the clock is the newest event time, and events dated more than 5 min after their record are ignored; events older than clock minus 2 h lateness minus the window are too late. Bounded state (10,000 keys per rule, 2,000 events per key; full counts and sums merge instead of forgetting), one window of quiet per key after firing, 50 alerts per rule per hour then one `correlation-flood`, one `correlation-state-full` per rule per hour, refused alerts kept (1,000) and retried. An alert backed only by `COLLECTED` events starts with "COLLECTED evidence only, not for destructive action"; `recent()` gives each alert with its techniques and `actionable` |
| `default-rules.yaml` | 18 rules: part A's rules in the language (7 rules covering 6 of A's; A's deny-storm-ip is split into count and spray) (`cr-break-glass-used`, `cr-honeytoken-touched`, `cr-deny-storm-subject`, `cr-deny-storm-ip`, `cr-spray-ip`, `cr-mfa-fatigue`, `cr-pam-refused`), endpoint (`encoded-powershell`), A6 (`stolen-laptop-collection`, `stolen-laptop-access`), A8 (`beacon-regular-destination`, `beacon-from-document-process`), A9 (`cloud-download-volume`, `cloud-bulk-download-then-external-share`) and the SOC's own sources (`telemetry-refused`, `telemetry-gap`, `collector-flooded`, `sensor-heartbeat-missing`) |

## Design decisions and why

1. **One language for search and rules.** A rule's `where` is a search query, so an analyst tries a rule out
   in the search box first and gets exactly what the rule will match.
2. **Parsed by hand, enums checked at parse time.** No regular expression ever runs on analyst or rule input
   (no ReDoS); `category = netwrk` is an error, not a rule that silently never fires.
3. **Missing fields never compare.** `x != y` is false when the event has no `x`; otherwise every rule written
   with `!=` would fire on every event of other sources.
4. **Event time, not arrival order.** Endpoint batches arrive up to an hour after their events and sources
   interleave; per-key windows are kept sorted and checked around each new event. The engine's clock is the
   newest event time, protected against future-dated events (ingestion refuses more than 5 min ahead; the
   engine ignores events more than 5 min ahead of their record).
5. **Full state merges, never forgets** (counts and sums). Dropping the oldest event would let an attacker hide
   a volume behind many small events (rD5); merging can only over-count. A distinct count keeps every distinct
   value. Rules that limits could never let fire are refused when the engine is built (rD4).
6. **Refused input is evidence.** Parse failures, refused batches, overflow and ingestion refusals all reach
   the chain as events (counts, hash, reason; never raw text), and rules alert on them.
7. **Sources are weighed, not trusted.** A collector's events carry its provenance; the ingestor refuses a
   source claiming more than it has; alerts say when they rest only on `COLLECTED` evidence.
8. **Alerts cite audit sequence numbers and are deterministic.** Ids are `al-<rule>-<newest evidence record>`,
   so a replayed trail gives the same ids (deduplication across restarts), and `raisedAt` is the newest
   evidence's record time.
9. **Rules use their own ids** (`cr-` for part A's rules), so both engines can run side by side; integration
   chooses (request 3).

## Threats and mitigations (STRIDE)

| # | STRIDE | Threat | Mitigation in code | Test |
|---|---|---|---|---|
| D1 | Spoofing | A forged, edited, moved or replayed endpoint batch is taken as the device's own telemetry | Signature by the device's own `DEVICE_AGENT` key over device, number, time and body hash; age and future checks; numbers single use and in order; lines must name the batch's device | `forgedEditedMovedOrMisusedBatchesAreRefused`, `batchNumbersAreSingleUseInOrderAndGapsAreReported`, `badLinesInASignedBatchAreRefusedOneByOne` |
| D2 | Spoofing / elevation | Syslog or a cloud export poses as signed telemetry or as Dwarpal's own record | Source registered with a maximum provenance; dataset fixed per source; `VERIFIED_AUDIT` never | `aSourceCannotWriteAnotherDatasetOrClaimMoreTrustThanItHas` |
| D3 | Elevation (framing) | Forged syslog naming the CEO's laptop leads to a destructive playbook | Alerts on `COLLECTED` evidence alone say so and are `actionable = false` | `forgedSyslogNamingTheCeoLaptopNeverYieldsAnActionableAlert`, `collectedOnlyAlertsSaySoAndAreNotActionable` |
| D4 | Tampering | Malformed input guessed into an event (duplicate keys, bad numbers, nested JSON, smuggled fields) | Strict hand parsers; each key once; refused, never guessed | `firewallRefusesWhatItCannotParse...`, `cloudLinesAreStrict`, `rD1`, `rD2` |
| D5 | Repudiation / info loss | Input dropped silently (unparseable, refused, overflow) | Every refusal is an event in the chain; overflow counted and reported | `aFloodFillsOnlyTheCollectorsOwnQueueAndTheLossIsReported`, `futureAndAncientEventsAreRefusedAndLateOnesFlagged` |
| D6 | Info disclosure | Raw lines (which can carry secrets) copied into failure events or errors | Failure events keep reason, length and a SHA-256 prefix only; query and YAML errors quote nothing | `firewallRefusesWhatItCannotParseAndKeepsATraceWithoutTheText`, `unsafeYamlIsRefusedWithoutEchoingIt` |
| D7 | Denial of service (SOC) | One noisy source starves the others | Token bucket per source, sources in turn, bounded collector queues | `aFloodingSourceCannotStarveTheOthers` |
| D8 | Tampering / evasion | Backdated events placed into closed windows; future-dated events closing everyone's windows | Ingestion refuses > 5 min ahead and > 7 days behind, flags > 1 h late; the engine ignores events ahead of their record and counts too-late ones | `futureAndAncientEventsAreRefusedAndLateOnesFlagged`, `aFutureDatedEventCannotMoveTheClock...`, `backdatedEventsAreTooLateToCount` |
| D9 | Tampering | Collected events edited after ingestion; forged records in the store | Written into the keyed chain first; store and engine read only through the keyed cursor and stop at a break | `aRecordForgedWithAnotherKeyAndEverythingAfterItIsNeverSearchable`, `theEngineStopsForGoodAtABreakInTheChain` |
| D10 | Denial of service | A query exhausts memory or time | Parse limits; examined-events limit; groups limit; bounded store with eviction reported | `malformedAndOversizedQueriesAreErrorsNeverEmptyResults`, `parsingIsLinearEvenOnHostileInput`, `aBroadQueryOverAHugeStoreStopsAtItsCostLimitAndSaysSo`, `theStoreIsBoundedAndSaysWhatItNoLongerHas` |
| D11 | Denial of service / evasion | Correlation state flooded with invented keys, or an alert flood | Key limit per rule (live keys kept, refusals alerted), hourly cap with one flood alert, merge on full | `floodingAStateWithInventedKeys...`, `anAlertFloodIsCappedPerRuleAndReportedOnce`, `rD5`, `rD6` |
| D12 | Elevation | A rule file builds objects (CVE-2022-1471), expands aliases, hides a second key | `SafeConstructor`, no aliases, no duplicate keys, size limit, strict schema | `unsafeYamlIsRefusedWithoutEchoingIt` |
| D13 | Evasion | A rule that can never fire (typo in a dataset, impossible combination, beyond state limits) gives false comfort | Lint ERRORs; engine refuses unreachable rules; `silentRules()` lists rules that matched nothing | `rulesThatCanNeverFireAreRefused`, `rD4`, `noRuleFiresOnEverydayActivity` |
| D14 | Repudiation | Alerts lost when the case book refuses or throws | Kept (1,000) and retried in order; beyond that counted as lost | `alertsTheSinkRefusesAreKeptAndOfferedAgainInOrder` |
| D15 | Evasion | A sensor silenced to hide activity | `telemetry.gap` on skipped numbers; `absence` rule on heartbeats, also when the key comes back | `batchNumbersAreSingleUse...`, `absenceFiresOnce...`, `rD3` |

## Red-team findings

Each was first written as a working probe in `RedTeamTest` and run against the code as it was: all seven
probes failed (the attack worked), with the output kept by the session; then the code was fixed and the probe
kept as a regression test.

| # | STRIDE | Breach (before the fix) | Root cause | Fix | Test |
|---|---|---|---|---|---|
| rD1 | Tampering | A syslog line with `verdict=deny host=fw-trusted` overwrote the collector's own `verdict` and `host` fields | Message pairs were merged into the event's fields after the collector's own | Reserved field names (`host`, `app`, `verdict`, `batch`, `user`, `ingest.*`, ...) refuse the line | `rD1_aSyslogMessageCannotOverwriteTheCollectorsOwnFields` |
| rD2 | Tampering | A line in a signed batch set `"batch":"999"`, replacing the real batch number, and could pre-set `ingest.late` | As rD1, in the endpoint collector; the ingestor did not check its own flags | Reserved names refused per line; the ingestor refuses any event that already carries `ingest.*` | `rD2_anEndpointLineCannotForgeTheBatchNumberOrTheIngestionFlags` |
| rD3 | Evasion | A sensor silent for 4 h 40 min and then back was never reported, because nothing else moved the clock in between | Absence was only checked when the clock passed the deadline | A key that comes back after more than the window raises the absence alert ("nothing for N min, then it came back") | `rD3_aSensorThatWentQuietAndCameBackIsStillReported` |
| rD4 | Evasion | A rule with `count: 5000` loaded fine but could never fire: a key keeps at most 2,000 events | Rule limits and engine limits were checked in different places | Counts and sums now merge (rD5); a distinct count or sequence step beyond the state limit is refused when the engine is built | `rD4_aRuleTheEngineCouldNeverFireIsRefusedWhenTheEngineIsBuilt` |
| rD5 | Evasion | 3,000 downloads of 400 kB (1.2 GB in 50 min) did not trigger the 1 GB volume rule | A full key dropped its oldest events, so the sum never passed 800 MB | Full counts and sums merge the two oldest entries (weights and amounts kept); distinct counts drop only repeated values | `rD5_manySmallEventsCannotHideAVolumeOverTheStateLimit` |
| rD6 | Denial of service (SOC) | 20,000 flows from one device to one address under a distinct-count rule took over 5 s (the probe timed out; rD5's probe took 122 s): the engine fell behind | Every new event re-scanned every window: quadratic in the events per key | One two-pointer pass per event, with running weight, sum and distinct counts | `rD6_oneBusyKeyCannotMakeTheEngineQuadratic` |
| rD7 | Spoofing (replay) | After a collector restart, a batch captured before it was accepted again | Used batch numbers lived only in memory | `EndpointCollector.lastBatches(cursor)` rebuilds them from the verified trail (every event carries its batch number); a broken or oversized trail stops the collector from starting | `rD7_aBatchCapturedBeforeARestartIsRefusedAfterIt` |

Found while writing the abuse tests (before the red-team pass, fixed at once): an `in (...)` list of repeated
values passed the 32-value limit (only distinct values were counted; the token limit still bounded it).

Probes that did not find a breach, kept as guards: framing the CEO's laptop with forged syslog (watch-only
alert), flooding a collector (overflow event and `collector-flooded` alert), flooding correlation state with
invented keys (refused and alerted, the live key kept), future-dated and backdated events, broad queries over
a large store, a forged record in the chain.

## Tests and results

`mvn -o verify spotbugs:check`, JDK 25.0.5 (Temurin), offline, 2026-11-05: **BUILD SUCCESS**, 822 tests in the
project, 0 failures; SpotBugs with FindSecBugs: 0 (six findings of the first run fixed: a constructor that could
throw in the abstract `CollectorBase`, and counters SpotBugs could not prove were locked).

| Test class | Tests | What it shows |
|---|---|---|
| `CollectorTest` | 9 | Abuse first: 19 kinds of bad syslog lines, 10 kinds of forged or misused batches, bad lines inside a signed batch, 13 kinds of bad cloud lines, overflow; then RFC 5424 / BSD parsing, leases, gaps, restart |
| `QueryTest` | 3 | 29 malformed or oversized queries are errors; hostile input stays linear; the meaning of every operator and field |
| `IngestorTest` | 6 | Wrong dataset and provenance refused; future, ancient and late events; fair share under a flood; audit write failure holds events in order; refusal summaries |
| `EventStoreTest` | 6 | Forged record never searchable; bad arguments are answers with a problem; cost limit; eviction reported; indexes, ranges, `count by` |
| `RuleBookTest` | 6 | Unsafe YAML (object gadget, billion laughs, duplicate keys, size); rules that can never fire; MITRE tags; bounds; the shipped rules load clean |
| `CorrelationEngineTest` | 12 | Future-dated and backdated events; key flood; alert flood; refused and throwing sinks; chain break; collected-only label; out-of-order thresholds; distinct and sum; cross-source sequences; absence |
| `RedTeamTest` | 8 | rD1 to rD7 and the CEO-framing guard |
| `SimulationTest` | 6 | End to end on the simulated organisation (below) |
| **Part D** | **56** | |

Coverage (JaCoCo) of `dev.dwarpal.siem.platform`: **96.6% lines, 86.0% branches**.

End to end on the simulated organisation (seed 7, 60 people, 8 days; firewall, endpoint and cloud telemetry
through the collectors into the same audit chain as the engine's own decisions; the generator and the rules are
written by the same team, so this is consistency with the threat model, **not real-world accuracy**):

| Scenario | Result |
|---|---|
| A6 stolen laptop at home | `stolen-laptop-collection` for all 60 A6 laptops; `stolen-laptop-access` (CRITICAL, signed + verified evidence, actionable) for every A6 laptop the engine allowed: the Layer 2 blind spot is closed by correlation, the engine unchanged |
| A8 beaconing | `beacon-regular-destination` (firewall only, labelled collected-only) and `beacon-from-document-process` (endpoint + firewall, actionable) for exactly the two beaconing laptops, destination the C2 address |
| A9 cloud exfiltration | `cloud-download-volume` and `cloud-bulk-download-then-external-share` for exactly the exfiltrating person, labelled collected-only |
| L5 quarter-end download | no alert (about 600 MB, no outside share) |
| L6 administrator PowerShell | no `encoded-powershell` alert |
| Noise | the 4 malformed lines kept as `parse.failure` events; nothing else refused |
| Part A's rules in the language | `cr-deny-storm-ip` + `cr-spray-ip` name exactly the addresses part A's `deny-storm-ip` names on the same trail; `cr-mfa-fatigue` covers everyone part A's `mfa-fatigue` names |
| Everyday activity | no alert from any cross-source rule on anyone else; no flood or state-full alert |

Alerts by rule on the simulation: `encoded-powershell` 60, `stolen-laptop-collection` 60, `stolen-laptop-access` 60,
`beacon-regular-destination` 4, `beacon-from-document-process` 2, `cloud-download-volume` 1,
`cloud-bulk-download-then-external-share` 1, `cr-deny-storm-ip` 11, `cr-spray-ip` 16. Silent (nothing in the
simulation they look for): break-glass, honeytoken, PAM refusals, telemetry refused or gap, collector flood,
heartbeat.

## Requests to integration

1. **Techniques on alerts.** `Alert` has no techniques, so part E cannot rank by MITRE technique from the alert
   alone. Either add `List<Technique> techniques` to `Alert` (soc contract), or have part E read
   `RuleBook.techniques(rule)` / `CorrelationEngine.recent()` (`Raised(alert, techniques, actionable)`). The
   summary also ends with `[MITRE ...]`.
2. **The actor of native records.** `SecurityEvents.nativeEvent` drops the record's actor, and part A's
   `casb.dlp` records name the uploader only as the actor, so `dlp-block-spike` cannot be expressed per person in
   the language. Request: add the actor as a field `actor` (and as a `SUBJECT` entity for `casb.dlp`).
3. **Two engines on the same trail.** The `cr-*` rules repeat part A's rules with their own ids. Choose one per
   rule (recommendation: keep part A's `DetectionEngine` for its rules, which also checks the anchor, and remove
   the `cr-*` rules from `default-rules.yaml`, or load them only for the demo); otherwise the case book gets two
   alerts for one storm. Part B/F playbooks need entries for the new rule ids, at least `stolen-laptop-access`
   (CRITICAL, actionable), `beacon-from-document-process` and `stolen-laptop-collection`; the collected-only
   rules (`beacon-regular-destination`, `cloud-*`) must stay watch/rank only.
4. **`count by` through `EventSearch`.** `EventSearch.Result` carries events only; `EventStore.counts()` answers
   `count by`. The SOC API (part F) should call it, or `EventSearch` could gain a `counts` method.
5. **Wiring at start-up** (Layer 6 launcher): one `Ingestor` per trail writer, with the same clock as the other
   audit writers; collectors get a fresh `runId` per start (for example the start time in base 36); call
   `EndpointCollector.resume(EndpointCollector.lastBatches(cursor, max))` before accepting batches (rD7);
   register endpoint as `SIGNED_SENSOR`, firewall and cloud as `COLLECTED`; pass `RuleBook.load` the same
   dataset map.
6. **Heartbeats.** `sensor-heartbeat-missing` needs the (simulated) device agent to send `sensor.heartbeat`
   lines; nothing sends them yet, so the rule is silent.
7. **Threat model.** Add rows D1 to D15 and rD1 to rD7 from this file (v1.4).
8. **Residual risks to state:** correlation state and the event store live in memory (a restart forgets open
   windows; the store refills from the trail); DHCP leases are configuration, so a stale lease names the wrong
   device for a firewall flow (the alert is collected-only anyway); a key flood beyond 10,000 keys per rule
   refuses new keys (alerted, but a new attacker key arriving during a flood is not tracked); thresholds are
   starting values for the simulated organisation, not tuned on real logs.
9. Part A's `DetectionEngine` reads `SECURITY_EVENT` records without trouble (tested on the simulated trail);
   no change needed.
