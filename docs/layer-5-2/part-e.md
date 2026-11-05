# Layer 5.2 part E: UEBA and prioritisation

*Notes file of the part E session (branch `layer5-2/part-e-ueba`, package `dev.dwarpal.ueba`). Read [layer-5-2-plan.md](../layer-5-2-plan.md) (sections 1 to 4 and 6) first; keep this file up to date.*

## What was built

| Class | What it does |
|---|---|
| `Ueba` | Part E wired together, and the object the other parts use: implements `EntityRisk` (risk per entity), `AlertRanker` (queue priority) and `AlertSink` (other rules' alerts come in here). `poll(cursor, max)` reads the audit chain; `falsePositive(verdict, gate)` is the only way, besides time, to lower risk. |
| `UebaEngine` | The detectors. Reads `ChainedEvent`s (through a keyed `AuditCursor` and `SecurityEvents.fromAudit`), judges each event against its entities' baselines, keeps it in quarantine, learns it only if nothing flagged it, and turns an entity's anomalies within two hours into one `ueba-anomaly` alert per severity step. |
| `Baselines` | The learned state, bounded: per person and device, hourly volume per action (window of 168 active hours), first-seen values per field (rule of succession), time-of-day samples, recent connection times per destination; plus what each peer group has learned. |
| `Anomaly` | One finding: entity, detector, group, weight (log-odds), evidence (audit sequence numbers), `actionable`, MITRE technique, and a reason line with the numbers. Detectors: `VOLUME`, `DATA_VOLUME`, `FIRST_SEEN`, `TIME_OF_DAY`, `BEACON`, `DRIFT`. |
| `PeerGroups` | Group (role or department) per person, supplied by the deployer; a device belongs to its owner's group (owner from the `AssetCatalog`). Fixed at start-up. |
| `UebaRisk` | Entity risk: contributions with half-lives, merged per group, capped, collected-only evidence capped, combined in log-odds with the base rate (M3), shown 0 to 100. Also takes watches. |
| `EvidenceIndex` | Provenance of the last 2 million audit records (one byte each), so `actionable` is computed from the cited records, not trusted from the rule. Unknown counts as not actionable. |
| `RiskRanker` | `AlertRanker`: a points table (severity, entity risk, asset criticality) into P1 to P4, techniques, `actionable`, and one reason line per term. |
| `TriageQueue` | A bounded analyst queue (priority, actionable first, score, oldest first), folding copies of one rule about one entity into one place. A reference for part F. |
| `TechniqueMap` | Rule id to MITRE techniques (part A's ten rules and the UEBA detectors; part D's rules to be added at integration); per-alert techniques for UEBA alerts. Only techniques `Techniques` knows are accepted. |
| `MitreCoverage` | Which known techniques have a rule or detector, and how many alerts pointed to each. |
| `SocReport` | The daily SOC report in text and JSON: data source first, alerts by priority (and how many only collected), top risky entities with their strongest reason, mean time to verdict, false positives per rule with the Laplace estimate, MITRE coverage. |
| `UebaSettings` | Every limit and threshold in one record, with `reference()` values. |
| `JsonOut` | A minimal JSON writer for the reports (RFC 8259 escaping, plus bidi and line separators). |

Test helper `SimTrail` (test code only) stands in for part D's collectors: it parses the simulator's firewall, cloud and
endpoint lines with a deliberately small parser, verifies each endpoint batch's signature (`SIGNED_SENSOR` only if it
verifies), and writes every event into the organisation's audit chain as `SECURITY_EVENT` under
`collector:<dataset>`. Ground-truth labels are kept beside the chain, never in it.

```
 AuditCursor (keyed) -> SecurityEvents.fromAudit -> UebaEngine.observe
        judge against baselines -> anomalies -> UebaRisk (EntityRisk)
                                          \-> correlate per entity (2 h) -> ueba-anomaly alert -> alert sink
        quarantine (1 h of audit time) -> learn, unless flagged by an anomaly or by any rule's alert
 other rules' alerts -> Ueba.raise -> risk + keep their evidence out of the baselines
 Ueba.rank(alert, now) -> RankedAlert (priority, score, techniques, actionable, reasons)
```

## Design decisions and why

**Every statistic can be recomputed by hand.** Each anomaly's reason prints its inputs and result, for example
`10 x file.download in one hour, usual 2.00 per active hour over 24 hours (z=5.7, Poisson l=5.0)` or
`first process mimikatz.exe for u1; 4 new in last 24 (P=(k+1)/(w+2)=0.192, l=0.96)`. The tests check several of them
against a calculation written in the test.

| Detector | Statistic | Fires when (reference) | Weight (log-odds) |
|---|---|---|---|
| `VOLUME` | Events of one action in one hour, k, against λ = mean of the last 168 active hours (floor 0.5); z = (k − λ)/√λ | k ≥ 10 and z ≥ 4, once per hour | Poisson LR of section 8.8 with λ_a = 10 λ: k ln 10 − 9λ, capped at ln 100 |
| `DATA_VOLUME` | Bytes of one action in one hour against the usual hour's bytes | ratio ≥ 10 and ≥ 50 MB | ln ratio, capped at ln 100 |
| `FIRST_SEEN` (M1) | A value never learned for this entity (action, process, parent, dst, dport, share, vendor, country); k new values in the last w ≤ 200 observations, P(new \| legit) = (k+1)/(w+2) | at least 20 observations of that field, and l ≥ ln 2 | ln(0.5 / P(new \| legit)); + ln 2 if fewer than 10% of the peer group know the value |
| `TIME_OF_DAY` (M6) | von Mises density over one learned sample per active hour, κ = 8 | at least 20 samples and l ≥ ln 10, once per hour | −n/(n+10) ln(2π f(θ)), capped at ln 100 |
| `BEACON` | Times of the last ≤ 32 connections to one destination (per dataset); coefficient of variation of the intervals | ≥ 10 intervals, mean 1 s to 1 h, CV ≤ 0.1, destination not known to the entity | ln 100 (assumption) |
| `DRIFT` | The volume baseline against its lowest daily level in the last 30 days | at least 3 daily levels and λ ≥ 3 x that level, once a day | ln ratio, capped at ln 100 |

**Learning only from events nobody flagged.** An event waits one hour of audit time before it is learned. If it
caused an anomaly, or if any rule (part A's, part D's) raises an alert citing it in the meantime (`Ueba.raise`), it is
never learned. Values a UEBA alert flagged are learned only after a signed false-positive verdict on that alert: the
analyst can teach the baseline, the attacker cannot.

**Groups, so correlated evidence is not counted twice.** The event count and the bytes of one burst are one piece of
evidence (`burst:<action>`); ten copies of one rule's alert about one person are one (`alert:<rule>`). Within a
group only the strongest (decayed) contribution counts; the reason line says how many there were. This is the main
guard against naive Bayes over-counting, which section 8.1 names as the model's assumption.

**Entity risk** (implements `EntityRisk`), all in `UebaRisk`'s javadoc:
w(t) = w₀ · 0.5^(age/T); contributions dated after `now` do not count (a replay gives the same answer); each group
capped at ln 1000; groups backed only by `COLLECTED` evidence capped together at ln 1000 (scaled proportionally, the
reason says so); Σ into p = σ(logit(0.001) + Σ); shown as score = 100 (p − 0.001)/0.999, so an entity with nothing
is 0 and Σ = ln 1000 gives 49.975 (MEDIUM). Every contribution is listed; above 20 the smallest are summed into one
`ueba:other` line so the listed weights always add up to the score. Weights and half-lives: alerts LOW ln 3 / 1 day,
MEDIUM ln 10 / 3 days, HIGH ln 100 / 7 days, CRITICAL ln 1000 / 14 days; anomalies their own weight / 1 day; watches
their own. Nothing subtracts, so nothing an entity does can lower its risk: only time, or `Ueba.falsePositive` with a
verdict that part B's `VerdictGate` admits (signed by a `SOC_ANALYST` key, fresh, single use), which removes exactly
that alert's contributions (and, for a UEBA alert, its anomalies).

**Ranking** (implements `AlertRanker`):

```
score = severity points (LOW 10, MEDIUM 25, HIGH 40, CRITICAL 55)
      + 0.30 x highest entity risk of the alert's entities      (0 to 30)
      + 3.75 x (highest asset criticality - 1)                   (0 to 15)
P1 from 75, P2 from 55, P3 from 35, else P4
```

`actionable` = at least one cited record is known to the evidence index and is more than `COLLECTED`. An alert that is
not actionable is ranked and shown (never hidden), labelled, and capped at P2. Unknown assets use the catalogue's
default criticality (3) and say "unknown asset", never "low".

**Assumptions** (all in `UebaSettings.reference()` and `UebaRisk.Settings.reference()`, none calibrated on real
data): P(new | attack) = 0.5; attack activity = 10 x the usual rate; regular connections to a new destination
LR = 100; the thresholds in the table above; the points table of the ranker; the weights and half-lives of risk.

## Threats and mitigations (STRIDE)

| # | STRIDE | Threat | Mitigation in code | Test |
|---|---|---|---|---|
| E1 | Spoofing | Forged syslog or cloud lines name an innocent person (framing) | Collected-only evidence capped at ln 1000 in risk (at most MEDIUM, score ≤ 50); collected-only alerts never actionable and at most P2 | `UebaRedTeamTest.forgedCollectedEventsCannotMakeAnInnocentPersonHighRisk` |
| E2 | Tampering | Slow baseline poisoning | Learned hourly counts clipped at λ + 2√λ + 1; `DRIFT` against the lowest daily level of 30 days; while drifting the baseline may not grow | `slowPoisoningCannotTeachTheBaselineAnExfiltrationRate` |
| E3 | Tampering | Teaching the baseline with the suspicious events themselves | One-hour quarantine; events with an anomaly or cited by any alert are never learned; flagged values learned only after a signed false positive | `UebaAbuseTest.eventsUnderAnAlertAreNotLearnedEvenIfTheAlertComesLater` |
| E4 | Tampering | A forged chain or a forged record | Reads only through a keyed `AuditCursor`; stops for good at the first break; records that do not convert (missing fields, actor not the dataset's collector) are counted as malformed | `aBrokenChainStopsReadingForGoodAndMalformedRecordsAreCounted` |
| E5 | Tampering | Event times far in the future or past move the hourly state | Events outside [recorded − 2 days, recorded + 5 min] are counted as skewed, neither judged nor learned | `aFarFutureEventDoesNotSwitchOffVolumeDetection`, `lateAndSkewedEventsAreCountedNotGuessed` |
| E6 | Repudiation | A score nobody can explain | Every anomaly carries its numbers; every contribution listed with evidence sequence numbers; ranked alerts list one reason per term | `UebaSimulationTest.summary` recomputes every score from its contributions |
| E7 | Info disclosure | Reports or reasons leak payloads or carry injection | Reasons sanitised and bounded (`Sanitize`), values shortened to 40 characters; JSON escapes quotes, controls, bidi and line separators; no payload copied into alerts | `hostileValuesAreHandledAsData`, `jsonEscapesEverythingHostile` |
| E8 | Denial of service | A flood of new entities evicts a victim's baseline | Profiles are never evicted; new ones beyond `maxProfiles` are refused and counted | `aFloodOfNewEntitiesCannotEvictAnEstablishedBaseline`, `floodsAreBounded` |
| E9 | Denial of service | A flood of alerts buries the real one | Queue keeps the most urgent; a full queue only accepts something more urgent than its last entry; copies fold into one place | `aFloodOfAlertsCannotPushARealAlertOutOfTheQueue`, `theQueueFoldsCopiesAndOrdersByPriority` |
| E10 | Denial of service | Unbounded memory | Bounds on profiles, actions, values, destinations, peer keys, quarantine, risk entities and contributions (the weakest makes room, never a stronger one), evidence index, alert memory, queue, report inputs | `floodsAreBounded` |
| E11 | Elevation | An entity lowers its own risk, or a forged or replayed verdict does | No input subtracts; only time or a verdict admitted by `VerdictGate` | `anEntitysOwnGoodBehaviourNeverLowersItsRisk`, `forgedReplayedOrWrongVerdictsDoNotLowerRisk` |
| E12 | Elevation | Hiding in a noisy peer group | Peers can strengthen a finding, never weaken it | `aNoisyPeerGroupDoesNotHideAFirstTimeValue` |
| E13 | Elevation | A rule claims its alert is actionable | `actionable` computed from the cited records' provenance; unknown records count as not actionable | `rankingPointsByHandAndUnknownAssets` |

## Red-team findings

*(each reproduced as a working probe first, then fixed, then kept as a regression test in `UebaRedTeamTest`; the
first version of the code had the weakness, the probe failed against it, the fix made it pass)*

| # | STRIDE | Breach (before the fix) | Root cause | Fix | Test |
|---|---|---|---|---|---|
| E-R1 | Tampering | Over 40 days the attacker raised the hourly download count just under z = 4 each hour (starting from 2 per hour); then 60 downloads in one hour raised **no volume anomaly** (only a time-of-day one), because the learned mean had reached about 120 | Every unflagged hour entered the window unchanged; nothing compared the baseline with its own past | Clip each learned hour at λ + 2√λ + 1; once a day compare λ with the lowest daily level of 30 days, report `DRIFT` from 3 x, and while drifting clip at that level | `slowPoisoningCannotTeachTheBaselineAnExfiltrationRate` |
| E-R2 | Spoofing | 40 forged collected process events and 80 forged downloads naming the CEO gave the CEO **risk 100, CRITICAL** | Collected and verified evidence added up alike | Groups backed only by collected evidence count together for at most ln 1000 (scaled, labelled); the ranker already capped them at P2 | `forgedCollectedEventsCannotMakeAnInnocentPersonHighRisk` |
| E-R3 | Elevation | In a group where 6 of 11 peers run `psexec.exe`, an insider's first `psexec.exe` raised **no anomaly** | A value common among peers halved the weight, pushing it below the reporting threshold | Peers only strengthen (rare for peers: + ln 2), never weaken | `aNoisyPeerGroupDoesNotHideAFirstTimeValue` |
| E-R4 | Denial of service | 5,000 forged HIGH alerts about distinct addresses **pushed the real P1 honeytoken alert out** of a 100-place queue | A full queue dropped its oldest entry | A full queue drops its last entry in triage order, and only for something more urgent; otherwise the newcomer is refused and counted | `aFloodOfAlertsCannotPushARealAlertOutOfTheQueue` |
| E-R5 | Denial of service | 200 events naming invented devices **evicted the victim's baseline** (limit 50 profiles); the victim's first `mimikatz.exe` was then not judged at all | Profiles were kept in a least-recently-used map | Established profiles are never evicted; new ones beyond the limit are refused and counted (`refusedProfiles`) | `aFloodOfNewEntitiesCannotEvictAnEstablishedBaseline` |
| E-R6 | Tampering | One forged collected download dated 30 days ahead **switched off volume detection** for that person and action: a 60-download burst was not seen | The hourly state moved to the newest event time, and every real event then counted as late | Events more than 5 minutes ahead of, or 2 days behind, their audit record time are counted as skewed, neither judged nor learned | `aFarFutureEventDoesNotSwitchOffVolumeDetection` |

Found while building, not by a probe: the time-of-day profile learned every event, so one busy hour of 200 events
could outvote weeks of habits (seen in the E-R1 probe output as a spurious time-of-day anomaly). It now learns one
sample per entity per active hour. And a UEBA alert was first dated at the anomaly that triggered it rather than the
newest one, so ranking at the alert's time missed risk already known; fixed.

## Tests and results

35 tests in `dev.dwarpal.ueba` (unit 18, abuse 7, red team 6, simulation 4). Coverage of `dev.dwarpal.ueba` with these
tests: **98.1% lines (1,248 of 1,272), 86.7% branches (586 of 676)** (JaCoCo, full gate run). SpotBugs and
FindSecBugs: no findings. Full gate `mvn -o verify spotbugs:check`: BUILD SUCCESS, 801 tests, 0 failures.

**Simulation** (`UebaSimulationTest`): `SimOrganisation` seed 7, 60 users, 8 days of `SimTelemetry` (firewall,
endpoint, cloud) written into the audit chain by `SimTrail`: 8,611 events, 4 noise lines refused by the test
collector, 0 malformed records, 2,047 anomalies, 364 UEBA alerts, ranked at their own time. *Data built by the same
team as the detectors: this measures consistency with the threat model, not real-world accuracy.*

| Label (alerts whose evidence includes it) | P1 | P2 | P3 | P4 | Best priority per person |
|---|---|---|---|---|---|
| A6 stolen laptop at home (all 60 users, day 6) | 122 | 112 | 99 | 18 | P1 for all 60 |
| A8 beaconing (u5, u17) | 4 | 2 | 2 | 2 | P1 for both |
| A9 cloud exfiltration (u9) | 0 | 1 | 1 | 0 | P2 (only collected evidence, so at most P2) |
| L5 big legitimate download (u11), alone | 0 | 1 | 0 | 0 | P2, never P1 |
| L6 administrator PowerShell | no alert | | | | |
| Normal activity only | no alert | | | | |

Notes: u11 is also an A6 victim on the same morning as their L5 download, so one alert mixes both; the test judges
L5 on alerts whose evidence is only L5 (and normal). 359 of 364 alerts are actionable (signed endpoint evidence);
the 5 that are not are the cloud-only A9 and L5 alerts. A9 reaching P2 rather than P1 is by design: the cloud export
is `COLLECTED`.

Gates: `-Xlint:all -Werror` clean; no secret-looking literals (keys are generated at run time by the fixtures).

## Requests to integration

1. **Field names.** UEBA reads `process`, `parent`, `dst`, `dport`, `share`, `vendor`, `country` (first-seen) and
   `bytes` (data volume) from `SecurityEvent.fields`. Part D's normalisers should use these names, or the integration
   sets `UebaSettings.noveltyFields` to D's names. Endpoint events should name both `SUBJECT` and `DEVICE`; firewall
   flows should name the `DEVICE` behind an internal address (DHCP leases), as `SimTrail` does.
2. **Wiring.** One `Ueba` instance. Send every alert of every other rule (part A's `DetectionEngine`, part D's
   correlation rules) to `ueba.raise(alert)` as well as to the case book (an `AlertSink` that fans out). UEBA's own
   alerts (`ueba-anomaly`) go to the shared alert sink given to the constructor; sending them back to `raise` is
   harmless (risk ignores its own rule). Poll with a keyed cursor: `ueba.poll(AuditCursor.fromStart(sink, key), n)`.
3. **Techniques of part D's rules.** Register them: `TechniqueMap.standard().rule(id, techniques...)` passed to the
   `Ueba` constructor, so ranking and the coverage report know them.
4. **Verdicts are single use.** `Ueba.falsePositive(verdict, gate)` admits the verdict itself. If part F's case book
   already admitted it through the same `VerdictGate`, a second admission is refused as a replay. Options: give UEBA
   its own `VerdictGate` on the same `KeyRing` and clock (each consumer keeps its own replay store), or add to part B a
   way to pass on an admitted verdict. The first needs no code change.
5. **Watches.** Part B's watches can feed `UebaRisk.watch(entity, source, weight, at, evidence, reason)`; integration
   may want a public `Ueba.watch` delegate (not added, to keep the facade small until the wiring is decided).
6. **Peer groups and assets.** Build `PeerGroups.of(department by person id, assetCatalog)` from the directory, and an
   `AssetCatalog` in which each device's owner is its person's id (device peer groups come from it).
7. **`actionable` for playbooks.** Part F should gate destructive steps on `RankedAlert.actionable()`; collected-only
   alerts are capped at P2 and labelled.
8. **Threat model v1.4.** Add rows for E1 to E13 and E-R1 to E-R6 above (slow poisoning, framing with collected
   events, noisy peer groups, queue flooding, profile eviction, far-future timestamps).
9. **Simulation fixture.** In `SimTelemetry`, u11 is both the L5 quarter-end downloader and an A6 victim on the same
   morning, which mixes the false-positive check with an attack; moving L5 to another day or person would make the
   check cleaner. A6 runs for every user on day 6, so A6 dominates the alert counts.
10. **Time zone.** Time of day is judged in UTC; a deployment-wide time zone setting would make the reasons easier
    to read. Not needed for correctness (the density is per person).
11. **Sizing.** Reference limits: 200,000 profiles, 1,000,000 events in quarantine, 2,000,000 records in the evidence
    index (2 MB), 100,000 risk entities with 256 contributions each. `stats()` reports refused profiles, dropped
    quarantine entries, late and skewed events, so a SOC sees when a limit is reached.
