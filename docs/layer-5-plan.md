# Layer 5 build plan: the SOC loop and analytics

*Plan for building Layer 5 in parallel: one integration session (this one) and three part sessions,
the same way as [Layer 4](layer-4-plan.md).*

## 1. Goal of Layer 5

Layers 1 to 4 decide and enforce. Layer 5 is the security team's side of the system: **see what
happened, react to it, and check that the numbers the engine relies on are right.** It also delivers
what earlier layers deferred to "Layer 5": SIEM export, per-signal decay set by the SOC (M5), What-If
replay of policy changes (M8), the sensitivity analysis of MFA strength (M9, the β values), calibration
of the assumed probabilities, encrypted audit storage at rest, and DLP findings as risk evidence.

| Part | Builds | Packages |
|---|---|---|
| **0. Contracts** (integration session, first) | Reading and verifying the audit trail, alert and verdict records, the engine-side signal feed with expiry and decay, a labelled simulated organisation for tests | `dev.dwarpal.audit` (additions), `dev.dwarpal.soc`, `dev.dwarpal.pip` (additions), test fixture `dev.dwarpal.sim` |
| **A. SIEM and detection** | Encrypted append-only audit store; export to SIEM formats; detection rules that turn audit events into alerts | `dev.dwarpal.siem` |
| **B. SOC response loop** | Cases, signed analyst verdicts, playbooks that act (revoke, deny with expiry, watch), verdicts and DLP findings fed back as decaying risk evidence | `dev.dwarpal.response` |
| **C. Analytics** | What-If replay of a proposed policy, calibration of the assumed probabilities, sensitivity analysis, accuracy metrics | `dev.dwarpal.analytics` |

```
                  audit trail (HMAC chain)
 engine, PA, PAM,  ------------------------>  A: encrypted store --> export (JSON lines, CEF, syslog)
 gateways, DLP                                   |
                                                 +--> A: detection rules --> alerts
                                                                                  |
                                                         B: cases, analyst verdicts (signed)
                                                                                  |
 engine  <-- signal feed (deny until, watch with half-life)  <-- B: playbooks -----+
   ^                                                              (revoke, deny, watch, force MFA)
   |
 C: What-If replay of recorded traffic under a proposed policy; calibration; sensitivity; accuracy
```

## 2. Why Part 0 comes first

The three parts meet in three places: the audit trail (A stores it, A's rules and C's analysis read
it), alerts and verdicts (A raises alerts, B handles them) and the signal feed (B writes to it, the
engine reads it). Part 0 fixes those three meeting points before anyone starts, plus one shared
simulated organisation so every part tests against the same users, attacks and audit trail.

Each part can be built and tested on its own:

- A reads any `AuditSource` (the in-memory sink in tests) and writes to any `AlertSink`.
- B takes alerts from a list in tests and acts through interfaces that already exist
  (`PolicyAdministrator`, `PrivilegedAccessManager`, `SignalFeed`).
- C runs the simulated organisation through two engines (current and proposed policy) and compares.

## 3. Part 0: contracts (this session)

**Status: built and tested.** Everything below exists on `main`; build on it.

| Item | Where | What it gives you |
|---|---|---|
| `AuditSource` | `dev.dwarpal.audit` | `after(sequence, max)`: records after a sequence number, in order, at most `MAX_BATCH` (10,000); `lastSequence()`. `InMemoryAuditSink` implements it (binary search, so reading a long trail is linear); part A's encrypted store must too |
| `AuditEvent` | `dev.dwarpal.audit` | `AuditEvent.of(record)`: sequence, time, type, actor and `fields()` (a map) / `field(name)`. Payloads must be flat JSON objects of strings within `PAYLOAD_LIMITS` (256 KiB, 65,536-character values); anything else throws |
| `AuditCursor` | `dev.dwarpal.audit` | `fromStart(source, key)` (or without key: order and links only), `resume(source, key, verifiedHead)`, `next(max)` gives a `Batch(events, problem)`. Checks sequence, link and MAC; **at the first break it stops for good** and every later `next` returns the same problem. `checkpoint()` to save a position; `checkAgainst(anchoredHead)` detects a truncated or rewritten trail |
| `Severity`, `Entity`, `Alert`, `AlertSink` | `dev.dwarpal.soc` | `Alert(id, rule, severity, raisedAt, entities, evidence, count, summary)`: ids are identifiers, 1 to 16 entities, 1 to 100 audit sequence numbers as evidence, a count for deduplicated alerts, and a summary sanitised and cut to 200 characters. `raisedAt` is audit time, so replaying a trail gives the same alerts. `AlertSink.raise(alert)` returns false when it refuses |
| `Verdict` | `dev.dwarpal.soc` | `Verdict(alertId, analystId, outcome, proof)` with `TRUE_POSITIVE`, `FALSE_POSITIVE`, `BENIGN`; `verify(keys, now)` checks a `SOC_ANALYST` key bound to that analyst over (alert, analyst, outcome, time), at most 15 min old. **Single use is the caller's job** (part B: remember spent verdicts with a `NonceCache`) |
| `SignalFeed` | `dev.dwarpal.pip` | `new SignalFeed(honeytokens, audit, clock)`. `deny(kind, id, duration, actor, reason)` (at most 30 days; a deny is only ever extended, `clear` ends it); `watch(kind, id, logLr, halfLife, actor, reason)` (adds risk only, 0 < logLr <= ln 1000, half-life 1 min to 90 days; a new watch adds to what is left of the old one, capped); `clear`; `snapshot(now)` for the engine (cached, read-only); `watchLogLr(kind, id, now)` and `denied(kind, id, now)` for scorers and playbooks; `purge()`. Every change is audited first (`SIGNAL_DENY`, `SIGNAL_WATCH`, `SIGNAL_CLEAR`); no audit, no change; at most 100,000 entries, then refusals are counted. **Times come from the feed's own clock**, never from callers |
| `KeyPurpose.SOC_ANALYST`, `SignedMessages.socVerdict` | `dev.dwarpal.crypto` | Key separation: an analyst key signs verdicts and nothing else |
| `SimOrganisation` (test) | `src/test/java/dev/dwarpal/sim` | `SimOrganisation.create(seed, users)`: users (2/3 home, 1/6 roamers, 1/6 travellers), keys (device agents, identity provider, analysts `ana` and `ben`), directory, 45 days of learned history, threat intelligence (a Tor exit, a cloud ASN). `engine(policies)` / `engine()`, `pipeline(engine)` (learning + audit into `sink`, key `auditKey`), `traffic()` (time-ordered `Step`s: `RequestStep` with a `Labelled(request, scenario, userId)` or `FailureStep` for the password spray; call once per run), `run(pdp, steps)` (moves `clock`, applies the feed's snapshot, returns `Result(labelled, decision)`), `verdict(analyst, alertId, outcome, at)`, `signals` (a `SignalFeed` on the same clock and audit log). Scenarios `L1` to `L4` are legitimate, `A1` to `A7` attacks; legitimate traffic is never denied and stuffing, impossible travel, Tor and spray are always denied (seed 7, 60 users) |

Things every part must know:

- Field **names** in `AuditEvent` come from Dwarpal's code, but exporters must still escape names as well
  as values (a record read without the key is not proven to be Dwarpal's).
- Numbers measured on `SimOrganisation` measure consistency with the threat model, not real-world
  accuracy; say so, with the seed and size.
- The red-team pass on part 0 found two breaches in `SignalFeed` (R11, R12 in the threat model), fixed
  before anything was pushed.

## 4. Rules for every part session

The rules of [Layer 4](layer-4-plan.md) section 4 apply unchanged: own branch from `main` after Part 0
(`layer5/part-a-siem`, `layer5/part-b-response`, `layer5/part-c-analytics`); own only your packages and
your notes file; build on the contracts; same engineering bar (fail-closed, limits, no secrets in
logs, `-Xlint:all -Werror`, abuse cases first, red-team pass with each weakness reproduced, fixed and
kept as a test, 80% line and branch coverage, SpotBugs and FindSecBugs clean, `mvn verify
spotbugs:check` green); zero cost; push your branch, do not merge into `main`; no secret-looking
literals; the notes file has what was built, design decisions, a STRIDE table, red-team findings,
test results and requests to integration.

Two additions for Layer 5:

1. **The SOC is a target too.** An attacker who can write to the audit trail, flood alerts, forge a
   verdict or trigger a playbook can turn the defence into a weapon (lock out the CEO, hide their own
   trail, drown the analysts). Every part's red-team pass must include attacks on the SOC itself.
2. **Numbers need their assumptions.** Any metric, threshold or calibration result states the data it
   came from (the simulated organisation, its seed and size) and is never presented as real-world
   accuracy.

## 5. Part A: SIEM and detection

**Goal:** the audit trail is stored safely, can be shipped to any SIEM, and turns into alerts.

| Component | Requirements |
|---|---|
| `siem.EncryptedAuditStore` | Implements `AuditSink` and `AuditSource`. Append-only file; each record encrypted with AES-256-GCM (JDK), a fresh 96-bit nonce per record, the sequence number as associated data (so records cannot be swapped or replayed); the key never written to disk next to the data; a damaged, swapped or truncated record is detected on read; bounded record size |
| Head anchoring | Writes the chain head (sequence, MAC) to a separate anchor file on a schedule and on demand; verification against the anchor detects a truncated trail |
| `siem.Exporters` | JSON lines, CEF and RFC 5424 syslog; each format's escaping rules applied so a field value cannot forge another field or another event (CEF `\|` and `=`, syslog structured data `]` and `"`, new lines everywhere) |
| `siem.DetectionEngine` | Reads an `AuditCursor`, runs rules, writes `Alert`s. Per-rule deduplication and throttling (one alert per entity and window, with a count), bounded state, deterministic (same trail, same alerts) |
| Rules (at least) | Break-glass used; honeytoken touched; stolen-token revocation (`SESSION_REVOKED` for another device); deny storm per subject and per address; many STEP_UP in a row for one person (MFA fatigue, M9); impossible travel followed by an ALLOW; DLP block spike per person; refused PAM requests or approvals; audit chain break or anchor mismatch (CRITICAL) |
| Tests | Tampering with the encrypted file (bit flip, swap, truncate, replay a record); exporter injection with hostile field values; rules on the simulated organisation's trail (expected alerts present, no alert on legitimate traffic); alert floods throttled; bounded memory under 1,000,000 events; a chain break stops detection and raises one CRITICAL alert |

## 6. Part B: SOC response loop

**Goal:** an alert becomes a case, an analyst decides, and the decision changes what the engine does.

| Component | Requirements |
|---|---|
| `response.CaseBook` | Cases from alerts (grouped by entity), states OPEN, TRIAGED, CLOSED, bounded; every change audited |
| Verdicts | Only `Verdict`s signed by a `SOC_ANALYST` key count; one analyst cannot both raise and close a case they are the subject of; replayed or stale verdicts refused |
| `response.Playbooks` | Actions per verdict and rule: revoke a session, a person or a device (`PolicyAdministrator`, and PAM grants for a person); deny in the `SignalFeed` until a time (never forever: a maximum, for example 7 days); watch with a weight and a half-life; each action audited with the case and the analyst |
| Guard rails | Destructive actions on privileged accounts need a second analyst (two-person rule, as for policy changes); rate limits on playbook actions so a flood of alerts cannot lock out the whole company; a false-positive verdict lifts what the playbook did |
| `response.WatchlistScorer` | A `RiskScorer` that turns the feed's decayed watch weight into a risk factor (capped like every scorer) |
| DLP feedback | `casb.dlp` audit records become watch entries on the person (decaying), so repeated attempts raise their risk |
| Runbook | `docs/runbooks/idp-down.md`: what to do when the identity provider is down (break-glass needs MFA for admin actions) |
| Tests | Forged, replayed, stale and wrong-purpose verdicts; an alert flood trying to deny everyone; a verdict on oneself; a deny expiring on time; decay matching the half-life; a false positive undoing its actions; the scorer capped |

## 7. Part C: analytics

**Goal:** show what a policy change would do before it is installed, and check the engine's numbers.

| Component | Requirements |
|---|---|
| `analytics.RequestRecorder` | A `DecisionPoint` wrapper that keeps the last N requests and decisions (bounded, in memory, data minimised: no tokens, no proofs) for replay |
| `analytics.WhatIf` (M8) | Replays recorded or simulated requests through the current and a proposed policy set with the same signals and a frozen clock (no learning, no audit side effects); reports who gains and who loses access, per policy, subject, resource and action, and flags any change that grants something new to a RESTRICTED resource |
| `analytics.Calibration` | Estimates the assumed probabilities (for example P(new country given legitimate), the Poisson rates) from the simulated organisation's labelled traffic with confidence intervals (Beta posteriors), and compares them with the values in use |
| `analytics.Sensitivity` | Sweeps the MFA β values (M9) and the three costs (M2) and reports where decisions change; the step-up and deny thresholds as functions of β |
| `analytics.Accuracy` | Confusion table, detection rate, false-alarm rate, ROC curve and area, expected cost, per scenario, from labelled traffic |
| Reports | Plain text and JSON; numbers state their data source (seed, users, days) |
| Tests | What-If on a known policy edit gives the exact expected diff; replay has no side effects (audit trail and learning untouched); calibration recovers parameters planted in synthetic data; thresholds match the closed forms of M2; metrics on hand-built tables |

## 8. Integration (this session, after the three branches)

1. Review each branch against this plan and its notes file.
2. Merge A, then B, then C; apply the requests to integration.
3. End to end: the simulated organisation's traffic goes through the engine; A's store and rules raise
   alerts; B's playbooks act; the engine's next decisions change; C's What-If and accuracy reports run
   on the same trail.
4. Cross-part red team: attacks that only appear when parts meet (for example an attacker who can
   write audit records to trigger B's playbooks against someone else).
5. Full gates; threat model, README, SECURITY, project state; Layer 5 report.
6. Push only after the project owner approves.

## 9. Practical notes

- Three sessions on an 8 GB laptop: avoid running three full `mvn verify` builds at the same moment.
- Each session reads `docs/project-state.md`, `docs/layer-4-report.md` and this plan first.
- Dates: Part 0 now; parts A, B, C in parallel; integration well before the submission on 2026-11-10,
  leaving time for the demo (Layer 6).
