# Layer 5 report: the SOC loop (SIEM and detection, response, analytics)

| | |
|---|---|
| State as of | 2026-11-05 (first round integrated) |
| Built by | Part 0 and integration in the main session; parts A, B and C in three parallel sessions on their own branches |
| Size | 36 new main classes (about 6,000 lines) in `soc`, `siem`, `response`, `analytics`, plus `AuditCursor`, `AuditEvent`, `SignalFeed` |
| Tests | 749 in the whole project (218 new in Layer 5), 0 failures; SpotBugs and FindSecBugs clean; `-Xlint:all -Werror` |

## 1. Where Layer 5 sits in the whole project

| Layer | Name | Status |
|---|---|---|
| 1 | Core decision engine | Done |
| 2 | Behavioural risk scorers | Done |
| 3 | Policy Administrator (sessions, privileged access) | Done |
| 4 | Enforcement points and the SASE edge | Done |
| **5** | **SOC loop and analytics** | **First round done (this report); second round (SOC platform) next** |
| 6 | Console, demo and deployment | When requested |

## 2. What Layer 5 is about

Layers 1 to 4 decide and enforce. Layer 5 closes the loop: what the engine decided is kept where nobody can
quietly change it, read back by detection rules, turned into cases, confirmed or rejected by a person, acted
on within guard rails, and fed back into the engine's next decisions. The same trail answers the analyst's
other questions: what would this policy change do, are our probabilities right, how accurate are we.

```
 decisions --> audit chain --> encrypted store --(verified cursor)--> detection rules --> alerts
                    |               |                                                       |
                 anchor        exporters (CEF, syslog, JSON lines)                       case book
                                                                                             |
 engine <-- signal feed <-- playbooks (guard rails) <-- signed analyst verdict (single use) -+
   ^             (deny with an end, fading watch)
   +-- analytics: What-If replay, calibration, sensitivity, accuracy (on the same trail)
```

NIST SP 800-207 calls this the continuous diagnostics and SIEM input to the policy engine. In product terms
it is the core of a SIEM (store, detect, export) and of a SOAR (cases, verdicts, playbooks), with the
analytics an engineering team uses to change policy safely.

## 3. How it was built

1. **Part 0** (main session, pushed first): the shared contracts, so the three parts could not disagree.
   `AuditSource`, `AuditEvent` and `AuditCursor` (verified reading of the trail), `Alert`, `Entity`,
   `Severity`, `AlertSink`, signed `Verdict`s with a new `SOC_ANALYST` key purpose, the `SignalFeed`
   (expiring denies, fading watches), and the `SimOrganisation` test fixture (60 users, labelled legitimate
   and attack traffic). Its red-team pass found two breaches in `SignalFeed` (R11, R12), fixed before push.
2. **Parts A, B, C** in parallel sessions, each in its own package with its own notes file, each with a
   red-team pass where every weakness was first reproduced as a working probe, then fixed, then kept as a
   regression test.
3. **Integration** (main session): review of each branch, merge, the parts' requests to integration,
   cross-part tests and red team, full gates, documents.

## 4. Part A: SIEM and detection (`dev.dwarpal.siem`)

### 4.1 The trail at rest and its anchor

| Class | Design |
|---|---|
| `EncryptedAuditStore` | One append-only file. Every record sealed on its own with AES-256-GCM (fresh nonce), bound to the store id and its position, so frames cannot be moved, swapped or copied between stores. Checked in full on open; damage is reported, the good records before it stay readable, writes are refused. Only the next record of the chain is accepted. `SYNC_EVERY_RECORD` (fsync) for production |
| `HeadAnchor` | Writes the chain head (sequence, MAC) to a separate file with its own HMAC key, on demand and on a schedule. A reader compares the trail with a fresh anchor: short of it means truncated, different means rewritten; a rolled-back, forged, missing or stale anchor is also tampering |
| `Exporters` | Events and alerts as JSON lines, ArcSight CEF and RFC 5424 syslog, so a real SIEM can take the trail. Names and values are escaped by each format's rules: one field cannot forge another field or another event |

Three keys, kept apart: the audit HMAC key (proves Dwarpal wrote a record), the store AES key (hides it), the
anchor HMAC key (proves the anchor). None is ever written next to the data.

### 4.2 Detection

`DetectionEngine` reads only through a keyed `AuditCursor`, so it never acts on a record it cannot prove
Dwarpal wrote, and at the first break in the chain it raises one critical alert and stops for good.

| Rule | Fires on | Severity |
|---|---|---|
| `break-glass-used` | every emergency-account use | CRITICAL |
| `honeytoken-touched` | any decision on a honeytoken | CRITICAL |
| `stolen-token-revoked` | a session ended because its token came from another person or device | HIGH |
| `deny-storm-subject` | 5 denies for one person in 15 min (they are the target, not the suspect) | MEDIUM |
| `deny-storm-ip` | one address denied 10 times, or for 5 people, in 1 h (stuffing, spray, Tor) | HIGH |
| `mfa-fatigue` | 5 step-ups for one person in 30 min without an allow | HIGH |
| `impossible-travel-allow` | impossible travel, then an allow for the same person within 2 h | HIGH |
| `dlp-block-spike` | 5 DLP blocks for one person in 1 h | MEDIUM |
| `pam-refused`, `break-glass-refused` | repeated refused elevations; any refused emergency access | MEDIUM, HIGH |
| `audit-chain-break`, `audit-anchor-mismatch` | the trail is broken, truncated or rewritten | CRITICAL, then detection stops |
| `alert-flood`, `detection-state-full` | a rule hit its hourly cap; a rule's state is full | HIGH |

Deduplication (1 h window, a count on the alert), hourly caps per rule (50, or 200 for critical rules, with
the flood itself alerted), bounded state everywhere (20,000 keys per rule, 50,000 open windows). Thresholds
are starting values for a small organisation, stated as assumptions.

## 5. Part B: the response loop (`dev.dwarpal.response`)

| Class | Design |
|---|---|
| `CaseBook` | The `AlertSink`: groups alerts by the person (or entity) they are about into cases OPEN, TRIAGED, CLOSED. Bounded: when full it drops the oldest untouched, less severe case (audited), never a critical one |
| `VerdictGate` | A verdict counts only if signed by that analyst's own `SOC_ANALYST` key over alert, analyst, outcome and time, at most 15 minutes old, and used once |
| `Playbooks` | TRUE_POSITIVE runs the rule's play; FALSE_POSITIVE undoes the case's denies and watches; BENIGN closes. A play has up to 16 steps: `Revoke` (person, device, session), `Deny` (person, device, address; at most 7 days), `Watch` (fading risk) |
| `SignalLedger` | Records who placed each deny and watch, so undoing one case leaves other cases' entries in place (time and weight left) |
| `WatchlistScorer` | A risk scorer for the engine: the faded watch weights on the request's person, device and address, capped at x1000 |
| `DlpFeedback` | Reads `casb.dlp` records from the verified trail; each adds a fading watch on the uploader (half-life 7 days, at most x100 from DLP alone) |
| `docs/runbooks/idp-down.md` | What to do when the identity provider is down or compromised (break-glass depends on it) |

The guard rails: every deny ends (7 days in a play, 30 days at most in the feed); watches only add risk and
fade; destructive actions are rate limited per hour and per analyst, counted per target; any case about a
privileged or protected person needs two analysts, and lifting what two confirmed needs two; an analyst can
never decide a case that names them.

## 6. Part C: analytics (`dev.dwarpal.analytics`)

| Class | Design |
|---|---|
| `RequestRecorder` | Keeps the last requests and decisions in memory (at most 100,000, with a per-person quota). Evidence (signed proofs) is stripped: recordings cannot be replayed as credentials |
| `WhatIf` (M8) | Replays requests through the current and a proposed policy on a frozen clock with no side effects (no audit, no learning, no signals). Reports gains and losses of access by policy, person, resource and action; grants to sensitive data are listed separately |
| `Calibration` | Beta posteriors for proportions and Gamma posteriors for rates, 95% intervals, "consistent or not" with the value in use |
| `Sensitivity` | The M2 thresholds as functions of the MFA beta; beta and cost sweeps that count changed actions |
| `Accuracy` | Confusion tables (flagged, blocked), detection and false-alarm rates, ROC curve and area, expected cost per request |
| `AuditDecisions` | Reads decisions back from the verified trail; stops at a break and says where |
| `Report`, `DataSource` | Text and JSON; every report starts with what data it was computed on, never as real-world accuracy |

## 7. Integration: what changed when the parts met

| # | Found at integration | Change |
|---|---|---|
| 1 | Four of B's playbooks were keyed by names A's rules never raise (`deny-storm`, `pam-refusals`, `stolen-token`, and nothing for the health alerts): those alerts only ever got the cautious default | Plays keyed by A's rule ids (14); a test fails if a rule has no play or a play no rule |
| 2 | Two rules matched other packages' wording ("possible token theft", the text rendering of risk factors): rewording a message would silently switch a rule off | The Policy Administrator writes `cause=token-theft`; every decision record carries `signals` (names of the factors that raised the risk). Rules use these, the old wording only for older trails |
| 3 | After a restart the audit writer began again at record 1; the encrypted store refused it and every decision became a deny | `AuditLog(key, sink, head)` continues from the store's verified head; a stale head is refused, so the chain cannot fork |
| 4 | A What-If on the live engine needed the freshness gate removed by hand, otherwise it was marked invalid | `PolicyEngine.forReplay()` drops only the clock-reading gate; `WhatIf` uses it itself. `withCostModel` lets sensitivity rebuild engines with other costs (the MFA beta must still agree) |
| 5 | Red team across A and B: anyone can send requests in the CEO's name | Proven by test: the alert names the CEO, but the confirmed play blocks the sender's address only and adds a small fading watch on the CEO; the CEO is a protected person (two analysts) |
| 6 | C reading A's store | Proven by test: the same alerts and the same decision entries from the encrypted store as from memory, with the anchor checked |

Requests left for later, with reasons, are in section 12.

## 8. The maths of Layer 5

- **M5, decay of SOC signals.** A watch of weight `w` (a log-likelihood ratio) with half-life `h` counts
  `w · 2^(-t/h)` after time `t`; a new watch adds to what is left, capped at `ln 1000`. It enters the
  engine's Bayes sum (M3) like any other factor, so it can only raise risk, and it fades on its own.
- **M8, change impact.** `Δ = { r : D_P1(r) ≠ D_P2(r) }` over recorded traffic, with everything but the
  policy held fixed (same engine copy, same frozen signals).
- **Calibration.** For a proportion with `k` events in `n` trials and a uniform prior, the posterior is
  `Beta(k+1, n-k+1)` with mean `(k+1)/(n+2)` (the rule of succession, M1); rates use a Gamma posterior.
  A value in use is "consistent" when it lies in the 95% interval.
- **Accuracy.** Detection rate `TP/(TP+FN)`, false-alarm rate `FP/(FP+TN)`; ROC area by the trapezoid
  rule, equal to the Mann-Whitney statistic (checked by a brute-force count); expected cost with the M2
  costs. Undefined rates (0/0) are reported as "n/a", never as 0.
- **Sensitivity (M9).** The M2 step-up and deny thresholds as closed-form functions of beta; the beta at
  which a given posterior changes action.

Results on the simulated organisation (seed 7, 60 users, 720 requests; generator and engine written by the
same team, so this is consistency with the threat model, **not real-world accuracy**):

| Measure | Value |
|---|---|
| Blocked (DENY): detection / false-alarm rate | 0.714 / 0.000 (no legitimate request denied) |
| Flagged (STEP_UP or DENY): detection / false-alarm rate | 0.857 / 0.567 (legitimate step-ups: odd hours, trips, a new laptop) |
| ROC area | 0.826 |
| Mean cost per request (C_B 1000, C_F 1, C_D 20, beta 0.05) | 87.7, almost all from the stolen laptop used at the victim's home (a stated limit) |
| Sensitivity of beta | no change from 0.05 to 0.10; 38 changed actions at 0.20, 124 at 0.30 |
| Detection on the same trail | Tor and spray traffic become `deny-storm-ip` cases; a confirmed case blocks the address for 4 hours |

## 9. Red-team passes on Layer 5

31 breaches were reproduced as working probes and fixed across part 0 (2), A (3), B (8), C (12) and
integration (6, counting design gaps found when the parts met); all stay as regression tests. The ones that
matter most for a SOC:

- **Turning the SOC against innocent people** (B): a false positive on a second case freed a person denied
  by the first; one analyst could revoke a privileged person's laptop; one stolen key could lift what two
  analysts confirmed; an analyst named in a case could clear it; one verdict on an alert naming 16 people
  acted on all 16 despite a limit of 6. All closed.
- **Hiding from the SOC** (A): cutting the store and putting back an old anchor; spacing MFA pushes with bad
  requests to reset the fatigue count; flooding critical honeytoken alerts. All closed.
- **Lying to the analyst** (C): a What-If with side effects; a stale gate hiding a dangerous change; a
  request claiming its own data classification; reports leaking request data or forging lines. All closed.

Full tables: threat model v1.2 (5A, 5B, 5C, 5I).

## 10. Tests and results

`mvn -o verify spotbugs:check`, JDK 25.0.5 (Temurin), offline, 2026-11-05: **BUILD SUCCESS**.

| | Tests |
|---|---|
| Before Layer 5 | 531 |
| Part 0 | 28 |
| Part A (`siem`) | 71 |
| Part B (`response`) | 51 |
| Part C (`analytics`) | 59 |
| Integration (`Layer5EndToEndTest`, `IntegrationAlignmentTest`) | 9 |
| **Total** | **749, 0 failures, 0 errors, 0 skipped** |

Coverage (JaCoCo): `siem` 94.7% lines / 87.8% branches, `response` 97.7% / 87.1%, `analytics` 99.3% /
89.6%; project gate met. SpotBugs with FindSecBugs: 0. Secret scan of the diff: no findings (class names
only).

## 11. How this compares with enterprise products

| Area | Enterprise SIEM / SOAR / UEBA / XDR | Dwarpal after Layer 5 first round |
|---|---|---|
| Log sources | Hundreds of collectors, a common schema | Its own trail only, but every record proven (keyed chain, encrypted, anchored); exports to a real SIEM |
| Rules | Rule languages analysts write, correlation over sequences | 10 rules in code with deduplication, caps and bounded state; rule language next round |
| Search and dashboards | Query languages, dashboards | None yet; SOC API next round, screens in Layer 6 |
| UEBA | Machine-learned baselines, peer groups, entity risk | Per-user baselines in the engine (Layer 2); fading watches; peer groups and entity risk next round |
| SOAR | Visual playbooks, connectors, cases with SLAs | Cases, signed single-use verdicts, playbooks with guard rails most products leave to configuration (denies always end, two analysts for privileged people, undo on false positive); playbooks in code |
| XDR / EDR | Kernel endpoint sensors, isolation | Device posture from the agent; simulated endpoint telemetry next round (real kernel sensors are out of scope) |
| Trust in the SOC's own data | Usually assumed | Proven: detection, response and analytics refuse unverified records and stop at a break |
| Change safety | Rarely built in | What-If replay of a policy edit before it goes live |

## 12. Remaining risks (stated, scheduled)

| Risk | Plan |
|---|---|
| Detection state, case book and signal ledger live in memory: a restart forgets open windows and which case holds which deny (feed entries still end on their own) | Persistent state |
| Thresholds and playbook weights are assumptions | Calibrate on real logs with part C's tools |
| What-If replays recorded requests without their evidence, so absolute decisions drift (250 of 720); the diff between policies is like for like | Replay of already-verified facts, after submission |
| Behaviour history is not time-indexed: a replay sees what was learned later | Point-in-time history |
| Every writer to the signal feed must share one `SignalLedger` | Per-holder clear in `SignalFeed` |
| An attacker who can write store and anchor and stop the anchor schedule can hide the records since the last anchor | Ship anchors off the machine |
| Keys and file permissions are deployment concerns | Layer 6 launcher (separate environment secrets, Windows ACL) |
| `WatchlistScorer` and `RequestRecorder` are built but must be wired into the deployed pipeline | Layer 6 launcher |

## 13. Files

| Where | What |
|---|---|
| `src/main/java/dev/dwarpal/siem` | Store, anchor, exporters, detection engine, rules |
| `src/main/java/dev/dwarpal/response` | Case book, verdict gate, playbooks, ledger, watch-list scorer, DLP feedback |
| `src/main/java/dev/dwarpal/analytics` | Recorder, What-If, calibration, sensitivity, accuracy, reports |
| `src/main/java/dev/dwarpal/soc`, `audit`, `pip` | Part 0 contracts |
| `src/test/java/dev/dwarpal/integration/Layer5EndToEndTest.java` | The loop across all three parts, restart, CEO red team |
| `docs/layer-5-plan.md`, `docs/layer-5/part-a.md`, `part-b.md`, `part-c.md` | Plan and each part's notes (design decisions, tests) |
| `docs/runbooks/idp-down.md` | Identity provider down or compromised |
| `docs/threat-model.md` v1.2 | 5A, 5B, 5C and 5I rows, residual risks |
