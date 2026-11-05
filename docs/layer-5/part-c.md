# Layer 5 part C: analytics

*Notes file of the part C session (branch `layer5/part-c-analytics`, package `dev.dwarpal.analytics`). Read [layer-5-plan.md](../layer-5-plan.md) first; keep this file up to date.*

## What was built

Ten classes in `dev.dwarpal.analytics` (main code only; no shared file changed):

| Class | What it does |
|---|---|
| `RequestRecorder` | `DecisionPoint` decorator that keeps the last N requests and decisions in memory (ring, at most 100,000; per-subject quota). Returns the delegate's decision unchanged; a failure to record is counted as a drop, never turned into a different decision. `snapshot()`, `stats()` (kept, recorded, evicted, refused by quota, dropped, time span), `clear()`, `forget(subject)` |
| `RecordedRequest` | The minimised record: the request with `Evidence.none()` (no posture or authentication proofs) plus what the live engine concluded (outcome, restricted, device verified, whether a login was claimed, policy, posterior). Its constructor refuses a request that still carries evidence |
| `WhatIf` (M8) | Replays requests through the current engine and `current.withPolicySet(proposed)` with one frozen `SignalSnapshot`. Reports gains and losses per request (subject, resource, action, authoritative classification, before/after outcome and policy), tallies per policy, subject, resource and action, flags new grants to RESTRICTED resources or ADMIN actions, and (for recorded traffic) replay fidelity against the live decisions. Marks the run INVALID if the freshness gate fired |
| `Observation` | One labelled decision (scenario, attack or not, outcome, restricted, posterior, gated, factor ln LRs). No request id, subject, address or device |
| `Accuracy` | Confusion tables at two operating points (flagged = STEP_UP or DENY; blocked = DENY), detection, false-alarm and precision rates (undefined rates are "n/a"), ROC curve over the score "outcome, then posterior" and its area (trapezoid = Mann-Whitney), expected cost with the engine's own M2 costs, all per scenario too |
| `Calibration` | Beta posteriors for proportions (uniform prior: mean = rule of succession), Gamma posteriors for Poisson rates (Jeffreys prior), 95% equal-tailed intervals, "consistent / NOT consistent" with the value in use; per risk factor P(fires given attack) and P(fires given legitimate), the ln LR they imply with an interval, against the mean ln LR the engine used; base rate against the prior |
| `Sensitivity` | M2 thresholds as functions of beta; closed-form beta breakpoints for a given posterior; sweeps of beta and of each cost (C_B, C_F, C_D) that re-decide the observed posteriors and count changed actions; MFA sweep (M9): of the STEP_UP requests, how many a passed challenge of strength beta resolves to ALLOW |
| `AuditDecisions` | Reads `ACCESS_DECISION` records back through an `AuditCursor` (with the key); stops at the first chain break and says where; malformed records counted, never guessed; keeps only subject, resource, action, outcome, policy and posterior |
| `Report`, `DataSource` | Every report has a mandatory `DataSource` whose statement (data, seed, users, days, requests, and a caveat) comes first in the text and in the JSON. Text is sanitised (no line forging); JSON goes through `JsonWriter`; numbers are finite or "n/a"/null; bounded sections, lines and lengths |
| `Stats` (package-private) | log-gamma (Lanczos), regularised incomplete beta (continued fraction) and gamma (series / continued fraction), quantiles by bisection; JDK only |

## Design decisions and why

1. **What-If accepts only a `PolicyEngine`.** The engine is pure; the live pipeline learns and audits. Taking a
   general `DecisionPoint` would let a caller pass the pipeline and turn a What-If into a flood of fake logins
   in the behaviour model and the audit trail (finding C1). `PolicyEngine` is final, so the type system enforces it.
2. **Proposed engine = `current.withPolicySet(proposed)`.** Same directory, keys, gates, scorers, aggregator and
   costs, so every difference is caused by the policy edit. A proposal with linter errors is refused (it could never be
   installed; reporting "no change" for it would be wrong, C10).
3. **Frozen clock.** The engine reads time only from the request (and the optional `FreshnessGate`). Replay keeps
   every request's own timestamp, so each is decided as of the moment it was made; WhatIf has no clock at all. A
   live freshness gate would deny every historical request under both policies and make the diff empty, so a run
   where it fired is INVALID (C2). The engine offers no way to remove a gate from outside; see requests to integration.
4. **Same signals.** One `SignalSnapshot` for the whole run, given by the caller; the recorder does not keep
   snapshots (they hold the honeytoken list, and a recorder dump must not reveal the traps).
5. **Classification from the directory.** The RESTRICTED flag uses the directory, never the request's claim; a
   resource the directory does not know counts as RESTRICTED (C3). New ADMIN grants are flagged as well, since an
   admin right on an INTERNAL app is just as dangerous.
6. **Data minimisation in the recorder.** Signed evidence is a credential within its validity window, so it is
   dropped (C5). Cost: a recorded request replays as "device unverified, no login". Both policies see the same
   stripped request, so the diff is still caused by the policy alone, and the report shows how many replays differ from the
   live decision (fidelity) and how many live devices were verified, instead of hiding the drift.
7. **Gain and loss.** Access rank DENY < STEP_UP < ALLOW_LIMITED < ALLOW, and within one outcome restricted <
   unrestricted. A change is counted for the policy it left and the policy it went to.
8. **ROC score = outcome first, then posterior.** A request a hard gate denied keeps the prior as its posterior;
   ranking by posterior alone would put a Tor login among the most benign requests (C8).
9. **Undefined is not zero.** Rates with an empty denominator are "n/a" in text and `null` in JSON; no analysis
   runs on an empty data set (C7).
10. **Sensitivity is the risk layer only.** Hard gates and policy floors do not depend on costs; the sweeps
    re-decide posteriors with the swept cost model and the report says so. Rebuilding whole engines per grid point
    is not possible from outside (the engine has no `withCostModel`), see requests to integration.
11. **Calibration says what it compares.** A factor "fires" when it adds risk. The implied ln LR compares marginal
    firing rates; the engine's ln LR is per event under naive Bayes, so a mismatch is a question for the SOC, not
    proof that the parameter is wrong. The simulation is attack-enriched (58% attacks), so its base rate must never
    replace the prior; the report shows it as NOT consistent on purpose.

## Threats and mitigations (STRIDE)

| # | STRIDE | Threat | Mitigation in code | Test |
|---|---|---|---|---|
| T1 | Tampering | A What-If run through the live pipeline poisons the behaviour model and the audit trail | Only `PolicyEngine` accepted; no API takes a `DecisionPoint` | `AnalyticsRedTeamTest.c1_*` |
| T2 | Spoofing | A recorded request claims a lower classification to hide a new RESTRICTED grant | Classification from the directory; unknown = RESTRICTED | `c3_*`, `c3b_*` |
| T3 | Information disclosure | Recorder keeps posture and login proofs that can be replayed | Evidence stripped; `RecordedRequest` refuses evidence | `c5_*` |
| T4 | Information disclosure | A report leaks request ids, addresses, devices or evidence | Change and Observation have no such fields; reports built only from ids, counts and rates | `c4_*` |
| T5 | Information disclosure | A recorder dump reveals the honeytoken list | Signal snapshots are not recorded | design 4; `RecordedRequest` components |
| T6 | Denial of service | One account floods the recorder so What-If sees only the attacker's traffic | Per-subject quota, refusals counted; window stated in `stats()` | `c6_*` |
| T7 | Denial of service | Huge inputs exhaust memory (replays, observations, grids, report lines) | Limits: 200,000 replayed requests, 10,000 changes kept (all counted), 1,000,000 observations, 1,000 grid points, 64 sections, 2,000 lines, 400-character values | `manyChangesAreCountedButListBounded`, `tooManyRequestsRefused`, `limits`, `c9_*`, `c12_*` |
| T8 | Repudiation / tampering | Forged audit records feed the analytics (SOC as a target) | `AuditCursor` with the key; reading stops at the first break and the source statement says so | `c11_*`, `AuditDecisionsTest` |
| T9 | Tampering (log forging) | Hostile text forges report lines or hides text with bidi controls | `Sanitize.text` on every label, value, title and description; JSON escaped | `c9_*` |
| T10 | Elevation of privilege | A What-If reports "no change" for an edit that grants access, so a reviewer approves it | Freshness gate detected (INVALID); lint-failing proposals refused; sensitive grants listed first | `c2_*`, `c10_*`, `grantToRestrictedResourceIsFlagged` |
| T11 | Repudiation (of numbers) | A number quoted without its data is read as real-world accuracy | `DataSource` mandatory in every report, statement printed first with a caveat | `dataSourceStatementsAlwaysCarryACaveat`, `reportStatesItsSourceAndValidity` |
| T12 | Tampering (silent failure) | A recording failure changes or blocks access | Recorder returns the delegate's decision; failures only counted | `recorderFailureNeverChangesTheDecision` |

## Red-team findings

Each was first reproduced as a working probe (the first half of each test), then fixed, and is kept as a regression test in `AnalyticsRedTeamTest`.

| # | Breach | Root cause | Fix | Test |
|---|---|---|---|---|
| C1 | What-If with side effects: replaying through a `DecisionPoint` given the live pipeline appended audit records and learned the replayed logins | API accepted any decision point | WhatIf takes a `PolicyEngine` only; test checks audit, history, trust and signals unchanged | `c1_replayThroughThePipelineWouldLearnAndAudit_whatIfAcceptsOnlyThePureEngine` |
| C2 | An engine with a live `FreshnessGate` denied every historical request under both policies: a three-grant payroll edit showed 0 changes | The one clock reader in the engine | Runs where the gate fired are INVALID, with the reason in the report | `c2_freshnessGateWouldHideTheDiff_replayIsMarkedInvalid` |
| C3 | A recorded request claiming `payroll` was INTERNAL hid a new grant to a RESTRICTED resource; an unknown resource was not flagged either | Classification read from the request | Directory lookup; unknown counts as RESTRICTED; ADMIN gains flagged too | `c3_*`, `c3b_*`, `c3c_*` |
| C4 | Report leaking request data (ids, addresses, devices) | Risk of copying request fields into reports | Change/Observation carry only ids that say who gains what; checked over every request of the simulation against every report's text and JSON | `c4_reportsCarryNoRequestIdsAddressesDevicesOrEvidence` |
| C5 | Recorder kept posture and authentication proofs (replayable credentials) | Whole request kept | Evidence stripped; record type refuses evidence | `c5_recorderStripsSignedEvidence` |
| C6 | One account sending 5,000 requests would evict all other traffic from a FIFO recorder | No per-subject bound | Per-subject quota, refusals counted | `c6_floodingSubjectCannotEvictOthers` |
| C7 | No legitimate traffic gave "0% false alarms" and NaN in JSON | 0/0 reported as 0 | Undefined rates are "n/a" / null; empty data refused | `c7_noLegitimateTrafficIsNotZeroFalseAlarms` |
| C8 | Hard-gate denials ranked as most benign on the ROC (posterior = prior) | Posterior used as the score | Score = outcome, then posterior | `c8_gateDenialsRankAsMostSuspicious` |
| C9 | A description with a newline forged an "Accuracy: detection rate: 1.0" line; bidi controls | Free text in reports | Sanitised and cut everywhere; bounded reports | `c9_hostileTextCannotForgeReportLines` |
| C10 | A proposal with linter errors would be "replayed" and reported | No check | `withPolicySet` lint gate: refused | `c10_proposalWithLinterErrorsIsRefused` |
| C11 | A record written into the store without the key, claiming P(attack) = 0, would enter the analysis | SOC as a target | Keyed `AuditCursor`; reading stops at the break and the source says "chain broken after sequence N" | `c11_forgedAuditRecordsStopTheReaderAndAreNotUsed` |
| C12 | Impossible inputs (k > n, NaN exposure, beta 1.5, empty or huge grids, infinite factors, p = 1 with beta = 0 giving 0/0) | Unchecked numbers | Validation everywhere; 0/0 in step-up resolution stays strict | `c12_estimatorsRefuseImpossibleInputs` |

## Tests and results

8 test classes, 59 tests in `dev.dwarpal.analytics`. Exact-diff tests use a hand-built world (`SmallWorld`: 2 people,
3 resources, no scorers, policies in code): adding one grant gives exactly one change (alice READ design-docs, DENY to
ALLOW); an edit granting payroll gives exactly 3 sensitive grants; removing the internal-apps grant gives exactly 5
losses and 1 gain; PERMIT to PERMIT_LIMITED gives 6 losses. Replay leaves the audit trail, behaviour history, trust
ledger and signal feed untouched. Calibration recovers planted probabilities (0.02, 0.3, 0.6), planted Poisson rates
(0.2, 5, 20) and a planted ln LR of ln 30; special functions are checked against closed forms. M2 thresholds match
the closed forms to 1e-15 and the project-state table. AUC equals a brute-force Mann-Whitney count.

**Results on the simulated organisation** (seed 7, 60 users, 8 days, 720 requests; the engine and generator were written by
the same team, so these measure consistency with the threat model, **not real-world accuracy**). Full reports are written
by `SimAnalyticsTest` to `target/analytics-reports/` (text and JSON).

| Measure | Value |
|---|---|
| Flagged (STEP_UP or DENY): detection / false-alarm rate | 0.857 / 0.567 (legitimate step-ups: odd hour, trip, new laptop) |
| Blocked (DENY): detection / false-alarm rate | 0.714 / 0.000 (no legitimate request denied) |
| ROC area (score = outcome, then posterior) | 0.826 |
| Mean cost per request (C_B 1000, C_F 1, C_D 20, beta 0.05) | 87.7, almost all from A6 (stolen laptop used at home: always allowed, the known limit) |
| Always denied | A1, A2, A4, A5, A7; A3 always stepped up |
| Calibration | impossible-travel, attack-surge, password-spray consistent with the data; novelty and login-time ln LRs not consistent with the simulation's marginal rates (expected: per-event naive-Bayes LRs against marginal rates, and the generator's attackers log in at habit hours); base rate 0.58 vs prior 0.001 (the simulation is attack-enriched); spray failures 15 per window vs the assumed attack rate 10 |
| Sensitivity (beta sweep) | 0 changes between beta 0.05 and 0.10; 38 at 0.20, 124 at 0.30; step-up resolution: all 280 step-ups resolve at beta 0.01, 147 at 0.05, 20 at 0.30 |
| What-If (remove P-01, recorded traffic) | 360 losses, 0 gains, 0 sensitive; replay fidelity: 250 of 720 replays differ from the live decision because evidence was stripped and the behaviour model has learned since (requests 1 and 2) |

**Gates** (JDK 25, `mvn -o verify spotbugs:check`, 2026-11-05): BUILD SUCCESS; 618 tests in the whole project, 0 failures
(59 of them in `dev.dwarpal.analytics`); `dev.dwarpal.analytics` coverage 99.3% line and 89.6% branch (bundle 97.4% / 90.0%);
SpotBugs with FindSecBugs: 0 bugs; `-Xlint:all -Werror` clean; source hygiene test clean (the bidi and line-separator
characters in the C9 probe are built at run time, so the source stays ASCII). No test secret is a literal: the audit
key is generated at run time.

## Requests to integration

1. **Faithful replay of recorded traffic.** Recorded requests replay without evidence (data minimisation), which
   changed 250 of 720 live decisions in the simulation. Options: an engine entry point that accepts already-verified
   facts (device verified, authentication method and time) for replay only, or `PolicyEngine.withKeyRing` so a
   replay ring with an in-process ephemeral key can vouch for facts the recorder verified at record time. Either is a
   change to `engine`, so it is yours.
2. **Point-in-time stores.** `InMemoryBehaviorHistory` is not time-indexed, so a replay sees what was learned after
   the request (look-ahead). Both policies see the same state, so the diff is unaffected, but absolute decisions drift.
   A history snapshot taken by the recorder, or `seen(..., asOf)`, would remove it.
3. **Remove a gate for replay.** Add `PolicyEngine.withoutGate(String name)` (or `forReplay()` that drops
   `FreshnessGate`), so a What-If can be built from the live engine instead of being refused as INVALID.
4. **`withCostModel` / `withAssurance`.** With these, `Sensitivity` could rebuild whole engines per grid point and
   sweep final outcomes, not only the cost-optimal action.
5. **End-to-end (plan section 8.3).** Run `WhatIf`, `Accuracy` and `AuditDecisions` on the trail produced by part A's
   encrypted store (`AuditDecisions.read` takes any `AuditCursor`, so it should work unchanged). Put a
   `RequestRecorder` in `DecisionPipeline` only behind configuration, with a per-subject quota.
6. **Threat model.** Add T1 to T12 above (or the red-team rows C1 to C12) to `docs/threat-model.md`.
7. **Project state 8.13 (M8).** Status can become "What-If replay done (Layer 5 part C)".
