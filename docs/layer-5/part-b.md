# Layer 5 part B: SOC response loop

*Notes file of the part B session (branch `layer5/part-b-response`, package `dev.dwarpal.response`). Read [layer-5-plan.md](../layer-5-plan.md) first; keep this file up to date.*

## What was built

An alert becomes a case, an analyst decides with a signed verdict, and the decision changes what the
engine does on its next decision; a false-positive verdict takes it back.

```
 part A alerts --> CaseBook (AlertSink) --> case OPEN --> verdict (signed, single use) --> Playbooks
                                                                                          |
            revoke: PolicyAdministrator (sessions) + PAM (elevation grants)  <------------+
            deny until / watch with half-life: SignalLedger --> SignalFeed --> engine (DenyListGate,
                                                                               WatchlistScorer)
 casb.dlp audit records --(keyed AuditCursor)--> DlpFeedback --> SignalLedger (holder "dlp")
```

| Class | What it does |
|---|---|
| `ResponseSettings` | The guard rails, fixed at deployment: maximum deny (7 days, hard ceiling), destructive actions per hour overall (20) and per analyst (10), the second analyst's window (1 h), privileged roles (`admin`), protected subjects (analysts, executives, break-glass accounts), shared addresses (office egress), case limits (10,000 cases, 100 alerts per case) |
| `CaseBook` | An `AlertSink`. Groups alerts by entity (the first person an alert names, otherwise its first entity) into cases OPEN, TRIAGED, CLOSED. Bounded: when full, forgets the oldest closed case that holds no actions, else drops the oldest untouched open case of lower severity than the new alert (audited), else refuses and counts. Every change is audited first (`CASE_OPENED`, `CASE_ALERT`, `CASE_STATE`, `CASE_RELEASED`, `CASE_DROPPED`) |
| `Case` | Read-only view: key entity, state, worst severity, alerts, whether actions are in force; `entities()` and `concerns(subject)` over all its alerts |
| `VerdictGate` | A verdict counts if `Verdict.verify` passes (a `SOC_ANALYST` key bound to the named analyst, over alert, analyst, outcome and time, at most 15 min old) and it is used for the first time (`NonceCache`, keyed by the signed claim, kept for 15 min + 2 x clock skew, 100,000 entries, refuses when full). The signature is checked before single use is recorded, so a forged copy cannot burn a real verdict |
| `Play` | A rule's play: up to 16 steps, each `Revoke` (person, device, session), `Deny` (person, device, address; at most 7 days) or `Watch` (log-likelihood ratio in (0, ln 1000], half-life 1 min to 90 days), applied to every entity of its kind the alert names |
| `Playbooks` | Handles verdicts. TRUE_POSITIVE runs the play; FALSE_POSITIVE lifts the case's denies and watches; BENIGN closes without action. Two-person rule, rate limits, pending verdicts that lapse, disagreement cancels. Reference plays for part A's rule ids, a watch-only play for unknown rules |
| `Enforcement` | What playbooks act through: `Enforcement.of(PolicyAdministrator, PrivilegedAccessManager, AttributeDirectory)`; revoking a person ends their elevation grants first, then their sessions; `rolesOf` = directory roles + roles active through elevation |
| `SignalLedger` | Who put which deny and watch on the `SignalFeed` (a case id, or `dlp`), so lifting one holder puts back the others' denies (time left) and watches (weight left). Remembers an entity whose putting-back failed and `reconcile()` retries |
| `WatchlistScorer` | A `RiskScorer`: the decayed watch weights on the request's person, device and address, added, capped at ln 1000; timed by the earlier of the request's time and its own clock |
| `DlpFeedback` | Reads the audit trail with a keyed `AuditCursor`; every `casb.dlp` record adds a decaying watch (half-life 7 days) on the uploader: BLOCK x4, REDACT x2, AUDIT x1.5, x2 for RESTRICTED, x1.5 for CONFIDENTIAL; at most x100 from DLP alone; 10 updates per person per hour; stops for good at a chain break; `checkpoint()` to resume |
| [`docs/runbooks/idp-down.md`](../runbooks/idp-down.md) | What to do when the identity provider is down, and when it is compromised |

The DLP weights and the reference plays' weights are assumptions (no labelled data); part C's
calibration can replace them.

## Design decisions and why

1. **A verdict is about one alert; a case groups alerts.** Part 0 signs (alert, analyst, outcome, time),
   so the verdict cannot say "case 7". The case is found from the alert. The play depends only on the
   alert's rule and the entities the alert names, never on anything the verdict could add, so an
   analyst's signature covers exactly what will happen.
2. **Playbooks act on verdicts only, never on alerts alone.** An attacker who can raise alerts (or flood
   them) can fill the case book, but nothing destructive happens without a signed human decision.
   Automatic containment for CRITICAL alerts is a possible extension; it would need its own guard rails.
3. **Two-person rule by alert, not by target.** If the alert names a privileged or protected person,
   every destructive step on that alert waits for a second analyst, including the steps on their laptop
   and address (finding B-R3). Denying a shared address needs two analysts even for ordinary people.
   Watches apply at once: they only add risk and fade. When the directory cannot say who is privileged,
   the person is treated as privileged. The second analyst must confirm the same alert within 1 h.
4. **Lifting is symmetric.** What two analysts confirmed, two analysts lift (B-R4); otherwise one stolen
   analyst key could free an attacker. Two analysts who disagree cancel the waiting verdict; nothing
   more happens.
5. **The SOC loop owns its share of the feed, not the feed.** `SignalFeed.clear` ends everything on an
   entity. A false positive must lift only what that case did (B-R2), and never the DLP evidence; the
   `SignalLedger` records shares and puts the others back. Putting back is conservative: remaining
   watches become one weight with the longest of their half-lives, so the entity never has less risk
   than the other holders gave it.
6. **Rate limits count per target, after verification.** A verdict on an alert naming 16 people costs 16
   (B-R8). Only verified verdicts consume quota, so junk sent in an analyst's name cannot exhaust it
   (the R7 lesson from Layer 3). Held-back steps leave the case TRIAGED; a new verdict retries only the
   steps not yet applied (steps are remembered per case, so a retry never adds a watch twice).
7. **No audit, no action.** Each `RESPONSE_ACTION` record (case, alert, analyst, step, target, whether
   two analysts agreed) is written before the action; the feed and the PA audit their own part too. If
   the trail fails mid-play, the remaining steps are not taken and the case does not move.
8. **Revocations are not undone.** Ended sessions stay ended; the person logs in again (with MFA). That
   is the safe side, and it is what the false-positive result says.
9. **The scorer cannot be told it is later than it is.** Watches decay with time; a request dated in the
   future would make a watch look faded (B-R1). The earlier of the two times is used.
10. **DLP feedback reads only MAC-verified records** (B-R7) and is capped below the level of a confirmed
    attack: repeated DLP blocks push a person towards step-up, but DLP alone cannot deny anyone.
11. **Under a flood, keep the severe.** A full case book drops an untouched, less severe open case for a
    more severe alert (B-R6), never a case that is triaged or holds actions.
12. **Enforcement behind an interface.** Playbooks see `Enforcement`, not the PA and PAM directly, so a
    failing PA can be simulated and a remote PA (over the engine API) can be plugged in later. A
    revocation that throws is reported as failed (the PA may still have revoked; it throws when its
    audit fails after revoking), and the verdict can be sent again.

## Threats and mitigations (STRIDE)

| # | STRIDE | Threat | Mitigation in code | Test |
|---|---|---|---|---|
| B1 | Spoofing | A forged verdict (another analyst's key, another outcome, junk, unknown key) triggers a playbook | `VerdictGate` → `Verdict.verify`: SOC_ANALYST key bound to the named analyst over exactly this claim | `aForgedVerdictDoesNothing` |
| B2 | Spoofing | A key of another purpose (an IdP key bound to the analyst's name) signs a verdict | Purpose checked by the key ring | `aVerdictSignedWithAKeyOfAnotherPurposeDoesNotCount` |
| B3 | Tampering | A captured verdict is replayed (for example to re-deny someone after a false positive) | Single use per (alert, analyst, outcome, time); retention covers the whole validity; full store refuses | `aReplayedVerdictCountsOnce`, `aFullReplayStoreRefusesRatherThanForgets` |
| B4 | Tampering | A stale or future-dated verdict | At most 15 min old, at most 2 min ahead | `staleAndFutureVerdictsAreRefused` |
| B5 | Elevation | An analyst clears (or decides) a case about themselves | Refused if the analyst is any person any alert of the case names | `anAnalystCannotDecideACaseAboutThemselves`, `r5_...` |
| B6 | Denial of service | An alert flood plus verdicts (or one stolen analyst key) locks out the company | 20 destructive actions per hour overall, 10 per analyst, counted per target; watches unaffected | `anAlertFloodCannotDenyTheWholeCompany`, `r8_...` |
| B7 | Denial of service | Junk verdicts in an analyst's name use up their quota | Quota consumed only after verification; refusals audited 20 per minute per name | `junkVerdictsInAnAnalystsNameDoNotUseUpTheirQuota` |
| B8 | Elevation / DoS | One analyst locks out a privileged account (or the office egress) | Two-person rule for destructive steps on alerts naming privileged or protected people, and on shared addresses | `privilegedAccountsNeedASecondAnalystForDestructiveSteps`, `sharedAddressesNeedTwoAnalystsTooButOrdinaryOnesDoNot`, `r3_...` |
| B9 | Elevation | One stolen analyst key lifts a deny on a confirmed attacker | Lifting what two confirmed needs two | `liftingWhatTwoAnalystsConfirmedNeedsTwoAnalysts`, `r4_...` |
| B10 | Elevation | A deny that never ends | Playbook denies at most 7 days (plays checked against the settings at start-up), the feed's own 30-day cap behind it | `aDenyEndsOnTimeAndNeverOutlastsTheMaximum` |
| B11 | Repudiation | Actions taken without a record | Audited before acting; no audit, no action; cases audited before each change | `noAuditNoAction`, `anActionThatCannotBeAuditedIsNotTaken`, `aTruePositiveRevokesDeniesAndWatchesAndTheEngineSeesIt` |
| B12 | Tampering | A false positive on one case frees the person from another case's deny | `SignalLedger` shares; interrupted lifts remembered and reconciled | `r2_...`, `anInterruptedLiftIsRememberedAndReconciled` |
| B13 | Tampering | A false positive wipes DLP evidence | DLP is its own holder | `aFalsePositiveDoesNotLiftDlpEvidence` |
| B14 | Spoofing | Forged `casb.dlp` records raise an innocent person's risk | Keyed `AuditCursor`; stops at the first break | `r7_...`, `aBrokenTrailStopsTheFeedbackForGood` |
| B15 | Denial of service | Repeated DLP findings deny a person | DLP alone capped at x100; 10 updates per person per hour | `dlpAloneNeverReachesTheLevelOfAConfirmedAttack`, `dlpUpdatesAreLimitedPerPerson` |
| B16 | Tampering | A request dated in the future hides a watch | Scorer uses the earlier of request time and its clock | `r1_...` |
| B17 | Denial of service | A flood of low alerts hides a critical one; memory exhaustion | Bounded case book; severity-aware room-making; refuse and count | `theCaseBookIsBoundedAndForgetsOnlyWhatIsSafeToForget`, `r6_...` |
| B18 | Info disclosure | Secrets or analysts' reasons leak through the scorer's explanation or audit records | Scorer evidence has numbers only; audit records carry ids, rule, step and target (alerts never copy payloads); reasons sanitised and capped | `theScorerIsSilentWithoutAWatchAndAddsUpPersonDeviceAndAddress` |
| B19 | Elevation | Directory down: a privileged person treated as ordinary | Unknown privilege = privileged | `whenTheDirectoryCannotTellWhoIsPrivilegedTwoAnalystsAreNeeded` |
| B20 | Elevation | A benign verdict closes a case while its watch stays in force | BENIGN refused when actions are in force | `aBenignVerdictCannotQuietlyKeepActionsInForce` |
| B21 | Denial of service | Enforcement unreachable mid-play | Reported as PARTIAL, case stays TRIAGED, a new verdict retries only what is missing | `enforcementDownIsReportedAndCanBeRetried` |

## Red-team findings

Each was first reproduced as a working probe: the eight probes in `ResponseRedTeamTest` were run
against the first version of each defence (7 failures and 1 error, one per finding), then the fixes
were put in and the same probes pass; they stay as regression tests. Most are attacks on the SOC
itself: turning the response loop against innocent people, or using it to free an attacker.

| # | Breach | Root cause | Fix | Test |
|---|---|---|---|---|
| B-R1 | (Tampering) A request dated 30 days ahead saw a x1000 watch (half-life 1 h) as faded: no risk factor at all | The scorer decayed the watch to the request's own time | The earlier of the request's time and the scorer's clock | `r1_aRequestDatedInTheFutureCannotMakeAWatchLookFaded` |
| B-R2 | (Tampering) Carol, denied for 24 h by case 1, was freed by a false positive on a second case about her | Undo called `SignalFeed.clear`, which ends every deny and watch on the entity | `SignalLedger`: shares per holder; a lift puts the others back with the time and weight left | `r2_aFalsePositiveOnOneCaseDoesNotFreeThePersonFromAnother` |
| B-R3 | (Elevation) One analyst revoked root's laptop and denied root's address; only root's account waited for a second analyst | The two-person rule looked at the target, not at whom the alert is about | Every destructive step on an alert naming a protected person waits | `r3_theTwoPersonRuleCoversThePrivilegedPersonsDeviceAndAddressToo` |
| B-R4 | (Elevation) A deny two analysts had confirmed was lifted by a third analyst alone: one stolen key frees an attacker | Undo needed one verdict | Lifting what two confirmed needs two | `r4_oneStolenAnalystKeyCannotLiftWhatTwoAnalystsConfirmed` |
| B-R5 | (Elevation) Ana, named second in an alert about alice, cleared the deny on herself | The self-decision check compared only the case's key entity | Any person named by any alert of the case | `r5_anAnalystNamedAnywhereInACaseCannotDecideIt` |
| B-R6 | (Denial of service) 50 LOW alerts filled the case book and the CRITICAL honeytoken alert was refused | Full meant refuse, whatever the severity | Drop the oldest untouched, less severe open case (audited `CASE_DROPPED`) | `r6_aFloodOfLowAlertsCannotShutOutACriticalOne` |
| B-R7 | (Spoofing) Five forged `casb.dlp` records, written with another key, raised alice's risk | The trail was read checking order and links only | DLP feedback requires the audit key; there is no unkeyed path | `r7_dlpRecordsWithoutAValidMacDoNotRaiseAnyonesRisk` |
| B-R8 | (Denial of service) One verdict on an alert naming 16 people revoked and denied all 16 with a limit of 6 | The rate limit counted once per verdict | Counted per destructive target | `r8_oneVerdictOnAnAlertNamingManyPeopleIsLimitedPerTarget` |

Also found while testing (not a breach): two verdicts by the same analyst on the same alert within the
same second collided in the replay store even when their outcomes differed; the single-use key now
includes the outcome.

## Tests and results

`mvn -o verify spotbugs:check` on JDK 25.0.5 (Temurin), offline: **BUILD SUCCESS**, 610 tests, 0 failures
(559 before this part, 51 new), SpotBugs and FindSecBugs clean, `-Xlint:all -Werror`.

| Test class | Tests | What it covers |
|---|---|---|
| `ResponseAbuseTest` | 13 | Abuse cases first: forged, wrong-purpose, replayed, stale and future verdicts; unknown alert; own case; alert flood against the company; junk in an analyst's name; no audit no action; audit failing mid-play; enforcement down and retry; directory down; benign over actions in force |
| `ResponseLoopTest` | 15 | Grouping into cases; a true positive revokes (a real PA session), denies and watches, and the engine's next decision is DENY; deny ends to the second; decay matches the half-life; false positive lifts and alice logs in again; benign; two-person rule, lapse, disagreement, two to lift; shared addresses; plays for unknown rules; stolen-token play; bounded case book; settings and play validation |
| `WatchAndDlpTest` | 10 | Scorer silent, additive, capped, decaying; DLP weights, repeated attempts, cap x100, per-person limit, unknown records, checkpoint resume, broken trail, DLP evidence kept after a false positive |
| `ResponseRedTeamTest` | 8 | B-R1 to B-R8 |
| `LedgerGateAndSimTest` | 5 | Interrupted lift and reconcile; ledger purge; full replay store; `Enforcement.of` with the real PA and PAM; the loop on `SimOrganisation` (seed 7, 60 users) with its signed-verdict helper |

Coverage of `dev.dwarpal.response` (JaCoCo): **97.7% of lines (677/693), 87.1% of branches (330/379)**.
Whole bundle: 97.2% lines, 89.8% branches.

The numbers in the simulated-organisation test (a legitimate request goes from not-denied to DENY and
back) measure consistency with the threat model on seed 7 with 60 users, not real-world accuracy. One
full run before the final one failed an existing gateway latency test (`latencyAddedByTheGatewayIsSmall`,
limit 50 ms) while another session's build was running; it passed on the rerun with the laptop quiet.

## Requests to integration

1. **Rule ids.** `Playbooks.referencePlays()` is keyed by `honeytoken-touched`, `stolen-token`,
   `break-glass-used`, `deny-storm`, `mfa-fatigue`, `impossible-travel-allow`, `dlp-block-spike`,
   `pam-refusals`, `audit-chain-break`. Align them with part A's actual rule ids (rules without a play
   get a watch-only play, so a mismatch is safe but weak). Part A's alerts should name the session
   (`Entity.Kind.SESSION`) for stolen-token alerts and the device for honeytoken alerts.
2. **Wire the loop.** `CaseBook` is the `AlertSink` for part A's `DetectionEngine`; `WatchlistScorer(feed,
   clock)` joins the standard scorers of the deployed engine; `DlpFeedback` polls the same audit source
   as part A, on a schedule, with the audit key, and its `checkpoint()` is stored where the audit writer
   cannot change it. `SignalLedger.purge()` and `reconcile()` go on the same schedule.
3. **Everything that writes to the feed should go through one `SignalLedger`** (playbooks, DLP feedback,
   and any direct analyst console), or a false positive may lift another writer's entry. Better still,
   a per-holder `clear` in `SignalFeed` itself would make the ledger's putting-back unnecessary (a
   change to `pip`, which this part does not own).
4. **Analyst accounts.** The self-decision rule compares the analyst id with the subject ids an alert
   names, so analysts' key bindings must use their directory subject ids, and analysts should be in
   `protectedSubjects` (a case about an analyst then needs two other analysts).
5. **Cross-part red team.** An attacker who can make part A raise alerts (by writing audit records) can
   fill the case book; destructive actions still need signed verdicts, but test that A's rules cannot be
   steered into naming the CEO with a convincing summary (alert summaries are attacker-influenced).
6. **Threat model, README, project state:** add B1 to B21 and B-R1 to B-R8; the runbook gives a
   procedure for the residual risk "break-glass needs the IdP for MFA on each admin action" (it stays a
   design limit: there is no offline MFA). New residual risks: revocations cannot be undone; the ledger
   and case book live in memory (a restart forgets which case holds which deny, though the feed's
   entries still end on their own); putting back watches merges half-lives (conservative).
7. `pom.xml` and `spotbugs-exclude.xml` needed no change for this part.
