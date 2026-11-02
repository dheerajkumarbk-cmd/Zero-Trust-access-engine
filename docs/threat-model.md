# Dwarpal threat model (STRIDE), v0.6

Scope: the Policy Engine core. Policy Administrator, PEP and SIEM loop are added in later layers
and get their own rows then.

## Design threats (v0.1)

| # | STRIDE | Threat | Mitigation in code | Test |
|---|---|---|---|---|
| T1 | Tampering | Malicious policy file executes code via YAML deserialization (CVE-2022-1471) | `SafePolicyLoader`: SafeConstructor, global tags rejected | `cve2022_1471_...` |
| T2 | Denial of service | Alias bomb / huge / deeply nested policy file | No aliases, 256 KiB cap, depth 16, 10k nodes | `billionLaughs...`, `oversized...`, `excessiveNesting...` |
| T3 | Tampering | Duplicate key hides a second `effect:` during review | Duplicate keys rejected | `duplicateKeysAreRejected...` |
| T4 | Tampering | Typo (`efect:`) silently disables a deny rule | Strict schema | `typoInAKeyIsAnError...` |
| T5 | Tampering | Conflicting/shadowed policies | Linter gate at load and at engine build | `linterErrorsBlockDeployment`, `programmaticPolicySetsAreLintGatedToo` |
| T6 | Repudiation | Log injection via identifiers | `Validate.id` allow-list | `logInjectionThroughIdentifiersIsImpossible` |
| T7 | Spoofing | Device self-reports healthy posture | `AssuranceLevel` | `selfReportedHealthIsNotEnough...` |
| T8 | Elevation | Signal outage becomes silent ALLOW | `FailMode` has no fail-open | `unavailableSignalFailsClosed...` |
| T9 | Elevation | Engine bug / stack overflow yields ALLOW or a crash | Stage errors and `StackOverflowError` -> DENY | `unexpectedEngineError...`, `stackOverflowInACondition...` |
| T10 | Info disclosure | Reason teaches attacker what to evade | Generic `userMessage()` | `userMessageNeverReveals...` |
| T11 | Elevation | Reassuring evidence lowers a mandatory control | Monotonic outcome; policy effect is a floor | `reassuringEvidenceCannotLoosen...` |
| T12 | Tampering | One noisy scorer dominates | Per-factor cap | `oneFactorCannotDominate` |
| T13 | Tampering | Caller mutates collections after construction | Unmodifiable copies | `ImmutabilityTest` |
| T14 | Elevation | YAML "Norway problem" | Strings required | `norwayProblem...` |

## Red-team pass on v0.1: breaches found and fixed in v0.2

Every row was a **working exploit** against v0.1 (proven by a test that passed), now a permanent
regression test in `BreachRegressionTest`.

| # | STRIDE | Breach | Root cause | Fix |
|---|---|---|---|---|
| B1 | Spoofing | Cookie thief replays victim's user-agent + device id; "familiar" evidence cancelled impossible travel -> ALLOW | Symmetric clamp: cheap reassurance weighed as much as hard attack evidence | Asymmetric caps: reassurance per factor and in total (order-independent scaling) |
| B2 | Repudiation | Newline / U+2028 / bidi override in risk evidence forged lines in the analyst report | Free text never sanitised | `Sanitize.text` on evidence, reasons, descriptions, loader messages |
| B3 | Elevation | Role `Contractor` skipped a DENY rule for `contractor` | Case-sensitive label comparison | Canonical labels (`Locale.ROOT`, also defeats the Turkish-I bug) |
| B4 | Elevation | DOWNLOAD allowed under a read-only rule; step-up dropped the restriction | Restriction was an outcome level, not an obligation | Sticky `restricted` obligation + engine denies non-READ actions under it |
| B5 | Elevation | Requester declared payroll PUBLIC and themselves finance -> ALLOW | Decision attributes taken from the request | `AttributeDirectory` (PIP) is authoritative; unknown ids denied; mismatches explained |
| B6 | Spoofing | 2019-dated or future-dated request accepted | No freshness check | `FreshnessGate` (live mode; off for replay) |
| B7 | Elevation | FIRST_APPLICABLE PERMIT placed before DENY bypassed it, loaded silently | Linter blind to order shadowing; warnings non-blocking | Shadowing warning + loader fails on warnings by default |
| B8 | Elevation | A workload matching only "restricted needs step-up" got STEP_UP, so passing MFA would grant payroll | REQUIRE_STEP_UP treated as a grant; default DENY bypassed | Grant vs constraint semantics in `Effect`/`PolicySet`; constraint alone never authorises |

B8 was not in the original attack list: it surfaced while writing the B5 regression test.

## Pipeline (DevSecOps) findings

| # | Finding | Fix |
|---|---|---|
| P1 | GitHub Actions referenced by mutable tags (`@v4`), the vector of the tj-actions compromise (CVE-2025-30066) | Pinned to full commit SHAs; Dependabot keeps them updated |
| P2 | `actions/checkout` persisted the token in `.git/config` for later steps | `persist-credentials: false` |
| P3 | Project-wide SpotBugs suppression of EI_EXPOSE_REP (hid 9 findings) | Narrowed to named classes, proven by `ImmutabilityTest` |
| P4 | SpotBugs found float equality in the new aggregator | Replaced with explicit flag |
| P5 | YAML parser errors (and their stack traces) could echo policy-file content into logs | Only line/column kept; raw cause dropped |

## v0.3 defence-in-depth controls

| # | STRIDE | Threat | Control | Tests |
|---|---|---|---|---|
| D1 | Spoofing | Request claims AGENT_SIGNED / HARDWARE_ATTESTED posture | Posture counts only with an Ed25519 signature from the agent key bound to that device; capped at AGENT_SIGNED | `EvidenceAndStepUpTest` (unsigned, edited, other device, wrong key purpose, stale) |
| D2 | Spoofing | Request claims device is corporate-managed | Managed status from the device inventory (PIP) | `managedStatusComesFromInventoryNotTheRequest` |
| D3 | Spoofing | Forged or replayed "already passed MFA" claim | IdP signature bound to subject + device + time; 15-min window; future-dated ignored | `anotherUsersAuthenticationProofIsRejected`, `stolenAuthenticationProofCannotBeReplayedFromAnotherDevice` |
| D4 | Elevation | Weak MFA (push, fatigue-prone) accepted as strongly as WebAuthn | Step-up is Bayesian evidence with per-method beta; under suspicion push is insufficient | `weakAuthenticatorUnderSuspicionNeedsSomethingStronger` |
| D5 | Tampering / Repudiation | Audit history edited, deleted, reordered or rewritten | HMAC-SHA256 chain; head anchored externally; PDP clock for timestamps | `AuditLogTest` |
| D6 | Repudiation | Decisions continue while the audit trail is down | No audit, no access | `noAuditNoAccess` |
| D7 | Elevation | One admin (or one stolen admin key) changes policy | Two distinct administrators must sign; one admin with two keys counts once | `oneAdministratorAloneCannotChangePolicyEvenWithTwoKeys` |
| D8 | Tampering | Approved policy text altered before install | Approvals sign the SHA-256 of the exact text and the sequence | `textEditedAfterApprovalIsRejected`, `approvalForOneSequenceCannotBeReusedForAnother` |
| D9 | Elevation | Re-install an older, more permissive signed policy | Strictly increasing sequence | `rollbackToAnOldButValidlySignedBundleIsRefused` |
| D10 | Elevation | Device or IdP key used to approve policy | Key purpose separation | `nonAdminKeysAndStaleApprovalsDoNotCount`, `KeyRingTest` |
| D11 | Tampering | "Trojan Source" invisible bidi characters hide logic in source | Build test fails on any such character in src/.github/docs | `SourceHygieneTest` |

Found during this pass and fixed before release:
- Audit records were initially timestamped with the request's (attacker-influenced) time; now the PDP clock.
- Authentication proofs were initially not device-bound (stolen-proof replay); now bound to the device id.
- Our own sanitiser and tests contained the literal invisible characters they defend against; replaced with escapes, and the hygiene gate added.

## v0.4 Layer 2 (behavioural scorers) threats

| # | STRIDE | Threat | Control | Tests |
|---|---|---|---|---|
| L1 | Tampering | Baseline poisoning: repeated attempts make the attacker's country/device "familiar" | Only a full, non-restricted, non-degraded ALLOW is learned | `repeatedAttacksCannotPoisonTheBaseline`, `stepUpDenyRestrictedAndDegradedDecisionsTeachNothing` |
| L2 | Denial of service | Spamming DENYs in a victim's name ruins their reputation (lock-out) | Automatic bad marks only from honeytoken hits, and only on the device | `ordinaryDenialsNeverDamageTheVictimsReputation` |
| L3 | Elevation | Fail once on purpose so the Poisson model reads "typo" and lowers risk | Failure LLR clamped at >= 0; zero failures give no evidence | `bruteForceIsPoissonAndCannotBeGamedWithOneFailure` |
| L4 | Denial of service | Rotating IPs/usernames exhaust memory | Size caps + LRU on every store | `perUserValuesAreBounded`, `userCountIsBounded...`, `failureLogAndLedgerAreBoundedPerKey` |
| L5 | Tampering | Future-dated ALLOW becomes "last login" and silences impossible-travel | Learner checks request time against its own clock | `futureOrStaleRequestsAreNeverLearned` (exploit reproduced first) |
| L6 | Tampering | A scorer writes to the stores it reads | Read-only views `BehaviorHistory`, `TrustView`, `FailureView` | SAST (EI_EXPOSE_REP2 led to the fix) |
| L7 | Spoofing | Replayed IP/device id buys reassurance | Known-value evidence is reassurance, capped per factor and in total (B1) | `noveltyOrdersEvidence...`, `b1_...` |
| L8 | Elevation | Numeric blow-up (kappa = 1/0 for a perfectly regular user) | kappa capped at 20 | `perfectlyRegularUserDoesNotProduceInfiniteEvidence` |

## v0.5 second red-team pass (both layers)

Each was reproduced as a passing exploit test before the fix.

| # | STRIDE | Weakness | Fix | Tests |
|---|---|---|---|---|
| C1 | Spoofing | Typing the victim's device id (no signature) bought "known device" reassurance and the laptop's reputation; a honeytoken hit with a typed id could get the real laptop flagged | Device identity counts only when the agent signature verifies; unproven devices share one `unverified-device` value that can add risk, never remove it; `Decision.deviceVerified`; evidence verification now runs first | `unprovenDevicesAreLearnedAsOneBucket...`, `honeytokenWithAnUnprovenDeviceId...`, `cloudServerWithStolenPasswordAndSpoofedLaptopId...` |
| C2 | Repudiation / Tampering | Flooding 100k junk failures evicted password-spray evidence from the LRU store | Recent evidence is never evicted (new keys dropped and counted instead); a keyless per-minute counter sees every failure; `attack-surge` heightened-alert scorer, capped at x10 so a flood cannot lock everyone out | `floodingCannotEvictRecentAttackEvidence`, `orgWideSurge...` |
| C3 | (correctness) | Distinct values capped at 256 while logins kept counting: long-tenure roamers were punished for normal behaviour | Novelty rate measured over the last 200 logins | `roamerWhoseEveryLoginIsANewIp...`, `novelUserWhoSettlesDown...` |
| C4 | Tampering | Learning wrapped inside audit learned an ALLOW that audit had turned into DENY | `DecisionPipeline.standard` builds learning(audited(core)) in one place | `learnsWhatTheUserActuallyGotWhenAuditFails` |
| C5 | (consistency) | MFA strength assumed by the cost model and by the step-up logic could silently disagree | `AssuranceSettings.challengeMethod`; engine refuses to build if the betas differ | `costModelAndChallengeMethodMustAgreeOnMfaStrength` |
| C6 | (model fit) | Single von Mises curve averaged two daily habits into a time the user never uses and called it the most normal | Circular kernel density | `twoDailyHabitsAreBothNormalAndTheGapBetweenIsNot` |
| C7 | Denial of service | Ed25519 in the JDK costs ~1.4 ms; repeated verification of identical proofs dominated latency | Bounded cache of successful verifications only; all policy checks still run every call | `verificationCacheNeverChangesAnAnswer`; p50 3.8 -> 0.3 ms |

Robustness evidence: 3,000 fuzzed requests (no crash, no NaN, no engine error, intact audit chain);
8 threads x 250 decisions (intact chain, exact learning counts); latency test p99 < 20 ms.

## v0.6 third pass (JDK 25 migration, accuracy simulation, property tests)

| # | STRIDE | Weakness | How it was found | Fix | Tests |
|---|---|---|---|---|---|
| B9 | Elevation | Unmanaged device + SaaS (read-only grant) + ADMIN action (step-up constraint): the constraint won, the read-only flag vanished, and after WebAuthn the device got full admin access | Property test: "attack evidence never lifts a restriction" | Policy result carries `limited` separately from the winning effect; the engine restricts the session whenever the grant was read-only | `b9_aStepUpConstraintCannotEraseAReadOnlyGrant`, `aStricterConstraintKeepsTheReadOnlyFlagOfTheGrant` |
| C8 | Repudiation | Password-spray evidence kept only the latest time per (IP, account), so late-arriving events or a re-evaluated past moment lost it (18 of 60 spray logins only stepped up) | Accuracy simulation | Every failure keeps its own timestamp (bounded per IP) | `sprayEvidenceSurvivesOutOfOrderEvents`, `AccuracySimulationTest` |

Dependency scan: all 9 dependencies clean on OSV.dev (control check: snakeyaml 1.33 correctly reports CVE-2022-1471).

## Residual risks (accepted for this layer, scheduled)

| Risk | Why accepted now | Planned in |
|---|---|---|
| Request-id replay inside the freshness window | Needs PA session/nonce state | Layer 3: PA nonce cache |
| Hardware (TPM) attestation not verified | Needs an attestation verifier | Later layer; until then capped at AGENT_SIGNED |
| HMAC audit key cannot live in an HSM yet (key must be extractable) | Simplicity | Layer 4: KMS-backed signing of chain heads |
| Correlated scorers overcount under naive Bayes | Inherent in the model | Documented; evaluation chapter |
| Linter conflict detection is structural only | SMT out of scope | What-If replay (Layer 4) |
| PEP must treat an exception (null input) as DENY | Contract outside the engine | PEP layer contract + tests |
| Admin endpoint flooding (each rejection is audited) | No admin API yet | Layer 3: rate limiting |
| Per-method MFA beta values are assumptions | No peer-reviewed rates exist | Sensitivity analysis in evaluation |
| Branch protection / required checks are GitHub settings | Needs the repo owner | When the repo is created |
| Network novelty and impossible travel are correlated (double count) | Naive Bayes | Evaluation measures it |
| Scorer probabilities (P(new country given attack), Poisson rates) are assumptions | No labelled data yet | Layer 4 calibration on simulated data |
| Shared NAT with several mistyping users can look like a spray | Rates chosen for small offices | Per-IP allow-list for known office egress |
| During a failure flood, brand-new attacking IPs may go untracked (store full of recent evidence) | Bounded memory | Flood itself raises `attack-surge` and `droppedKeys`; SOC alert in Layer 4 |
| Ed25519 is not quantum-resistant | Hybrid needs a format change | Build is on JDK 25 LTS (ML-DSA verified working); hybrid Ed25519 + ML-DSA after the college submission |
| Stolen, unlocked laptop used at the victim's home with their password looks exactly like the victim (60/60 ALLOW in simulation) | Signals alone cannot separate them | Layer 3: session lifetime limits and periodic re-authentication |
| The org-wide failure counter only covers the last 2 hours of recorded time | Ring buffer | Fine for live use; What-If replay must rebuild it from the audit trail |
| An attacker who passes strong MFA from a new place gets that place learned | By design (verified) | SOC review + `InMemoryBehaviorHistory.forget` for remediation |
