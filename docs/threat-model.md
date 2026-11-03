# Dwarpal threat model (STRIDE), v0.9

Scope: the Policy Engine core (v0.1 to v0.6) and the Policy Administrator: sessions (v0.7, v0.8) and
privileged access (v0.8). The PEP
and the SIEM loop get their own rows when they are built.

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

## v0.7 Layer 3 (Policy Administrator: sessions)

Design threats for sessions, and how each is met.

| # | STRIDE | Threat | Mitigation in code | Test |
|---|---|---|---|---|
| S1 | Spoofing | Stolen bearer token used from the attacker's machine | Every use needs a signature by the session key (proof of possession, DPoP-style) over this exact request | `aStolenTokenIsUselessWithoutTheSessionKey` |
| S2 | Tampering | Captured request replayed inside the proof's validity | Request id is single-use per session (`NonceCache`, retention = proof age + clock skew); checked after the proof, so nobody can burn the victim's ids | `aCapturedRequestCannotBeReplayed`, `parallelUsesAreAllServedAndAParallelReplayWinsOnlyOnce` |
| S3 | Tampering | A valid proof moved to a different request (READ proof reused for WRITE) | Proof binds session, request id, subject, device, resource and action | `aProofCannotBeMovedToADifferentRequest` |
| S4 | Info disclosure | Token leaks from logs or a store dump | Only the SHA-256 of the token is stored; `SessionGrant.toString()` redacts it; audit records carry the session id only | `anAllowedLoginOpensASessionThatCanBeUsed` |
| S5 | Spoofing | Token guessed | 256-bit random tokens from `SecureRandom`; malformed tokens refused before lookup; no RNG injection point | `garbageTokensAreRefusedWithoutErrors`, `onlyWellFormedTokensReachTheStore` |
| S6 | Elevation | A session outlives the conditions it was granted under (device deny-listed, risk rises) | Continuous evaluation: the engine decides every use; a risk-driven, hard-gate or READ denial revokes the session | `continuousEvaluationRevokesTheMomentADeviceIsDenyListed` |
| S7 | Denial of service | One harmless action-specific denial (e.g. WRITE forbidden) kills a working session | Revoke only when the action was READ, a hard gate fired, or P(attack) is at least `revokeAboveRisk` | `anActionSpecificPolicyDenialDoesNotEndTheSession` |
| S8 | Elevation | Read-only session used for downloads, or a downgrade lost | Read-only checked before the engine; downgrade is permanent for the session | `aReadOnlySessionMayReadButNotDownloadAndSurvivesTheAttempt` |
| S9 | Spoofing | Stolen unlocked laptop keeps a session forever | Idle timeout 30 min; re-authentication every 8 h / 4 h / 1 h / 15 min by classification needs fresh, IdP-signed, subject- and device-bound MFA; absolute lifetime 10 h | `theStolenUnlockedLaptopIsCutOffAtTheNextReauthentication`, `afterTheReauthIntervalOnlyAFreshVerifiedMfaContinuesTheSession` |
| S10 | Spoofing | Token presented for another subject or device | Treated as theft: session revoked and audited | `aTokenPresentedFromAnotherDeviceEndsTheSession` |
| S11 | Repudiation | Sessions opened or ended without a record | `SESSION_OPENED` audited before the token is released (no audit, no session); revocations audited after removal (revocation never waits for the audit) | `noAuditNoSession`, `revocationBySessionSubjectOrDeviceIsImmediateAndAudited` |
| S12 | Denial of service | Memory exhaustion through sessions or nonces | 100,000 sessions, 5 per subject (oldest closed), 200,000 nonces; when full of live entries, refuse (fail-closed) rather than forget | `aFullStoreRefusesNewSessionsUntilOldOnesExpire`, `aFullNonceCacheRefusesRatherThanForgetsLiveEntries` |
| S13 | Denial of service | Fake login failures injected to lock users out (brute-force scorer) | Failure reports must be signed by the identity provider, recent, single-use; the subject is signed | `forgedReplayedAndStaleFailureReportsAreRefused` |
| S14 | Tampering | Revocation racing an in-flight use | Session updates go through the store atomically and never re-create a removed session | `parallelUsesAreAllServedAndAParallelReplayWinsOnlyOnce` and the store design |

Red-team pass on Layer 3 (each item first reproduced as a working exploit, now a permanent regression test):

| # | STRIDE | Breach | Root cause | Fix | Tests |
|---|---|---|---|---|---|
| R1 | Spoofing | A captured login, replayed with a new request id and the attacker's own session key, opened a session the engine counted as coming from the victim's verified laptop | The signed posture report is valid for 24 h and is not tied to any key the client holds | When a login carries signed posture, the device agent must also sign (device, request id, session key thumbprint), at most 2 min old, usable once; checked before the engine runs, so a replay is neither decided nor learned | `aReplayedLoginCannotOpenASessionForAnotherKey`, `aBindingMustBeFreshAndFromThisDevicesAgent` |
| P6 | (pipeline) | SpotBugs: the builder stored the shared audit log and an injectable random generator | Setter-style builder | The audit log is a required builder argument; the random generator is no longer injectable | SpotBugs gate |

## v0.8 Layer 3 completed (second pass on sessions; privileged access)

Second red-team pass on sessions (each first reproduced as a working probe, now a regression test in `SessionHardeningTest` or the engine tests):

| # | STRIDE | Breach | Root cause | Fix | Tests |
|---|---|---|---|---|---|
| R2 | Elevation | A resource reclassified INTERNAL to CONFIDENTIAL kept its 4 h re-authentication interval (90 min without MFA observed) | Interval fixed when the session opened | The interval in force is the shorter of the opening one and the one for the resource's classification now | `r2_reclassifyingAResourceUpwardsShortensItsOpenSessions` |
| R3 | Tampering | A login dated 3 h in the past opened a session | The PA trusted the request's timestamp (freshness gate is optional in the engine) | Sessions are live: requests more than 2 min from the PA clock are refused before the engine | `r3_requestsDatedAwayFromTheClockAreRefused` |
| R4 | Spoofing | A captured MFA proof plus the password opened a session on an agentless device | MFA proofs were bound to a device *id*, which is only a name without an agent | Key-bound MFA (`dwarpal/authentication/v3`): the identity provider signs the session key's thumbprint; the PA refuses any MFA claim not bound to the session key, at login and on every use | `r4_aCapturedMfaProofCannotBeReplayedWithAnotherKey`, `r4_insideASessionAnMfaProofForAnotherKeyIsRefused` |
| R5 | Elevation | Every employee held standing admin rights on internal apps (P-01, P-02 and P-20 granted every action) | Reference policy | Grants cover READ, WRITE and DOWNLOAD only; ADMIN needs the `admin` role (P-06), granted just in time by the PAM | `thereAreNoStandingAdminRights`, `r5_noStandingAdminEvenWithStrongMfa` |
| R6 | Denial of service | Five idle sessions counted towards the per-subject limit and were closed as 'limit', never as expired | Dead sessions only removed when used | A subject's dead sessions are closed (audited as expired) before the limit is applied; `purgeExpired()` for a scheduler | `r6_deadSessionsDoNotCountTowardsTheLimitAndAreReportedAsExpired` |
| P7 | Repudiation | A flood of refused proofs could flood the audit trail | Every refusal audited | Refusal records throttled to 20 per type and subject per minute, the rest counted | `aFloodOfRefusalsCannotFloodTheAuditTrail` |

Privileged access (part B), design threats:

| # | STRIDE | Threat | Mitigation in code | Test |
|---|---|---|---|---|
| A1 | Elevation | Standing admin rights waiting to be stolen | No grant for ADMIN without the `admin` role; the role exists only inside an approved time window (`ElevatedDirectory`) | `justInTimeAdminExistsOnlyInsideTheApprovedWindow` |
| A2 | Elevation | One person grants themselves admin | Approver must be a different person; approval signed with an `ELEVATION_APPROVER` key bound to that approver | `nobodyApprovesTheirOwnElevation` |
| A3 | Tampering | An approval reused for a longer duration, another role or another request | The approval signs request id, subject, role and duration | `anApprovalCoversExactlyWhatWasAskedAndNothingElse` |
| A4 | Spoofing | Elevation requested with weak, stale or replayed MFA | WebAuthn only, at most 5 min old, identity-provider-signed, single-use | `requestingPrivilegeNeedsFreshPhishingResistantMfaUsedOnce`, `oneMfaCeremonyServesOneRequest` |
| A5 | Elevation | Elevation outlives the need | At most 1 h (hard cap 8 h in settings); unapproved requests lapse after 30 min; revocation by grant or subject takes effect on the next decision | `anUnapprovedRequestLapses`, `revokingElevationTakesEffectOnTheNextDecision` |
| A6 | Elevation | Break-glass used quietly or by the wrong account | Only designated accounts and roles; sealed `BREAK_GLASS` credential signs role and justification, once; 30 min; SOC alerted at once; mandatory review by someone else, 'misuse' ends the grant | `breakGlassWorksAlertsAtOnceAndMustBeReviewed`, `misuseFoundInReviewEndsTheGrantAtOnce`, `breakGlassCannotBeForgedReplayedOrSelfReviewed` |
| A7 | Repudiation | Privilege granted without a record | Nothing is requested, granted or opened unless its audit record was written | `noAuditNoElevation`, `withoutAnAuditTrailThereIsNoApprovalAndNoBreakGlass` |
| A8 | Denial of service | Unbounded requests, grants or admin endpoints | Bounded stores (refuse when full); rate limits on genuine requests (5/h), approvals (20/h), break-glass (3/day); policy-install rejections audited 10/h per name, 100/h overall | `elevationRequestsAndApprovalsAreRateLimited`, `genuineApprovalsAreLimitedPerApprover`, `oneGrantCanBeRevokedAndStoresStayBounded`, `aFloodOfJunkBundlesNeitherFloodsTheAuditTrailNorLocksAnyoneOut` |

Red-team pass on part B:

| # | STRIDE | Breach | Root cause | Fix | Tests |
|---|---|---|---|---|---|
| R7 | Denial of service | Ten junk requests sent in Alice's name (no MFA) used up her 5-per-hour quota, locking her out of elevation during an incident; the same held for approvals in Bob's name and for policy installs (the requester name is not authenticated) | Rate limits counted attempts before checking who was asking | Only authenticated actions count against a person's quota (after MFA, approval or sealed-credential verification); junk is refused and its audit records and alerts are throttled; policy installs are never blocked, only the auditing of rejections is throttled | `r7_junkSentInSomeonesNameCannotUseUpTheirQuota`, `aFloodOfJunkBundlesNeitherFloodsTheAuditTrailNorLocksAnyoneOut`, `manyInventedRequesterNamesStillCannotFloodTheAuditTrail` |

## v0.9 Layer 4 part 0 (shared contracts for enforcement points)

| # | STRIDE | Threat | Mitigation in code | Test |
|---|---|---|---|---|
| E1 | Elevation | An enforcement point (or an attacker controlling one) claims roles, a lower classification or a managed device | `EdgeRequest` has no such fields; `LocalSessionAuthority` takes them from the directory; the wire schema rejects unknown members | `theSchemaIsStrict`, `everyFieldTypeIsChecked` |
| E2 | Tampering | An enforcement point switches off deny-lists or honeytokens | Threat signals come from an engine-side supplier, never from requests | `threatSignalsComeFromTheEngineSideOnly` |
| E3 | Info disclosure | Results across the network teach an attacker what to evade | `EdgeResult` carries status, reference, generic message and flags only; analyst detail stays in the audit trail | `resultsRoundTripAndHideAnalystDetail` |
| E4 | Denial of service / tampering | Malicious JSON: huge, deeply nested, million-digit numbers, duplicate keys, invalid UTF-8, lone surrogates | Own strict reader with hard limits (`JsonLimits`), bounded recursion, duplicate keys rejected, 25,000-case fuzzing | `JsonTest` |
| E5 | Spoofing | A component certificate from another CA, an expired one, none at all, or TLS 1.2 | `TlsContexts`: TLS 1.3 only, AEAD suites, client certificate required, trust store with the Dwarpal CA only; callers identified by exact principal | `TlsContextsTest` |
| E6 | Info disclosure | Session tokens in logs | `EdgeGrant` and `UseBody` redact the token in `toString` | `requestsProofsAndBodiesRoundTripExactly` |
| E7 | Tampering | Response splitting or request smuggling through header values | `EdgeHttp.safeHeaderValue` (no CR, LF, NUL; bounded length); strict token and proof parsing | `headersAreParsedStrictly`, `malformedTokensAndProofHeadersAreRefused` |

Red-team pass on part 0:

| # | STRIDE | Breach | Root cause | Fix | Tests |
|---|---|---|---|---|---|
| R8 | Tampering | A single (non-session) decision dated 3 h in the past was GRANTED | The live-clock rule lived only in the Policy Administrator | `LocalSessionAuthority.decide` refuses requests more than 2 min from its clock | `r8_singleDecisionsDatedAwayFromTheClockAreRefused` |
| R9 | Elevation | Invented headers (`X-Dwarpal-Roles`, `Dwarpal-Read-Only`, `X_Dwarpal_Subject`) would reach the application | Only the defined header names were stripped | `EdgeHttp.clientOnly` strips the whole `Dwarpal-` / `X-Dwarpal-` name spaces, case- and underscore-insensitive | `r9_everyHeaderInTheDwarpalNameSpacesIsStripped` |
| R10 | Elevation | Finance was granted every CONFIDENTIAL+ resource of any kind, including a RESTRICTED web destination (after MFA) | Reference policy P-02 had no resource-kind condition | P-02 covers private apps only (policy `2026.11.03-1`) | `resultInvariantsHold` |
| P8 | (pipeline) | SpotBugs: LDAP-injection pattern when reading a certificate's name; catching `NullPointerException` | Parsing the subject name; defensive catch | Callers compared by exact principal (no parsing); catch removed | SpotBugs gate |

## Residual risks (accepted for this layer, scheduled)

| Risk | Why accepted now | Planned in |
|---|---|---|
| ~~Request-id replay inside the freshness window~~ | Closed in v0.7 for session traffic (S2) | Done (Layer 3) |
| Hardware (TPM) attestation not verified | Needs an attestation verifier | Later layer; until then capped at AGENT_SIGNED |
| HMAC audit key cannot live in an HSM yet (key must be extractable) | Simplicity | Layer 4: KMS-backed signing of chain heads |
| Correlated scorers overcount under naive Bayes | Inherent in the model | Documented; evaluation chapter |
| Linter conflict detection is structural only | SMT out of scope | What-If replay (Layer 4) |
| PEP must treat an exception (null input) as DENY | Contract outside the engine | PEP layer contract + tests |
| ~~Admin endpoint flooding (each rejection is audited)~~ | Closed in v0.8 (A8, R7) | Done (Layer 3) |
| Per-method MFA beta values are assumptions | No peer-reviewed rates exist | Sensitivity analysis in evaluation |
| Branch protection / required checks are GitHub settings | Needs the repo owner | When the repo is created |
| Network novelty and impossible travel are correlated (double count) | Naive Bayes | Evaluation measures it |
| Scorer probabilities (P(new country given attack), Poisson rates) are assumptions | No labelled data yet | Layer 4 calibration on simulated data |
| Shared NAT with several mistyping users can look like a spray | Rates chosen for small offices | Per-IP allow-list for known office egress |
| During a failure flood, brand-new attacking IPs may go untracked (store full of recent evidence) | Bounded memory | Flood itself raises `attack-surge` and `droppedKeys`; SOC alert in Layer 4 |
| Ed25519 is not quantum-resistant | Hybrid needs a format change | Build is on JDK 25 LTS (ML-DSA verified working); hybrid Ed25519 + ML-DSA after the college submission |
| Stolen, unlocked laptop used at the victim's home with their password looks exactly like the victim (60/60 ALLOW in simulation) | Signals alone cannot separate them | Narrowed in v0.7 (S9): the window ends at the next re-authentication (at most 8 h / 4 h / 1 h / 15 min by classification), and a laptop left idle 30 min has no session to take |
| The org-wide failure counter only covers the last 2 hours of recorded time | Ring buffer | Fine for live use; What-If replay must rebuild it from the audit trail |
| An attacker who passes strong MFA from a new place gets that place learned | By design (verified) | SOC review + `InMemoryBehaviorHistory.forget` for remediation |
| MFA proofs outside sessions (single decisions straight to the engine) may still be unbound (`authentication/v2`) and replayable for 15 min | Backward compatibility for engine-only callers | Sessions require key-bound MFA (v0.8, R4); retire v2 when the enforcement point (Layer 4) always runs through the PA |
| Whoever holds a stolen token can end the victim's session by presenting it for another device (S10) | Ending a possibly stolen session is the safe side | Accepted; the victim logs in again |
| Sessions and nonces live in memory: a restart ends all sessions | Simplicity, no database yet | Layer 4 persistent store (tokens stay hashed) |
| A session opened while its subject is being revoked can survive the revocation | Open and revoke are not one transaction | Continuous evaluation denies its first use once the directory disables the account; revoke together with the directory change |
| Break-glass needs the identity provider for MFA on each admin action (P-05) | Consistency: every admin action needs fresh MFA | An offline emergency procedure for 'identity provider down' (Layer 5 runbook) |
| Approvers are any holder of an `ELEVATION_APPROVER` key; no per-role approver lists; one human with two accounts could approve themselves | Simplicity | Per-role approver groups in the admin console (Layer 6) |
| Elevation applies to all of the subject's sessions, not one device | The directory has no device context | Admin actions still need fresh MFA bound to the session key on every request (P-05 + R4), so another device without that key gains nothing |
