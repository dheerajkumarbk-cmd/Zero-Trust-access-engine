# Dwarpal threat model (STRIDE), v1.5

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

## v1.0 Layer 4 (enforcement points and SASE edge)

Each part's full STRIDE table is in its notes file ([part A](layer-4/part-a.md), [part B](layer-4/part-b.md),
[part C](layer-4/part-c.md)). The findings below were each first reproduced as a working attack, then
fixed, then kept as a regression test. They are numbered 4A, 4B and 4C here because A1 to A8, B1 to B9 and
C1 to C8 above are older findings; the notes files use the short names.

| # | Part | STRIDE | Breach (before the fix) | Fix | Test |
|---|---|---|---|---|---|
| 4A-1 | API | Spoofing | A compromised web gateway (valid Dwarpal certificate, valid for `localhost`) answered in the API's place, said GRANTED and received session tokens and proofs | Clients pin the API's exact subject during the handshake (`TlsContexts.createPinned`) | `a1_aCompromisedComponentCannotPoseAsTheApi` |
| 4A-2 | API | Denial of service | Four slow connections (one byte short of a body, half a header line) held every worker; even the SOC's health check timed out | A deadline per worker task; the watchdog interrupts the worker, which closes its channel | `a2_slowBodiesAndSlowHeadersCannotStarveTheServer` |
| 4A-3 | API | Denial of service | A server dripping one byte every 100 ms held the client past 8 s; a 128 MB answer would have been buffered | One deadline for the whole exchange; bounded body subscriber (64 KiB) | `a3_theClientHasADeadline...` |
| 4A-4 | API | Tampering | A GRANTED answer for another request id was accepted | The answer's reference must equal the request id; the status must fit the call | `a4_anAnswerMustBelongToTheQuestion` |
| 4A-5 | API | Spoofing | `CN=GATEWAY` was the gateway (`X500Principal.equals` folds case) | Exact RFC 2253 comparison (`TlsContexts.samePrincipal`) | `a5_callerSubjectsAreComparedExactly...` |
| 4B-1 | ZTNA | Spoofing | A login without MFA, or with MFA signed by an attacker key, opened a session | `LoginGuard` at the gateway, and since integration the PA itself (X3) | `b1LoginWithoutVerifiedAuthenticationIsRefused` |
| 4B-2 | ZTNA | Info disclosure | The login endpoint opened sessions for resources the gateway does not front (a login oracle) | Logins only for routed resources | `b2LoginOnlyForResourcesThisGatewayFronts` |
| 4B-3 | ZTNA | Elevation | `POST /wiki/Admin/settings` was authorised as WRITE and changed admin settings | Case-insensitive download and admin classification | `b3RouteClassificationIsCaseInsensitive` |
| 4B-4 | ZTNA | Elevation | `GET` with `X-HTTP-Method-Override: DELETE` deleted a page under a READ grant | Override headers and `_method` refused | `b4MethodOverrideHeadersAreRefused` |
| 4B-5 | ZTNA | Info disclosure | Redirects revealed the app's internal address | `Location` rewritten to gateway-relative paths | `b5RedirectsNeverRevealTheInternalAddress` |
| 4B-6 | ZTNA | Denial of service | One user's logins filled the gateway's session table | At most 5 tracked sessions per subject | `b6OneUserCannotFillTheGatewaySessionTable` |
| 4B-7 | ZTNA | Spoofing | A captured login from a device without an agent, replayed 5 times, opened 5 sessions | Login MFA proof single-use (gateway, and since integration the PA: X4) | `b7ACapturedLoginCannotBeReplayed` |
| 4B-8 | IdP | Denial of service | One address took all 10,000 login challenge slots | 30 challenges per minute per address | `b8OneAddressCannotExhaust...` |
| 4B-9 | ZTNA | Denial of service | Four stalled login bodies held every in-flight slot; honest users got 503 (found in the integration review) | One deadline per request, body included; the slot comes back | `b9SlowBodiesCannotHoldTheInFlightSlots` |
| 4C-1 | SWG | Elevation | `2130706433`, `0x7f000001`, `127.1` passed as host names and skipped the raw-IP rule | Names with a numeric or hex last label refused | `r1_numericSpellingsOfAnIpAddressAreNotHostNames` |
| 4C-2 | SWG | Info disclosure | An allowed name resolving to 127.0.0.1 or the metadata address got a tunnel (SSRF) | Every resolved address checked; connect only to the checked address | `r2_aNameThatResolvesToAnInternalAddress...` |
| 4C-3 | SWG | Spoofing | A Cyrillic look-alike name passed as ordinary | Mixed-script labels decided as `web:malicious` | `r3_namesMixingWritingSystemsAreLookalikes` |
| 4C-4 | SWG | Denial of service | One byte per 250 ms held a connection although the read timeout was 1 s | Total time limit per head and body | `r4_aSlowTrickleCannotHoldAConnectionOpen` |
| 4C-5 | CASB | Info disclosure | 10,500 e-mail addresses pushed an AWS key out of the findings and the upload passed | Cap per finding type; truncated + REDACT becomes BLOCK | `r5_...` |
| 4C-6 | CASB | Info disclosure | A card number in UTF-16 text passed | UTF-16 recognised; other NUL-bearing content uninspectable (blocked) | `r6_...` |
| 4C-7 | CASB | Info disclosure | Zero-width spaces or full-width digits hid a card number | Any Unicode digit; invisible characters ignored | `r7_...` |
| 4C-8 | CASB | Denial of service | 2 MB of key markers took 32 s to scan (quadratic) | Linear scan; 8 MiB now 137 ms | `r8_...` |
| 4C-9 | CASB | Info disclosure | Forwarding the original bytes of a REDACTED upload undid the redaction | `GuardResult.forward(original)` | `r9_...` |
| 4C-10 | SWG | Denial of service | Under load the 503 of a busy gateway was lost (reset) | Short lingering close on the busy path | `tooManyConnectionsGetServiceUnavailable` |

Cross-part red team at integration (`CrossPartRedTeamTest`, every component through the real API over mutual TLS):

| # | STRIDE | Breach (before the fix) | Root cause | Fix | Test |
|---|---|---|---|---|---|
| X1 | Denial of service | Slow login bodies held the ZTNA gateway's slots (= 4B-9) | Part A's deadline lesson not applied in part B | Fixed in part B | `b9...` |
| X2 | Elevation | A gateway certificate asked `/v1/decisions` about the wiki and got GRANTED: no session, so no MFA at open and no proof of possession | Single decisions were allowed for every resource kind | Single decisions only for `WEB` resources (session-less browsing); private apps and SaaS data need a session | `x2_aSingleDecisionCannotStandInForASessionOnAPrivateApp` |
| X3 | Spoofing | A gateway certificate could open sessions without MFA straight at the API | MFA at login was checked only in the gateway (`LoginGuard`) | The PA requires fresh, verified, key-bound MFA at open (`allowLoginWithoutMfa()` only for engine-path tests) | `x3_aStolenGatewayCertificateCannotOpenASessionWithoutMfa`, `MfaAtOpenTest` |
| X4 | Spoofing | A captured login replayed through another gateway instance would open a second session | Single use was remembered per gateway only | The PA remembers spent login MFA proofs for every PEP | `x4_aCapturedLoginCannotBeReplayedThroughAnotherGatewayInstance` |
| X5 | Elevation | The web gateway's certificate could open and spend wiki sessions | Any PEP could ask about any resource | Every PEP caller has a required resource scope (`Caller.pepComponent("swg", "web:*")`); outside it: 403 | `x5_eachEnforcementPointStaysWithinItsOwnResources`, `ApiScopeTest` |
| X6 | Elevation | Revoking a compromised person over the API left their admin elevation running | Revocation and PAM were separate calls | Subject revocation also ends their elevation grants | `revokingASubjectOverTheApiAlsoEndsTheirElevation` |

## v1.1 Layer 5 part 0 (shared contracts for the SOC loop)

| # | STRIDE | Threat | Mitigation in code | Test |
|---|---|---|---|---|
| K1 | Tampering | A reader of the audit trail (SIEM export, detection, analytics) is fed edited, inserted, deleted or reordered records | `AuditCursor` checks sequence continuity, the link to the previous MAC and, with the key, every MAC; at the first break it stops for good | `anAlteredRecordStopsTheCursorForGood`, `gapsReorderingAndDuplicatesAreBreaksEvenWithoutTheKey`, `aChainForgedWithAnotherKeyPassesTheLinksButNotTheMacs` |
| K2 | Tampering | A truncated or rewritten trail is read as complete | `checkAgainst(anchoredHead)` | `aTruncatedOrRewrittenTrailDisagreesWithItsAnchor` |
| K3 | Denial of service / tampering | A hostile store returns huge batches or malformed payloads to steer a reader | Batches capped and checked; payloads must be flat objects of strings within limits, otherwise a break (never skipped) | `aSourceThatSendsMoreThanAskedIsNotBelieved`, `payloadsMustBeFlatObjectsOfStrings`, `anUnreadablePayloadIsABreakNotASkip` |
| K4 | Spoofing | A forged or misattributed verdict triggers a playbook | Verdicts count only when signed by a `SOC_ANALYST` key bound to the named analyst, over alert, analyst, outcome and time; at most 15 min old | `aVerdictCountsOnlyWhenItsAnalystSignedExactlyIt` |
| K5 | Info disclosure / repudiation | An alert summary forges lines in an analyst's view or carries secrets | Summaries sanitised and capped at 200 characters; alerts cite audit sequence numbers instead of copying payloads | `alertsAreBoundedAndTheirSummaryIsSafeToShow` |
| K6 | Elevation / denial of service | SOC signals used to lock people out for good, or to lower someone's risk | Denies end on their own (at most 30 days); watches only add risk, capped at x1000, and fade with a half-life; bounded store refuses rather than forgets; every change audited first | `aDenyIsNeverForeverAndOnlyEverExtendedHere`, `watchesOnlyAddRiskWithinBounds`, `theStoreIsBoundedAndRefusesRatherThanForgets`, `noAuditNoChange` |

Red-team pass on part 0:

| # | STRIDE | Breach (before the fix) | Root cause | Fix | Test |
|---|---|---|---|---|---|
| R11 | Elevation | A caller claiming to be five years ahead set a five-year deny on the CEO (still in force two years later) | `deny` measured its 30-day limit from a time the caller supplied | The feed keeps its own clock; changes take durations | `r1_aCallerCannotChooseTheTimeADenyIsMeasuredFrom` |
| R12 | Elevation | A snapshot read for a far-future time deleted every deny ending before then, and the empty result was then served from the cache for the present | Building a snapshot removed expired entries; the cache had no lower time bound | Reading never changes the store; the cache covers only the interval it was built for | `r2_readingTheFutureNeitherDeletesNorHidesDenies` |

## v1.2 Layer 5 (SOC loop: SIEM and detection, response, analytics)

Ids are prefixed by part: 5A (SIEM and detection), 5B (response loop), 5C (analytics); `R` marks a breach
found by that part's red-team pass, reproduced as a working probe before the fix. Details and design reasons
are in `docs/layer-5/part-a.md`, `part-b.md` and `part-c.md`.

### 5A SIEM and detection

| # | STRIDE | Threat | Mitigation in code | Test |
|---|---|---|---|---|
| 5A-1 | Info disclosure | A stolen disk, backup or copied store file reveals the audit trail (who accessed what, from where) | AES-256-GCM per record; the key is passed in and never written; no plaintext or key bytes in the file | `theFileHoldsNeitherPlaintextNorTheKey`, `theWrongKeyReadsNothing` |
| 5A-2 | Tampering | Bit flips, swapped records, a replayed record, a frame spliced from another store, a changed header | GCM tag over each record with sequence and store id as associated data; detected on open and on every read; writes refused afterwards | `aFlippedBitIsDetectedAndEarlierRecordsStayReadable`, `swappedRecordsAreDetected`, `aReplayedRecordIsDetected`, `aChangedStoreIdBreaksEveryRecord`, `aFileChangedAfterOpeningIsCaughtOnRead`, `aFrameAppendedWithoutTheKeyIsDamageAndAChainBreak` |
| 5A-3 | Tampering / repudiation | A trail cut back at a record boundary (invisible to the store and to the chain) | `HeadAnchor` in a separate place; the engine compares at the anchor; stale, rolled-back, rewritten or removed anchors are refused | `aTruncationAtAFrameBoundaryNeedsTheAnchor`, `aTruncatedTrailDisagreesWithItsAnchor`, `aRemovedOrRolledBackAnchorIsTamperingOnceOneExisted`, `rA1_aRestoredOldAnchorIsStaleAndStopsDetection` |
| 5A-4 | Tampering | A caller (or bug) writes a gap or a fork into the store | Only sequence + 1 linked to the previous MAC is accepted | `onlyTheNextRecordOfTheChainIsAccepted` |
| 5A-5 | Denial of service | Huge records or a corrupt length field exhaust memory | Records at most 1 MiB, refused before writing; frame length bounds-checked before allocating; batches capped | `oversizedRecordsAreRefusedBeforeAnythingIsWritten`, `aFrameLengthOutOfBoundsIsDamageNotAHugeAllocation`, `batchesAreCappedLikeEverySource` |
| 5A-6 | Tampering | Two writers on one file interleave frames | File lock on a byte past the end (readers never blocked on Windows) | `aSecondWriterOnTheSameFileIsRefused` |
| 5A-7 | Spoofing / tampering | A field value or name forges another field or another event in the SIEM (CEF `\|` `=`, syslog `]` `"`, new lines, bidi) | Per-format escaping of names and values; names mapped to safe, distinct keys; one event per line | `cefCannotBeForged`, `cefHeaderFieldsEscapePipesAndBackslashes`, `syslogCannotBeForged`, `jsonLinesAreLosslessAndOneLine`, `namesMapToDistinctSafeKeys` |
| 5A-8 | Denial of service / repudiation | One huge value pushes the subject or address out of a size-capped SIEM line | Values cut at 2,048, lines at about 32 KiB, short fields first, no split surrogate pairs | `aHugeValueCannotPushOutTheSubject`, `cuttingNeverSplitsASurrogatePair` |
| 5A-9 | Spoofing | Detection fed forged or edited records raises alerts against innocent people, or misses real ones | Keyed cursor built by the engine; a break raises one CRITICAL alert and stops for good | `aRecordForgedWithAnotherKeyIsNeverDetectedOn`, `aChainBreakRaisesOneCriticalAlertAndStopsForGood`, `aSourceThatThrowsIsABreakNotAnEnd` |
| 5A-10 | Denial of service (SOC) | An alert flood drowns the analysts or buries a real CRITICAL alert | Per-entity dedup with roll-up; per-rule hourly caps (separate cap for CRITICAL rules); one `alert-flood` alert | `repeatsFoldIntoOneAlertAndARollUpWithTheirCount`, `aDenyFloodCannotBuryABreakGlassAlert`, `rA3_honeytokenFloodsAreCappedWithOneCriticalFloodAlert` |
| 5A-11 | Denial of service / evasion | Detection state flooded with invented entities, so the real attacker is not tracked, or memory runs out | Bounded state; idle keys dropped, live keys never forgotten; refusals counted and alerted | `floodingDetectionStateRaisesStateFull`, `windowCounterIsBounded`, `boundedUnderAMillionEvents` |
| 5A-12 | Elevation (SOC as a weapon) | Junk requests in the CEO's name make detection point at the CEO, so a playbook locks the CEO out | `deny-storm-subject` names the person as target plus the attacking addresses, and says it is not evidence against them; request 4 to part B | `junkInSomeonesNameNamesTheAttackingAddresses` |
| 5A-13 | Evasion | An attacker resets a counting rule between attempts (MFA fatigue) | Only an ALLOW ends a step-up run | `rA2_aDenyBetweenPushesDoesNotResetMfaFatigue`, `mfaFatigueNeedsFivePushesWithoutAnAllow` |
| 5A-14 | Repudiation / info loss | Alerts lost when the case book is full or down | Refused alerts kept and retried; reading stops while any wait; `lost` counted | `alertsTheSinkRefusesAreKeptAndNothingMoreIsReadUntilItAccepts`, `aSinkThatThrowsIsTreatedAsRefusing` |
| 5A-15 | Tampering | A factor name forged inside free text makes a decision look like impossible travel | Index search only at a factor boundary; number length capped; NaN and non-positive refused; no ReDoS-prone regex | `onlyARealPositiveTravelFactorCounts` |
| 5A-16 | Info disclosure | Alerts or exceptions carry secrets or payload text | Summaries carry ids and counts only; damage messages name record numbers only; invalid ids hashed | `oddIdsInARecordStillCountAndNeverReachAnAlertRaw` |

Red-team pass:

| # | STRIDE | Breach (before the fix) | Root cause | Fix | Test |
|---|---|---|---|---|---|
| 5A-R1 | Tampering | An attacker who can write the store and the anchor directory cut the store back to record 5 and put back a copy of the anchor file from record 5. After a restart, the trail agreed with "its" anchor: five records (all `BREAK_GLASS_USED`) gone without trace | A new `HeadAnchor` instance has no memory of later anchors, and an anchor carried no notion of age | Every write renews the anchor's time (a heartbeat, even when the head is unchanged); `readFresh(maxAge)` refuses an anchor older than the schedule allows (or dated in the future), and detection treats that as `audit-anchor-mismatch` | `rA1_aRestoredOldAnchorIsStaleAndStopsDetection`, `rA1_aLiveAnchorStaysFreshOnAQuietTrail` |
| 5A-R2 | Evasion | 40 MFA pushes to the CEO in 15 minutes raised no alert: the attacker sent one deliberately bad request (from Tor, so DENY) after every fourth push | The fatigue rule reset its count on any decision that was not a STEP_UP, including a DENY the attacker could cause at will | Only an ALLOW (a successful decision for that person) ends a run | `rA2_aDenyBetweenPushesDoesNotResetMfaFatigue` |
| 5A-R3 | Denial of service (SOC) | Someone who knows a honeytoken's id sent 2,000 requests with invented device ids: 2,000 CRITICAL alerts, none throttled (alert fatigue, and part B's playbooks run per alert) | CRITICAL alerts were exempt from throttling, and the honeytoken dedup key includes the device | CRITICAL rules get their own cap (200 per rule per hour), then one CRITICAL `alert-flood` alert; the rest are counted | `rA3_honeytokenFloodsAreCappedWithOneCriticalFloodAlert` |

### 5B Response loop

| # | STRIDE | Threat | Mitigation in code | Test |
|---|---|---|---|---|
| 5B-1 | Spoofing | A forged verdict (another analyst's key, another outcome, junk, unknown key) triggers a playbook | `VerdictGate` → `Verdict.verify`: SOC_ANALYST key bound to the named analyst over exactly this claim | `aForgedVerdictDoesNothing` |
| 5B-2 | Spoofing | A key of another purpose (an IdP key bound to the analyst's name) signs a verdict | Purpose checked by the key ring | `aVerdictSignedWithAKeyOfAnotherPurposeDoesNotCount` |
| 5B-3 | Tampering | A captured verdict is replayed (for example to re-deny someone after a false positive) | Single use per (alert, analyst, outcome, time); retention covers the whole validity; full store refuses | `aReplayedVerdictCountsOnce`, `aFullReplayStoreRefusesRatherThanForgets` |
| 5B-4 | Tampering | A stale or future-dated verdict | At most 15 min old, at most 2 min ahead | `staleAndFutureVerdictsAreRefused` |
| 5B-5 | Elevation | An analyst clears (or decides) a case about themselves | Refused if the analyst is any person any alert of the case names | `anAnalystCannotDecideACaseAboutThemselves`, `r5_...` |
| 5B-6 | Denial of service | An alert flood plus verdicts (or one stolen analyst key) locks out the company | 20 destructive actions per hour overall, 10 per analyst, counted per target; watches unaffected | `anAlertFloodCannotDenyTheWholeCompany`, `r8_...` |
| 5B-7 | Denial of service | Junk verdicts in an analyst's name use up their quota | Quota consumed only after verification; refusals audited 20 per minute per name | `junkVerdictsInAnAnalystsNameDoNotUseUpTheirQuota` |
| 5B-8 | Elevation / DoS | One analyst locks out a privileged account (or the office egress) | Two-person rule for destructive steps on alerts naming privileged or protected people, and on shared addresses | `privilegedAccountsNeedASecondAnalystForDestructiveSteps`, `sharedAddressesNeedTwoAnalystsTooButOrdinaryOnesDoNot`, `r3_...` |
| 5B-9 | Elevation | One stolen analyst key lifts a deny on a confirmed attacker | Lifting what two confirmed needs two | `liftingWhatTwoAnalystsConfirmedNeedsTwoAnalysts`, `r4_...` |
| 5B-10 | Elevation | A deny that never ends | Playbook denies at most 7 days (plays checked against the settings at start-up), the feed's own 30-day cap behind it | `aDenyEndsOnTimeAndNeverOutlastsTheMaximum` |
| 5B-11 | Repudiation | Actions taken without a record | Audited before acting; no audit, no action; cases audited before each change | `noAuditNoAction`, `anActionThatCannotBeAuditedIsNotTaken`, `aTruePositiveRevokesDeniesAndWatchesAndTheEngineSeesIt` |
| 5B-12 | Tampering | A false positive on one case frees the person from another case's deny | `SignalLedger` shares; interrupted lifts remembered and reconciled | `r2_...`, `anInterruptedLiftIsRememberedAndReconciled` |
| 5B-13 | Tampering | A false positive wipes DLP evidence | DLP is its own holder | `aFalsePositiveDoesNotLiftDlpEvidence` |
| 5B-14 | Spoofing | Forged `casb.dlp` records raise an innocent person's risk | Keyed `AuditCursor`; stops at the first break | `r7_...`, `aBrokenTrailStopsTheFeedbackForGood` |
| 5B-15 | Denial of service | Repeated DLP findings deny a person | DLP alone capped at x100; 10 updates per person per hour | `dlpAloneNeverReachesTheLevelOfAConfirmedAttack`, `dlpUpdatesAreLimitedPerPerson` |
| 5B-16 | Tampering | A request dated in the future hides a watch | Scorer uses the earlier of request time and its clock | `r1_...` |
| 5B-17 | Denial of service | A flood of low alerts hides a critical one; memory exhaustion | Bounded case book; severity-aware room-making; refuse and count | `theCaseBookIsBoundedAndForgetsOnlyWhatIsSafeToForget`, `r6_...` |
| 5B-18 | Info disclosure | Secrets or analysts' reasons leak through the scorer's explanation or audit records | Scorer evidence has numbers only; audit records carry ids, rule, step and target (alerts never copy payloads); reasons sanitised and capped | `theScorerIsSilentWithoutAWatchAndAddsUpPersonDeviceAndAddress` |
| 5B-19 | Elevation | Directory down: a privileged person treated as ordinary | Unknown privilege = privileged | `whenTheDirectoryCannotTellWhoIsPrivilegedTwoAnalystsAreNeeded` |
| 5B-20 | Elevation | A benign verdict closes a case while its watch stays in force | BENIGN refused when actions are in force | `aBenignVerdictCannotQuietlyKeepActionsInForce` |
| 5B-21 | Denial of service | Enforcement unreachable mid-play | Reported as PARTIAL, case stays TRIAGED, a new verdict retries only what is missing | `enforcementDownIsReportedAndCanBeRetried` |

Red-team pass:

| # | Breach | Root cause | Fix | Test |
|---|---|---|---|---|
| 5B-R1 | (Tampering) A request dated 30 days ahead saw a x1000 watch (half-life 1 h) as faded: no risk factor at all | The scorer decayed the watch to the request's own time | The earlier of the request's time and the scorer's clock | `r1_aRequestDatedInTheFutureCannotMakeAWatchLookFaded` |
| 5B-R2 | (Tampering) Carol, denied for 24 h by case 1, was freed by a false positive on a second case about her | Undo called `SignalFeed.clear`, which ends every deny and watch on the entity | `SignalLedger`: shares per holder; a lift puts the others back with the time and weight left | `r2_aFalsePositiveOnOneCaseDoesNotFreeThePersonFromAnother` |
| 5B-R3 | (Elevation) One analyst revoked root's laptop and denied root's address; only root's account waited for a second analyst | The two-person rule looked at the target, not at whom the alert is about | Every destructive step on an alert naming a protected person waits | `r3_theTwoPersonRuleCoversThePrivilegedPersonsDeviceAndAddressToo` |
| 5B-R4 | (Elevation) A deny two analysts had confirmed was lifted by a third analyst alone: one stolen key frees an attacker | Undo needed one verdict | Lifting what two confirmed needs two | `r4_oneStolenAnalystKeyCannotLiftWhatTwoAnalystsConfirmed` |
| 5B-R5 | (Elevation) Ana, named second in an alert about alice, cleared the deny on herself | The self-decision check compared only the case's key entity | Any person named by any alert of the case | `r5_anAnalystNamedAnywhereInACaseCannotDecideIt` |
| 5B-R6 | (Denial of service) 50 LOW alerts filled the case book and the CRITICAL honeytoken alert was refused | Full meant refuse, whatever the severity | Drop the oldest untouched, less severe open case (audited `CASE_DROPPED`) | `r6_aFloodOfLowAlertsCannotShutOutACriticalOne` |
| 5B-R7 | (Spoofing) Five forged `casb.dlp` records, written with another key, raised alice's risk | The trail was read checking order and links only | DLP feedback requires the audit key; there is no unkeyed path | `r7_dlpRecordsWithoutAValidMacDoNotRaiseAnyonesRisk` |
| 5B-R8 | (Denial of service) One verdict on an alert naming 16 people revoked and denied all 16 with a limit of 6 | The rate limit counted once per verdict | Counted per destructive target | `r8_oneVerdictOnAnAlertNamingManyPeopleIsLimitedPerTarget` |

### 5C Analytics

| # | STRIDE | Threat | Mitigation in code | Test |
|---|---|---|---|---|
| 5C-1 | Tampering | A What-If run through the live pipeline poisons the behaviour model and the audit trail | Only `PolicyEngine` accepted; no API takes a `DecisionPoint` | `AnalyticsRedTeamTest.c1_*` |
| 5C-2 | Spoofing | A recorded request claims a lower classification to hide a new RESTRICTED grant | Classification from the directory; unknown = RESTRICTED | `c3_*`, `c3b_*` |
| 5C-3 | Information disclosure | Recorder keeps posture and login proofs that can be replayed | Evidence stripped; `RecordedRequest` refuses evidence | `c5_*` |
| 5C-4 | Information disclosure | A report leaks request ids, addresses, devices or evidence | Change and Observation have no such fields; reports built only from ids, counts and rates | `c4_*` |
| 5C-5 | Information disclosure | A recorder dump reveals the honeytoken list | Signal snapshots are not recorded | design 4; `RecordedRequest` components |
| 5C-6 | Denial of service | One account floods the recorder so What-If sees only the attacker's traffic | Per-subject quota, refusals counted; window stated in `stats()` | `c6_*` |
| 5C-7 | Denial of service | Huge inputs exhaust memory (replays, observations, grids, report lines) | Limits: 200,000 replayed requests, 10,000 changes kept (all counted), 1,000,000 observations, 1,000 grid points, 64 sections, 2,000 lines, 400-character values | `manyChangesAreCountedButListBounded`, `tooManyRequestsRefused`, `limits`, `c9_*`, `c12_*` |
| 5C-8 | Repudiation / tampering | Forged audit records feed the analytics (SOC as a target) | `AuditCursor` with the key; reading stops at the first break and the source statement says so | `c11_*`, `AuditDecisionsTest` |
| 5C-9 | Tampering (log forging) | Hostile text forges report lines or hides text with bidi controls | `Sanitize.text` on every label, value, title and description; JSON escaped | `c9_*` |
| 5C-10 | Elevation of privilege | A What-If reports "no change" for an edit that grants access, so a reviewer approves it | Freshness gate detected (INVALID); lint-failing proposals refused; sensitive grants listed first | `c2_*`, `c10_*`, `grantToRestrictedResourceIsFlagged` |
| 5C-11 | Repudiation (of numbers) | A number quoted without its data is read as real-world accuracy | `DataSource` mandatory in every report, statement printed first with a caveat | `dataSourceStatementsAlwaysCarryACaveat`, `reportStatesItsSourceAndValidity` |
| 5C-12 | Tampering (silent failure) | A recording failure changes or blocks access | Recorder returns the delegate's decision; failures only counted | `recorderFailureNeverChangesTheDecision` |

Red-team pass:

| # | Breach | Root cause | Fix | Test |
|---|---|---|---|---|
| 5C-R1 | What-If with side effects: replaying through a `DecisionPoint` given the live pipeline appended audit records and learned the replayed logins | API accepted any decision point | WhatIf takes a `PolicyEngine` only; test checks audit, history, trust and signals unchanged | `c1_replayThroughThePipelineWouldLearnAndAudit_whatIfAcceptsOnlyThePureEngine` |
| 5C-R2 | An engine with a live `FreshnessGate` denied every historical request under both policies: a three-grant payroll edit showed 0 changes | The one clock reader in the engine | Runs where the gate fired are INVALID, with the reason in the report | `c2_freshnessGateWouldHideTheDiff_replayIsMarkedInvalid` |
| 5C-R3 | A recorded request claiming `payroll` was INTERNAL hid a new grant to a RESTRICTED resource; an unknown resource was not flagged either | Classification read from the request | Directory lookup; unknown counts as RESTRICTED; ADMIN gains flagged too | `c3_*`, `c3b_*`, `c3c_*` |
| 5C-R4 | Report leaking request data (ids, addresses, devices) | Risk of copying request fields into reports | Change/Observation carry only ids that say who gains what; checked over every request of the simulation against every report's text and JSON | `c4_reportsCarryNoRequestIdsAddressesDevicesOrEvidence` |
| 5C-R5 | Recorder kept posture and authentication proofs (replayable credentials) | Whole request kept | Evidence stripped; record type refuses evidence | `c5_recorderStripsSignedEvidence` |
| 5C-R6 | One account sending 5,000 requests would evict all other traffic from a FIFO recorder | No per-subject bound | Per-subject quota, refusals counted | `c6_floodingSubjectCannotEvictOthers` |
| 5C-R7 | No legitimate traffic gave "0% false alarms" and NaN in JSON | 0/0 reported as 0 | Undefined rates are "n/a" / null; empty data refused | `c7_noLegitimateTrafficIsNotZeroFalseAlarms` |
| 5C-R8 | Hard-gate denials ranked as most benign on the ROC (posterior = prior) | Posterior used as the score | Score = outcome, then posterior | `c8_gateDenialsRankAsMostSuspicious` |
| 5C-R9 | A description with a newline forged an "Accuracy: detection rate: 1.0" line; bidi controls | Free text in reports | Sanitised and cut everywhere; bounded reports | `c9_hostileTextCannotForgeReportLines` |
| 5C-R10 | A proposal with linter errors would be "replayed" and reported | No check | `withPolicySet` lint gate: refused | `c10_proposalWithLinterErrorsIsRefused` |
| 5C-R11 | A record written into the store without the key, claiming P(attack) = 0, would enter the analysis | SOC as a target | Keyed `AuditCursor`; reading stops at the break and the source says "chain broken after sequence N" | `c11_forgedAuditRecordsStopTheReaderAndAreNotUsed` |
| 5C-R12 | Impossible inputs (k > n, NaN exposure, beta 1.5, empty or huge grids, infinite factors, p = 1 with beta = 0 giving 0/0) | Unchecked numbers | Validation everywhere; 0/0 in step-up resolution stays strict | `c12_estimatorsRefuseImpossibleInputs` |

### Integration (cross-part)

| # | STRIDE | Threat or breach | Mitigation in code | Test |
|---|---|---|---|---|
| 5I-1 | Elevation | Four playbooks were keyed by names no detection rule raised (`deny-storm`, `pam-refusals`, `stolen-token`, unmatched health alerts), so their alerts only ever got the cautious default | Playbooks keyed by part A's rule ids; a test fails if any rule lacks a play or any play lacks a rule | `everyRuleHasItsOwnPlayAndEveryPlayHasARule` |
| 5I-2 | Tampering / denial of service | Rules matched other packages' wording ("possible token theft", the rendering of risk factors): rewording a message silently disabled detection | Machine-readable `cause` on revocations and `signals` on decisions; rules use them first, old wording only for older trails | `tokenTheftIsMatchedOnTheCauseNotTheWording`, `travelIsMatchedOnTheSignalNames`, `decisionsOnTheSimulatedOrganisationCarrySignals` |
| 5I-3 | Denial of service | After a restart the audit writer started again at sequence 1, the encrypted store refused it, and every decision became a deny | `AuditLog(key, sink, head)` continues from the store's verified head; a stale head is refused (no fork) | `afterARestartTheWriterContinuesTheEncryptedTrailAndAStaleHeadIsRefused` |
| 5I-4 | Elevation (against innocent people) | An attacker floods the trail with denied requests in the CEO's name; part A raises a deny-storm alert naming the CEO; an analyst confirms it | The play denies the sending address only and adds a small watch on the CEO (x10, fading); the CEO is protected (two analysts) | `junkInTheCeosNameBlocksTheSenderButNeverLocksOutTheCeo` |
| 5I-5 | Tampering | A What-If replayed on the live engine: the freshness gate called every old request stale and hid a dangerous change | `WhatIf` replays on `PolicyEngine.forReplay()` (drops only the clock-reading gate; live engine unchanged) | `c2_freshnessGateWouldHideTheDiff_replayUsesAReplayCopy` |
| 5I-6 | Repudiation / tampering | Detection or analytics over the encrypted store differs from the trail it holds | Same alerts and same decision entries from the store as from memory; anchor checked | `theEncryptedStoreFeedsDetectionAndAnalyticsExactlyLikeTheTrailItHolds` |

## v1.3 Layer 5.2 part 0 (shared contracts for the SOC platform)

| # | STRIDE | Threat | Mitigation in code | Test |
|---|---|---|---|---|
| P1 | Spoofing | A collected event (syslog, cloud export) poses as Dwarpal's own verified audit record | `SecurityEvents.toAuditFields` refuses `VERIFIED_AUDIT` and the native dataset; reading refuses a `SECURITY_EVENT` record that claims either | `aCollectedEventCanNeverPoseAsDwarpalsOwnRecord` |
| P2 | Spoofing / elevation | The unauthenticated firewall collector passes its lines off as signed endpoint telemetry, or another component writes events for a dataset | A `SECURITY_EVENT` record counts only when written by `collector:<its dataset>` | `aCollectorCanOnlyWriteItsOwnDataset` |
| P3 | Tampering | A malformed or crafted event record is guessed into something (wrong category, smuggled entities) | Every field required and checked; entities are ids that cannot contain the separators; at most 16; refused, never guessed | `malformedSecurityEventRecordsAreRefusedNotGuessed` |
| P4 | Info disclosure / repudiation | Event text forges lines in an analyst's view; huge values exhaust memory | Field names restricted, values sanitised and cut at 1,024 characters, at most 64 fields, immutable | `eventsAreBoundedAndTheirTextIsSafeToShow` |
| P5 | Tampering | Collected events edited after collection | Each event is written into the keyed audit chain before anything reads it, and read back only through the keyed cursor | `aCollectedEventComesBackFromTheVerifiedChainExactlyAsItWent` |
| P6 | Elevation (against innocent people) | Anyone on the network sends a syslog line naming the CEO and a playbook acts on it | Provenance on every event; `COLLECTED` is not `actionable`; ranked alerts carry `actionable`; rule for parts D to F: no destructive action on collected evidence alone | `eventsAreBoundedAndTheirTextIsSafeToShow`, `rankedAlertsAreBoundedAndSayWhetherAnyoneMayActOnThem` |
| P7 | Elevation | Risk lowered by the entity's own activity or by a negative contribution | Contributions only add (weight at least 0); scores 0 to 100 with a level that must agree | `riskOnlyEverAddsAndAlwaysExplainsItself` |
| P8 | Elevation | An unknown device ranks as harmless because nobody catalogued it | Unknown assets get the deployment's default criticality and are marked unknown | `unknownAssetsAreNeverSilentlyHarmless` |
| P9 | Spoofing / tampering | Endpoint telemetry forged, edited, moved to another device, replayed or reused from a posture signature | Batches signed by the device agent key bound to that device over device, batch number, time and the body's SHA-256, under their own message domain | `everyEndpointBatchIsSignedByItsOwnDeviceAndNumberedInOrder` |

Red-team pass on part 0: the abuse tests above were written first as probes against the contracts; none found a
breach in the contracts as designed. One defect was found in the test code itself (a raw bidirectional-override
character written into a test file, which the source hygiene check forbids) and replaced by an escape. Checks that
belong to the collectors (single-use batch numbers, event time against collection time, per-source quotas) are
part D's and must be reproduced there.

## v1.4 Layer 5.2 (SOC platform: SIEM platform, UEBA, SOAR and SOC API)

Ids are prefixed by part: 5D (SIEM platform), 5E (UEBA and prioritisation), 5F (SOAR, cases and SOC API); `R`
marks a breach found by that part's red-team pass, reproduced as a working probe before the fix. Details are in
`docs/layer-5-2/part-d.md`, `part-e.md` and `part-f.md`. The rows keep each part's own ids (D, E, F).

### 5D SIEM platform

#### Threats

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

#### Red-team findings

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

### 5E UEBA and prioritisation

#### Threats

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

#### Red-team findings

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

### 5F SOAR, cases and SOC API

#### Threats

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

#### Red-team findings

*(each reproduced as a working probe first, then fixed, then kept as a regression test)*

| # | STRIDE | Breach (before the fix) | Root cause | Fix | Test |
|---|---|---|---|---|---|
| F-R1 | Denial of service (against the CEO) | A forged syslog line naming the CEO, confirmed by one analyst who believed it, put a x1000 watch on her (watch-only mode kept the play's watches as written: the probe measured log-odds 6.9 instead of at most 2.3); a few forged lines a day could keep her locked out without any destructive step | Watch-only mode removed destructive steps but trusted the watches' weights, and nothing limited repetition | On collected evidence a watch is at most x10 with a half-life of at most one day, and each entity gets at most one such watch a day (refused, audited, otherwise); one a day never sums past x100 | `SoarRedTeamTest.forgedSyslogLinesCannotLockTheCeoOutThroughWatches` |
| F-R2 | Elevation of privilege | One analyst confirmed a verified alert that named only the CEO's laptop, and the laptop was denied, its sessions ended and it was isolated (status `APPLIED` with one verdict) | Part B's two-person rule looks only at the people an alert names | Devices owned by a protected person (asset catalogue) or of criticality 5 need two analysts before part B sees the verdict; the same analyst twice, a different alert or a disagreeing second analyst do not count; the wait lapses after part B's second-analyst window | `SoarRedTeamTest.oneAnalystCannotIsolateTheCeosLaptopThroughAnAlertNamingOnlyTheDevice`, `aSecondAnalystWhoDisagreesCancelsTheProtectedDeviceWait` |
| F-R3 | Information disclosure | A search for "subject = ben" by ana hid ben's events but answered `"matched":4,"truncated":true,"hidden":3`, so she could count a colleague's activity | Hidden events were left out of the list but not out of the numbers | When anything is hidden, `matched` is what is shown, `hidden` is gone from the answer, `truncated` refers to the shown list; the audit record keeps the hidden count | `SocApiRedTeamTest.searchDoesNotRevealHowManyEventsAboutColleaguesMatched` |
| F-R4 | Information disclosure | Reading alice's case showed `"links":["case-1"]`, the id of a case about ben that shares an address; the timeline said the same | Links were computed for the whole SOC, not for the reader | Links and LINKED timeline entries are filtered by the reader's visibility | `SocApiRedTeamTest.caseLinksDoNotRevealCasesTheReaderCannotSee` |

Probes that held from the start and stay as regression tests: a forged syslog line never isolates the CEO's laptop; an analyst cannot act on, read or annotate her own case (in the SOAR and through the API); an analyst cannot read a colleague's case through any endpoint, and "not yours" looks like "does not exist"; a playbook file without guard rails does not load whoever signed it; no endpoint revokes, denies, isolates or releases without a verdict; a collected alert cannot ride on a case decided in full mode.

### 5.2 Integration (cross-part)

Run on the whole SOC with all six parts wired together on the simulated organisation (seed 7, 60 users): tests
`SixPartEndToEndTest` and `SocCrossPartRedTeamTest`. `(F)` marks a breach that was reproduced as a working probe
on the integrated build before it was fixed.

| # | STRIDE | Threat or breach | Mitigation in code | Test |
|---|---|---|---|---|
| 5.2I-1 | Denial of service / evasion (F) | A flood that overflowed a collector's queue hid its own overflow report: the report waited at the back of 10,000 queued events, behind the source quota, for hours | The loss is reported first, at the front of the next poll | `aFloodFromOneSourceIsRefusedAndReportedWhileAnotherSourcesEventStillArrives`, `aFloodFillsOnlyTheCollectorsOwnQueueAndTheLossIsReported` |
| 5.2I-2 | Elevation / repudiation (F) | The API hid a case about an analyst from non-lead colleagues, but the SOAR itself did not check: a script or console calling it directly could let a colleague close the case of a friend | `CaseManager.mayDecide`: never one's own case, and a case about any analyst only by a lead; checked inside `Soar.handle` | `anAnalystCannotActOnOrReadACaseAboutThemselvesThroughAnyDoor` |
| 5.2I-3 | Tampering / denial of service | Two engines on one trail (part A's rules and part D's copies of them) raise two alerts for one attack | Part D's copies live in a file that is not loaded by default; the default rules only cover what part A cannot see (cross-source and health) | `theDefaultRulesLoadCleanAndCoverTheCrossSourceAttacksWhilePartAKeepsItsOwnRules`, `partARulesExpressedInTheLanguageAgreeWithPartAOnTheSameTrail` |
| 5.2I-4 | Elevation (against innocent people) | Forged syslog about the CEO's laptop opens a case and, once an analyst confirms it, isolates the laptop | Collected evidence is ranked, not actionable; the play for it is watch only; nothing is isolated, revoked or denied | `forgedFirewallLinesAboutTheCeoOpenACaseAndAWatchButNeverIsolateTheLaptop` |
| 5.2I-5 | Elevation (against innocent people) | Forged cloud logs make a colleague look like an exfiltrator | Cloud alerts are P2 at most (capped), not actionable; confirming them changes nothing destructive | `forgedCloudLogsAboutAnInnocentPersonCannotTriggerAnythingDestructive`, `cloudExfiltrationIsP2NotP1BecauseItRestsOnCollectedEvidenceOnly` |
| 5.2I-6 | Elevation | A playbook file removes the guard rails (isolate on a collected-only rule) | Strict lint against the rule catalogue's evidence classes; two-person signed install | `aPlaybookFileThatRemovesTheGuardRailsIsRefusedWhateverTheRuleBook` |
| 5.2I-7 | Spoofing | Genuine signed telemetry of the device, or an edited acknowledgement, is passed off as the sensor's confirmation of isolation | The acknowledgement must match the exact command body and carry a valid device signature; once only | `telemetryCannotBePassedOffAsTheSensorsIsolationAcknowledgement` |
| 5.2I-8 | Tampering / evasion | Backdated lines open windows in the past; future lines close everyone's windows | Ingestion refuses lines more than 5 minutes ahead and more than 7 days behind; late lines are flagged and cannot raise alerts | `backdatedAndFutureLinesAreRefusedAndOpenNoWindowsInThePast` |
| 5.2I-9 | Elevation (drift) | The rule catalogue (what a playbook may do on a rule) and the ranker (whether an alert is actionable) disagree after a rule is added | Checked on every alert raised in the simulation: collected-only rules never actionable, verified rules always actionable, mixed rules actionable exactly when some evidence is verified | `whatCannotBeActedOnIsNeverRankedActionableAndTheCatalogueAgreesWithTheRanker` |
| 5.2I-10 | Repudiation | A signed verdict is used twice, or by two consumers that share one replay store | Each consumer (part F's SOAR, part E's UEBA) has its own gate on the same key ring; each admits a verdict once | `aFalsePositiveFromAnalystsLiftsRiskInUebaAndTheSameVerdictCannotBeUsedTwice` |
| 5.2I-11 | Spoofing / elevation | Anyone with a valid certificate acts as an analyst; an analyst submits a colleague's signed verdict | SOC API: analysts by exact certificate subject; the verdict's signer must be the caller; reports are for leads | `theSocApiServesTheWholePictureOverMutualTlsToExactlyTheAnalysts` |
| 5.2I-12 | Tampering | The new record types break older readers (analytics misreading collected events as decisions) | Part C reads decisions only; collected events and the SOC's own records are skipped and counted | `analyticsReadDwarpalsDecisionsFromTheSameChainAndIgnoreTheCollectedEvents` |
| 5.2I-13 | Evasion | Detection per person needed the uploader's name, which native DLP records did not carry | Native events carry the actor as a field, and DLP records name it as a subject entity | `SecurityEventTest` |
| 5.2I-14 | Tampering | Playbook bundles were signed under a message domain defined outside the one place all signed messages live | Domain and message moved to `SignedMessages.playbookBundle` | `approvalsMustCoverThisExactTextAndBeFreshAndOfTheRightPurpose` |

Red-team pass on the integrated SOC: five probes found nothing (framing the CEO with syslog, framing a colleague
with cloud logs, faking the sensor's acknowledgement, backdating, a playbook file without guard rails); two found
real breaches (5.2I-1 and 5.2I-2), both fixed with a regression test. Slow baseline poisoning is part E's
(E-R1) and was not repeated here.

## v1.5 Layer 6 (the lab: launcher, console, scenario lab, admin views)

Ids are prefixed by part: 6G (console server), 6H (analyst console, the front end), 6I (admin and user views), 6J (scenario lab and guide); `6X` is the cross-part integration. The control baseline each row is checked against is `docs/layer-6/standards.md` (OWASP ASVS L2/L3, NIST SP 800-53 and 800-207, SOC 2, ISO 27001, CIS, MITRE). Details are in `docs/layer-6/part-g.md` to `part-j.md`; the rows keep each part's own ids.

### 6G Console server

#### STRIDE and ASVS

| # | Threat (STRIDE) | Control | ASVS 4.0.3 | Evidence |
|---|---|---|---|---|
| S1 | **Spoofing**: guessing or brute-forcing a login | PBKDF2 password + key PIN through the IdP; generic answer; per account+address exponential lockout, per address cap; throttle also on step-up | V2.1.1, V2.2.1, V2.2.2, V2.5.4, V2.8.x | `ConsoleThrottleTest`, `ConsoleSessionTest` |
| S2 | Spoofing: fixation or stolen cookie | New id at login and step-up; 256-bit ids; address+agent binding ends the session; duplicate/malformed cookie ignored | V3.2.1, V3.2.3, V3.3.1 | `ConsoleSessionTest`, red team a3 |
| S3 | Spoofing: another origin's page acting as the user (CSRF) | Strict cookie + token + Origin + Sec-Fetch-Site + JSON | V4.2.2, V13.2.3 | `ConsoleRequestGuardTest`, a2 |
| S4 | Spoofing: DNS rebinding | `Host` must be one of the server's names | V14.5.x | `aForeignHostHeaderIsRefused` |
| T1 | **Tampering**: changing who acts, or smuggling fields | Person from session only; exact-field bodies; SOC body rebuilt; delegation signed per call | V4.1.2, V5.1.5, V13.2.x | `ConsoleAccessTest.theBrowserNeverNamesWho...`, a4 |
| T2 | Tampering: path traversal, request smuggling, odd encodings | Allow-list by exact name; strict raw path; JDK server handles framing; header size cap | V12.3.x, V14.5.x | `ConsoleStaticTest`, a7, a8 |
| T3 | Tampering: forged or injected audit lines | All values sanitised and JSON-escaped, flat map, actor validated | V7.3.1 | `ConsoleAuditTest.whatTheBrowserSendsCannotForgeARecord` |
| R1 | **Repudiation**: a person denies an action | Intent + result for each write, reads of sensitive objects, login/step-up/logout, under the person's id with a hashed session tag; chain is keyed and anchored, verifiable in the page | V7.1.x, V7.2.x | `ConsoleAuditTest` |
| I1 | **Information disclosure**: errors, caching, side channels | Four error shapes, no reasons, `no-store`, uniform login answers; unknown users cost the same hashing | V7.4.1, V8.2.1, V2.2.x | a9, headers tests |
| I2 | Disclosure: records about colleagues through the audit explorer | Analysts get headers only for records outside the console's/SOC API's own types; the SOC API enforces the case/risk/search rules | V4.2.1 | `anAnalystSeesTheConsolesRecordsInFull...` |
| I3 | Disclosure: SSE events | Events carry no ids, names or text; each follow-up request is checked | V13.x | `ConsoleStreamTest` |
| D1 | **Denial of service**: floods, slow clients, large inputs | Per-person and per-address rates; worker pool + semaphore + deadline; 16 KiB bodies; 16 KiB headers; stream cap; login-id cap; throttle table bound | V11.1.x, V13.x | a6, a8, a13, `ConsoleStreamTest` |
| E1 | **Elevation of privilege**: reaching a route above one's role | Role check on every route in the host, module routes included; module files gated by role | V4.1.1, V4.1.3 | `ConsoleAccessTest` |
| E2 | Elevation: a stolen session making a privileged write | Step-up (password + PIN) for verdicts and any module route that asks for it; signing only for the session's own person | V2.8, V4.3.x | `aVerdictNeedsAFreshStepUp...`, a4, a12 |
| E3 | Elevation: the console used to reach the SOC API as someone else | Console cert + one-use 60 s delegation per call, only for analysts; server pinned to `CN=soc-api` | V9.2.x | a10, a11 |

#### Red-team findings

Each attack was written as a probe and run against the build (`ConsoleRedTeamTest` and the other classes).

| ID | Attack | Result | Fix and regression test |
|---|---|---|---|
| **F-G1** | A 200 KB request header value | **Succeeded**: the JDK server limits the number of headers but not their size, and answered 200 | Header bytes counted in the pipeline, over 16 KiB is 431. `ConsoleRedTeamTest.a8` (also a 3 MB header: refused) |
| **F-G2** | Open four sessions for one person in the same instant | **Succeeded (a bug, found by the test of the session limit)**: "oldest" was chosen by random id when creation times were equal, so a new session could be the one ended | Sessions carry a creation counter; step-up keeps it. `ConsoleSessionTest.aPersonHasAtMostThreeSessions...` |
| F-G3 | Builder setters kept references to mutable objects (SpotBugs EI_EXPOSE_REP2); an unchecked queue offer (RV_RETURN_VALUE_IGNORED) | Found by the gate | Holders and a loop; no suppression |
| a1 | Stored XSS through a note | Failed: the API only returns `application/json` with `nosniff` and the strict CSP; the text comes back verbatim (escaping on output is part H, with its source test) | `a1_scriptInANoteComesBackAsJsonTextOnly` |
| a2 | One session's CSRF token in another session | Failed (403) | kept |
| a3 | Session id in query or `Authorization` | Failed (401) | kept |
| a4 | Step-up or login naming another person; using ben's secrets in ana's session | Failed (400, 401, still stale) | kept |
| a5 | One login id used by eight threads at once | Failed: exactly one session | kept |
| a6 | Flood of unfinished logins from one address | Bounded at 20 per address (see open issue 1) | kept |
| a7 | Content-Length plus Transfer-Encoding smuggling | Failed: no hidden request ran | kept |
| a8 | Twelve stalled request bodies (more than the 8 workers) | Bounded: a normal request was answered within the 5 s deadline plus margin | kept |
| a9 | 12 malformed requests looking for a stack trace, class name or path in an answer | Failed: only the four short shapes | kept |
| a10 | Asking for people without standing; pointing the channel at a server that is not the SOC API | Failed (empty / 503) | kept |
| a11 | A copied delegation header without the console's certificate | Failed: the TLS handshake is refused | kept |
| a12 | Signing for a lead or an administrator | Failed (no key) | kept |
| a13 | 300 parallel calls from 24 threads | Only 200/429/503, no hang | kept |
| (guard tests) | Path traversal forms (22 of them), foreign Host, cross-site fetch, text/plain and form posts, `OPTIONS` preflight | Failed | `ConsoleStaticTest`, `ConsoleRequestGuardTest` |

##### Open issues (not fixed, named)

1. **Login flood on a shared address.** On the loopback every browser shares one source address, so someone who can reach the
   port can fill the 20 pending-login slots of that address for two minutes and make logins on it fail. A real deployment
   puts the console behind the gateway, where the source differs per user. Accepted for the lab; named in the report.
2. **A stalled body holds a worker up to the request deadline (5 s).** Eight workers means a determined local client can slow
   everyone. The anonymous limit (120 per minute per address) and the deadline bound it; a separate short read timeout for
   unauthenticated bodies would need a change in how the JDK server hands out the stream.
3. **Sessions are in memory.** A console restart logs everybody out (safe direction).
4. **The JDK server's header read time** (`sun.net.httpserver.maxReqTime`) is read once, when the server class first loads;
   `ConsoleMain` sets it to 30 s before anything else, but a test harness that loaded the server earlier keeps the default.

### 6H Analyst console (front end)

#### Standards lines for the front end, and their tests

| Standards line (section 3, "Output and input", "Secrets", "Static files") | How | Test |
|---|---|---|
| No `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `new Function`, string `setTimeout`, inline handlers | Not present; `dom.js` is the only way elements are made | `ConsoleSourceTest.noScriptCanTurnText...` (19 patterns, comments stripped), `noPageHasInlineScriptStyleOrHandlers`, and `theGateCatchesWhatItIsMeantToCatch` proves each pattern matches its attack |
| Strict CSP with Trusted Types works | No inline script/style, no `.style` writes, no `javascript:` URLs, no foreign addresses | `ConsoleSourceTest` (the same patterns) |
| One place talks to the server | `api.js` | `ConsoleSourceTest.onlyApiJsTalksToTheServer` |
| Only a harmless preference in `localStorage`, guarded | `prefs.js` | `ConsoleSourceTest.storageIsOnlyInThePreferencesFile...` |
| Nothing secret in the page | The session cookie is HttpOnly; the CSRF token is in a JS variable only; passwords are cleared from the form after use | `ConsoleSourceTest` (no `sessionStorage`, `indexedDB`, `document.cookie`) |
| Every file the page needs is served, every import resolves | | `ConsoleShellTest` |
| Fail closed: an error is shown as "Unavailable", never as an empty list | `DwView.fail`, `unavailable()`; the ATT&CK view says "Incomplete" when cases could not be read | exercised in the live run below |

##### What was and was not checked in a browser (honest account)

The built-in browser refuses the lab's own certificate authority (`ERR_CERT_AUTHORITY_INVALID`), and trusting a CA or turning
certificate checks off is the user's decision, not mine; the owner chose to **skip the browser check**. So **nothing was
looked at with eyes**: layout, colours, dark/light, focus rings, dialogs and the keyboard shortcuts are untested in a real
browser. What was done instead:

* Every script passes `node --check` (syntax).
* A scratch harness (not in the repository) ran the real `api.js` and every view against a **running `ConsoleMain`**
  (`NODE_EXTRA_CA_CERTS` pointed at the lab CA for that Node process only) with a small stand-in DOM, as cleo and as ana, and
  printed what each view rendered: overview, queue, cases, case, entity (landing and one entity), hunt, response, audit
  (list and one record), ATT&CK. All rendered real data from the SOC API with no "Unavailable".
* The same harness added a note containing `<img onerror>`, `<script>` and `<svg onload>` to a case and rendered the case:
  no `img`, `script`, `svg` or `iframe` element appeared in the tree, no `on*` attribute and no non-route `href`; the text
  was in the page as text.
* Server side, everything the views call is covered by part G's tests.

The owner should open `https://localhost:8443/` once (`ConsoleMain` prints the logins) and look.

#### Red-team notes for part H

| ID | Attack | Result |
|---|---|---|
| H1 | Stored XSS in a note, an alert text, a host name, a user agent: markup in every free-text field the SOC API returns | Failed. All text enters through `h()` text nodes; the harness above proved it for a note; the source test fails the build on any markup sink |
| H2 | A link in data that goes elsewhere (`javascript:`, another origin) | Failed. `h()` writes an `href` only if it matches `#/...`; a test pattern in `ConsoleSourceTest` also forbids `javascript:` in any file |
| H3 | A query in the hunt box that breaks the page when echoed (`"` and `\` in an entity id) | Failed. The entity page escapes only for the query language and inserts everything else as text; the hunt link goes through `encodeURIComponent` and the route allow-list for hrefs |
| H4 | Another module (parts I, J) with `innerHTML` or a script from a CDN | Would fail the build: the scan includes `modules/**` |
| **H5** | `encodeURIComponent` leaves `! ' ( ) *` unescaped, and the first version of the href allow-list did not accept them, so a hunt link for a query containing them silently lost its `href` (found while reading the code, not an attack) | Fixed in `dom.js` (the characters are allowed in the fragment); every link goes through the same function |
| H6 | The page keeps a session alive by polling | Refreshes triggered by the live feed or timers send `X-Dwarpal-Background: 1`, which the server does not count as activity (tested server side) |

Open points: no browser check (above); the ATT&CK view shows detections only because the SOC API does not expose rule
coverage; the entity page cannot show half-lives because the risk JSON gives the current (decayed) weight only.

### 6I Admin and user views

#### Threat model: STRIDE with ASVS / Top 10

| # | Threat | Control | Test | Reference |
|---|---|---|---|---|
| S1 | A person signs as another administrator | the signing key is looked up by the logged-in person's id; a person without a key (any other id) gets 403 | `AdminModuleTest.aPersonWithoutASigningKey...` | ASVS V2, V4; A01 |
| S2 | A stale session approves or installs | host step-up plus a second check in every privileged handler | `privilegedWritesAlsoRefuseAStaleSecondFactor...` | ASVS V2.8 |
| T1 | One administrator approves twice, or alone | the installer counts distinct signers; the test signs twice and installs: refused | `aPolicyNeedsTwoDifferentAdministrators...` | CM-5, SOC 2 CC8.1 |
| T2 | An old sequence replayed, or an approved file edited | approvals sign the exact text and sequence (a proposal cannot be edited, only withdrawn); the installer refuses rollback | `anOldSequenceIsRefusedByTheInstaller...` | ASVS V13 |
| T3 | A hostile policy or playbook file (tags, aliases, nesting, duplicate keys, control characters, unknown rules, destructive default, secret) | the real safe loaders and linters; a refused file is shown with findings but never kept; its text is not echoed back | `LabAdminModuleTest.hostileFiles...`, `AdminModuleTest` | ASVS V5; A03, A08 |
| T4 | Elevation without a second person | PAM refuses own approval, ineligible people and roles, short reasons, long windows | `anElevationNeedsADifferentApprover...`, `...Ineligible...` | AC-5, AC-6 |
| R1 | Who changed what | every install, grant and revoke is an audit record written by the component under the administrator's id; the history page reads them | `LabAdminModuleTest.anInstalledPolicy...` | AU-2, AU-10 |
| I1 | "Why was I denied" teaches an attacker | only the engine's requester message, the reference, time, resource, action and generic next steps: no policy, score, signal, address, device or threshold | `theRequestersPageUsesTheEnginesOwnWords...` | ASVS V7.4, V8; A04 |
| I2 | Reading another person's decision by guessing a reference | a reference that is not yours answers exactly like one that does not exist (same status and body) | `anotherPersonsReferenceLooksExactlyLike...` | ASVS V4.2; API1 |
| I3 | Stored XSS through policy descriptions or justifications | text goes in only with `textContent`; JSON stays valid whatever the text holds; the source test covers the admin pages | `textFromTheFileComesBackAsData...`, `FrontEndRulesTest` | ASVS V5.3 |
| D1 | Proposal flood | at most 10 open, 64 KiB each, one hour; PAM's own rate limits | `proposalsAreBoundedAndLapse` | ASVS V11 |
| D2 | What-if too large | at most 20,000 recent requests, the replay's own 200,000 cap | `whatIfReplays...` | |
| E1 | An analyst or ordinary person reaches admin data | role in registration and in every handler | `handlersRefuseTheWrongRoleEvenWithoutTheHostsCheck` | ASVS V4.1 |

#### Red-team pass

| Probe | First result | Now |
|---|---|---|
| Refused proposal file echoed back to the browser in the answer | **Leak of the submitted text** (found by the hostile-file test: an object tag came back in the response) | A refused file's text is not returned |
| Same administrator signs twice then installs | Held (installer: "1 distinct") | Regression test |
| Person with ADMIN role but no signing key approves | Held (403) | Regression test |
| Stale second factor on approve, install, request | Held (403) | Regression test |
| Install the same proposal twice; install an older sequence after a newer one | Held (404; "rollback") | Regression tests |
| Someone else's decision reference, a made-up one, and `../..` | Held (identical 404; 400) | Regression tests |
| Decision details page as an ordinary person | Held (403) | Regression test |
| Elevation: own approval, ineligible role, stranger, 1-character reason, 600 minutes | Held (PAM refuses each) | Regression tests |
| 11th proposal; proposal after the hour | Held (429; lapses) | Regression test |
| Object tag, alias, 5,000-deep nesting, duplicate keys, control character in policy and playbook files | Held; no stack trace | Regression test |
| Word "factor" in the requester's page | Test too strict, not a leak: the generic advice says "second factor" | Test now looks for risk, score, policy names |

### 6J Scenario lab and guide

#### Threat model: STRIDE with ASVS / Top 10

| # | Threat | Control | Test | Reference |
|---|---|---|---|---|
| S1 | A non-admin resets the lab | role in route registration and again in the handler; reset also needs `stepUpFresh` | `LabModuleTest` (3 tests) | ASVS V4.1, V4.2; A01 |
| S2 | A stale session performs a privileged write | host step-up and a second check inside the handler | `LabModuleTest.resetNeedsAFreshSecondFactor...` | ASVS V2.8, V4.3 |
| T1 | A learner's rule or playbook escapes the sandbox (object tags, aliases, bombs, deep nesting, giant files) | safe YAML loaders (no objects, no aliases, no duplicate keys), 16 KiB limit, 20 rules, linter refuses rules that can never fire | `ScenarioToolsTest.yamlTagsAliasesAndBombs...`, `...aRuleWithTooMany...` | ASVS V5.1, V5.5; A03, A08 |
| T2 | A learner's rule affects the live SOC | the rule runs in a private engine over a private copy of the records; alerts go to a list; test compares cases, raised alerts and chain head before and after | `ScenarioToolsTest.aGoodRuleRunsOnRecordedEvents...` | ASVS V1.4, V13.1 |
| T3 | A playbook acts on forgeable evidence | the real `PlaybookCompiler` refuses destructive steps on collected-only rules; sandbox never installs | `ScenarioToolsTest.aPlaybookOnForgeableEvidence...`, `ExamplesTest` | ASVS V11 |
| R1 | Who launched what | every write is audited by the host under the person; the journal keeps `by`, scenario, time | `LabModuleTest` | ASVS V7.1 |
| I1 | The export leaks a key, a hash, the lab directory, the host's names or real people | pseudonyms, field allow-list, key-like runs removed, final scan fails the export | `ScenarioToolsTest.theExportHolds...`, `...lastLineOfDefence...` | ASVS V8.3, V9; A02 |
| I2 | Error text echoes the submitted rule | findings name places and rule ids only | `ScenarioToolsTest.lintingNeverEchoes...` | ASVS V7.4 |
| I3 | Stored XSS through rule titles, findings, alert text, guide text | the pages insert text only with `textContent`; attributes from an allow-list; link targets restricted; a source test forbids `innerHTML`, `eval`, inline handlers and style | `FrontEndRulesTest` | ASVS V5.3; A03 |
| D1 | A scenario button held down | one launch per second, 12 per person per five minutes, a scenario cannot be launched again while it plays, world refuses more than 50,000 waiting items, past-dated items and unknown types | `LabModuleTest.aScenarioButtonHeldDown...`, `ScenarioToolsTest` (3 tests) | ASVS V11.1, V13.2; API4 |
| D2 | Expensive sandbox runs | one run at a time, one per person per 2 s, 100,000 records, 8 s budget, engine's own state limits | `ScenarioToolsTest.oneRunAtATime...` | ASVS V11.1 |
| D3 | Fast-forward or reset used to freeze the lab | one heavy operation at a time (429), fast-forward in 10-minute steps so the SOC API answers between steps | `LabModuleTest` | |
| E1 | Path parameters used for traversal or injection | identifier-only path parameters (letters, digits, `-`, `_`, 64 characters) | `LabModuleTest.badLaunches...` | ASVS V5.1.3, V12.3 |

ASVS levels touched: V4 (access control), V5 (validation and encoding), V7 (error handling), V8, V11 (business logic),
V13 (API), V14 (configuration; no new dependency).

#### Red-team pass

Each probe is a working test. The first column says what happened on the first build.

| Probe | First result | Now |
|---|---|---|
| First launch of any lab | **Breach of the lab's own limit: refused.** The rate limiter's "never launched" marker was `Long.MIN_VALUE`; subtracting it overflowed, so the gap check refused the very first launch (found by the first probe run) | Fixed (marker is half of it); every test launches |
| Injecting an endpoint batch with the next number | Design finding: a collector refuses numbers that go backwards, so an injected batch would have made every later scripted batch of that device "replayed" | `LabWorld` numbers and signs every batch with the device key when it runs |
| Export of a lab with the A9 alert | **Would have refused every export:** the "base64-like" scan matched the 39-character rule name `cloud-bulk-download-then-external-share` and the alert id built from it (found while writing the export tests, before any export ran) | The scan needs upper case, lower case and digits and excludes `-`; the test keeps the rule name as a negative case |
| Command line with a PEM header in an event that is cited as evidence | **Self-inflicted denial:** the last-line scan refuses the whole export | PEM markers are removed from values first; the scan still refuses if one gets through |
| Launch or fast-forward during a reset | Launch went into the old, closed world and was lost | Refused with 409 while resetting; a second reset is refused with 429 |
| A6 as first built | Fidelity: the login at the launch hour was STEP_UP, not the simulation's ALLOW | The thief has the owner's security key; the test pins ALLOW |
| Reset by an analyst, a lead, and an administrator with a stale second factor | Held (403) | Regression tests |
| Object tag, alias bomb, 5,000-deep nesting, duplicate keys, oversize, control characters, empty, in a rule file | Held; no stack trace, no echo | Regression tests |
| Playbook with a destructive default, a 400-day deny, an unknown rule, an unknown step, an extra key, a secret in the version | Held | Regression tests |
| Rule that matches every event | Held: sample capped, records capped, engine's flood limits | Regression test |
| 20,000 junk lines three times over | Held: the world refuses after 50,000 waiting items; past-dated and non-item objects refused | Regression test |
| Scenario button pressed 60 times; 15 launches by one person | Held: one accepted; at most twelve in five minutes | Regression tests |
| Path parameter with `../`, `%00`, `;` | Held (400/404, not echoed) | Regression test |
| An analyst reads the export | Held (403; leads only) | Regression test |

### 6X Integration (cross-part)

Run over HTTPS against the real launcher (`ConsoleMain`: lab session, console server, lab, guide and admin
modules, SOC API, audit chain): tests `LabConsoleEndToEndTest` and `LabConsoleRedTeamTest`. Earlier in 0b the
integration session also found and fixed two leaks while building the shared pieces (6X-1, 6X-2). A probe that
succeeded would be a breach; none of the eight cross-part probes succeeded.

| # | STRIDE | Threat or breach | Mitigation in code | Test |
|---|---|---|---|---|
| 6X-1 | Information disclosure (F) | A `count by` over all events would show an analyst how active a colleague is (grouped counts and totals) | Counts are taken over only the events the caller may see, per event, exactly as for search | `SocApiRedTeamTest.countByDoesNotRevealColleaguesGroupsOrTotals` |
| 6X-2 | Tampering (F) | The anchor check passed a chain whose history had been rewritten and then extended past the anchor | `LabAudit.verify` also compares the record at the anchored sequence number | `LabAuditTest.aChainCutShortRewrittenAndExtendedOrAlteredIsCaught` |
| 6X-3 | Spoofing / elevation | The console, if compromised or confused, acts as any analyst | The console's certificate alone is nobody; every call needs a per-call assertion signed with a key the ring trusts only for this, bound to method, path and body, one use, 60 seconds | `ConsoleDelegationTest` |
| 6X-4 | Elevation (CSRF) | A page on another site, or a script with a stolen cookie, makes a write | Token header, same-origin `Origin`, JSON content type, no CORS | `LabConsoleRedTeamTest.aWriteWithTheCookieButWithoutTheTokenOrFromAnotherOriginIsRefused` |
| 6X-5 | Tampering (XSS) | Hostile text in a note, alert or host name runs in an analyst's browser | Every API answer is JSON with `nosniff` and the strict CSP; the front end inserts text only with `textContent` (source test forbids `innerHTML`, `eval`, inline script) | `LabConsoleRedTeamTest.hostileTextComesBackAsJsonTextOnly...`, `ConsoleSourceTest`, `FrontEndRulesTest` |
| 6X-6 | Repudiation / spoofing | A verdict names someone else, or is signed without a fresh second factor | The signer is the session's person, never a field; step-up no older than five minutes | `LabConsoleRedTeamTest.aVerdictCannotNameAnotherAnalystAndNeedsAFreshStepUp` |
| 6X-7 | Elevation | Escalation across modules: an analyst resets the lab or installs policy; an administrator signs a verdict or launches an attack; a user reads policy | Role checked in the host (hierarchical, ANALYST < LEAD < ADMIN, USER separate) and again in each module; administrators are not analysts | `LabConsoleRedTeamTest.roleEscalationAcrossTheModulesFails`, `LabConsoleEndToEndTest` |
| 6X-8 | Information disclosure | The run export or a crafted URL gives away key store passwords, demo logins, certificates or the lab path | Export is sanitised and for leads only; static files are served only from a fixed in-jar allow-list by exact name | `LabConsoleRedTeamTest.theRunExportCarriesNoKey...`, `...filesOutsideTheStaticAllowListAreNotServed...` |
| 6X-9 | Denial of service / integrity | A reset of the lab leaves the console with a stale SOC address, a dead channel or a broken audit chain | The console reads the lab through one handle on every call; the new chain starts anchored; analysts' sessions keep working | `LabConsoleRedTeamTest.anAdministratorResetsTheLab...` |
| 6X-10 | Repudiation | The console's own actions are not on the trail | Login, step-up, writes and sensitive reads are audited under the person's name | `LabConsoleRedTeamTest.whatTheConsoleDid...`, `ConsoleAuditTest` |
| 6X-11 | Elevation (functional) | The host reserved the module id `lab` for its own status route, so the lab module could not load and the launcher stopped at start-up | `lab` freed; routes do not collide (different path lengths) | `LabConsoleEndToEndTest` |

Cross-part red-team pass: eight probes, none succeeded. Open items named by the parts are in the residual risks
below.

## Residual risks (accepted for this layer, scheduled)

| Risk | Why accepted now | Planned in |
|---|---|---|
| ~~Request-id replay inside the freshness window~~ | Closed in v0.7 for session traffic (S2) | Done (Layer 3) |
| Hardware (TPM) attestation not verified | Needs an attestation verifier | Later layer; until then capped at AGENT_SIGNED |
| HMAC audit key cannot live in an HSM yet (key must be extractable) | Simplicity | Layer 4: KMS-backed signing of chain heads |
| Correlated scorers overcount under naive Bayes | Inherent in the model | Documented; evaluation chapter |
| Linter conflict detection is structural only | SMT out of scope | What-If replay shows the effect of a change on recorded traffic (Layer 5 C); no proof |
| ~~PEP must treat an exception (null input) as DENY~~ | Closed in v1.0: every enforcement point maps any failure, timeout or odd answer to a deny (`RemoteSessionAuthority`, `aFailingOrSilentAuthorityIsADeny`) | Done (Layer 4) |
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
| MFA proofs outside sessions (single decisions straight to the engine) may still be unbound (`authentication/v2`) and replayable for 15 min | Narrowed in v1.0 (X2): single decisions exist only for web browsing, which never needs MFA | Retire v2 after the submission |
| Whoever holds a stolen token can end the victim's session by presenting it for another device (S10) | Ending a possibly stolen session is the safe side | Accepted; the victim logs in again |
| Sessions and nonces live in memory: a restart ends all sessions | Simplicity, no database yet | Layer 4 persistent store (tokens stay hashed) |
| A session opened while its subject is being revoked can survive the revocation | Open and revoke are not one transaction | Continuous evaluation denies its first use once the directory disables the account; revoke together with the directory change |
| Break-glass needs the identity provider for MFA on each admin action (P-05) | Consistency: every admin action needs fresh MFA | An offline emergency procedure for 'identity provider down' (Layer 5 runbook) |
| Approvers are any holder of an `ELEVATION_APPROVER` key; no per-role approver lists; one human with two accounts could approve themselves | Simplicity | Per-role approver groups in the admin console (Layer 6) |
| Elevation applies to all of the subject's sessions, not one device | The directory has no device context | Admin actions still need fresh MFA bound to the session key on every request (P-05 + R4), so another device without that key gains nothing |
| The web gateway knows its users by source address (`IdentityResolver.fixed`) | No proxy authentication yet; fine on a protected network, wrong behind NAT | HTTPS-proxy mode with the device certificate as identity (tested in part C), wired in the demo launcher |
| No TLS interception in the web gateway: only host names are seen | Interception needs a certificate on every client | Accepted; stated as a limit |
| DLP does not decode base64, compressed or Office/PDF content | Lite DLP; binary containers are blocked by default | Accepted; a determined insider can always encode |
| ~~DLP findings reach the audit trail but not the behavioural scorers~~ | Closed in v1.2: `DlpFeedback` turns blocks into fading watches read by `WatchlistScorer` | Done (Layer 5) |
| The JDK HTTP server's own slow-request limits (`sun.net.httpserver.maxReqTime`) are JVM-wide | Each server already has its own per-request deadline in code | The demo launcher sets them on the command line as a second layer |
| A compromised ZTNA gateway holds the application's shared secret and can reach the app directly | The gateway is the app's only door by design | Mutual TLS from gateway to app instead of a shared secret (later) |
| Detection windows start from zero after a restart (rule state is in memory) | No database yet | Persistent state with the store |
| Detection thresholds are starting values, not measured rates | No real traffic | Calibrate on real logs (part C's tools) |
| A rule's hourly cap hides further alerts of the same rule during a flood (they are counted, and the flood is alerted) | Protects analysts from alert floods | Accepted |
| An attacker who can write both the store and the anchor and stop the anchor schedule can hide records written since the last anchor | Anchor on another volume or account limits it | Ship anchors off the machine |
| The three Layer 5 keys (audit HMAC, store AES, anchor HMAC) come from the launcher; on Windows the store file has no POSIX permissions | Deployment concern | Layer 6 launcher and installer ACL |
| Revocations by a playbook cannot be undone by a false positive (people log in again) | Ending sessions is the safe side | Accepted |
| Case book and signal ledger live in memory: a restart forgets which case holds which deny (feed entries still end on their own) | No database yet | Persistent store |
| Several writers to the signal feed must share one `SignalLedger`, or a false positive may lift another writer's entry | `SignalFeed` has no per-holder clear | Per-holder clear in `SignalFeed` |
| What-If replays recorded requests without their evidence (data minimisation), so absolute decisions drift (250 of 720 in the simulation); the diff between two policies is still like for like | Faithful replay needs the engine to accept already-verified facts | After submission |
| Behaviour history is not time-indexed, so a replay sees what was learned after the request | Both policies see the same state | Point-in-time history |
| Correlation state and the event store live in memory: a restart forgets open windows (the store refills from the trail) | No database yet | Persistent state with the store |
| DHCP leases are configuration: a stale lease names the wrong device for a firewall flow | The alert is collected-only anyway (watch, never destructive) | Lease feed from the DHCP server |
| A key flood beyond 10,000 keys per rule refuses new keys (alerted), so a new attacker key arriving during a flood is not tracked | Bounded memory | Accepted; the flood itself is an alert |
| Sustained source-quota backpressure (queue filling but not yet overflowing) raises no alert until the queue overflows | The first overflow report is now first in line (5.2I-1) | A backlog signal from the ingestor |
| Detection, UEBA and ranking thresholds are starting values for the simulated organisation, not tuned on real logs | No real traffic | Calibrate on real logs |
| `sensor-heartbeat-missing` is silent until a device agent sends heartbeats | The simulated sensor sends none | The demo launcher (Layer 6) |
| The SOC API returns analyst notes and alert text sanitised only for control and bidirectional characters | Escaping belongs to the page | The console must HTML-escape everything (Layer 6) |
| Isolation commands to the sensor are not signed by Dwarpal (the simulated sensor trusts its channel) | A real sensor needs a signed command | Key purpose and `SignedMessages.isolationCommand` with a real sensor |
| Cases, isolation state, protected-device waits and the collected-watch budget live in memory | No database yet | Persistent store |
| `count by` queries are answered by the event store but not yet exposed through the SOC API's search | `EventSearch` returns events only | Add a `counts` method to `EventSearch` |
| The lab starts from day zero on every restart: cases, risk and isolations live in memory (certificates and demo logins are kept) | Rebuilding six components from the trail is large | Persistent state with the store, after the submission |
| `sensor-heartbeat-missing` is still silent: the simulated sensors seal telemetry hourly and send no heartbeats | Needs the simulator to seal every 10 minutes | After the submission |
| The console's screens were tested against the real scripts in a simulated page and over HTTPS, but not looked at in a real browser by the build sessions (the built-in browser refuses the lab's CA) | Layout, themes and shortcuts are unverified by eye | The owner looks once with the lab CA trusted (runbook) |
| Login flood on the loopback address: all local browsers share one source address, so pending logins can be exhausted for two minutes | Behind the gateway the source differs per person | Accepted for the lab (6G open issue 1) |
| Verdicts are signed on the console server with the lab's analyst key after a fresh step-up, not in the analyst's browser or hardware key | The seam is `VerdictSigner` | WebAuthn or WebCrypto signing |
| The console is a trusted proxy: it holds the delegation key that lets it speak for any configured analyst, though each call is signed and audited | An identity provider would issue the tokens in a company | Token issuance by the identity provider |
