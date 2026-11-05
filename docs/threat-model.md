# Dwarpal threat model (STRIDE), v1.2

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
