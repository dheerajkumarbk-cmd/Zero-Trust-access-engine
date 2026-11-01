# Dwarpal threat model (STRIDE), v0.3

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
