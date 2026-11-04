# Dwarpal: project state document (Layers 1 to 4)

| | |
|---|---|
| Document | Project state and progress log |
| State as of | 2026-11-04 (Layer 4 integrated) |
| Repository | https://github.com/dheerajkumarbk-cmd/Zero-Trust-access-engine (public) |
| Platform | Java 25 LTS (Temurin 25.0.5), Maven 3.9, no Docker, runs on an 8 GB laptop |
| Size | 170 main classes (16,937 lines), 70 test files (12,917 lines), 531 tests |
| Layers complete | Layer 1 (core decision engine), Layer 2 (behavioural risk scorers), Layer 3 (Policy Administrator: A sessions, B privileged access), Layer 4 (enforcement points: engine API, ZTNA gateway, web gateway, SaaS data guard) |
| Next | Layer 5 (SOC loop and analytics); the demo front end (Layer 6) when requested |

The name: a *dvārapāla* (Sanskrit, "door guardian") is the guardian figure at a temple gate who
decides who may pass. Dwarpal does the same for every access request.

---

## Contents

1. [What Dwarpal is](#1-what-dwarpal-is)
2. [Where it sits in a Zero Trust architecture](#2-where-it-sits-in-a-zero-trust-architecture)
3. [Principles it is built on](#3-principles-it-is-built-on)
4. [Architecture](#4-architecture)
5. [Layer 1: the core decision engine](#5-layer-1-the-core-decision-engine)
6. [Layer 2: behavioural risk scorers](#6-layer-2-behavioural-risk-scorers)
7. [How the layers work together, and Layer 3](#7-how-the-layers-work-together-and-layer-3)
8. [Mathematics reference](#8-mathematics-reference)
9. [Worked examples](#9-worked-examples)
10. [What makes Dwarpal different from enterprise products](#10-what-makes-dwarpal-different-from-enterprise-products)
11. [DevSecOps: security built in from the first line](#11-devsecops-security-built-in-from-the-first-line)
12. [Testing and quality evidence](#12-testing-and-quality-evidence)
13. [Standards and research behind the design](#13-standards-and-research-behind-the-design)
14. [Assumptions and known limits](#14-assumptions-and-known-limits)
15. [Progress log](#15-progress-log)
16. [Roadmap](#16-roadmap)
17. [Glossary](#17-glossary)
18. [Appendix: configuration reference](#18-appendix-configuration-reference)

---

## 1. What Dwarpal is

Dwarpal is a **Zero Trust Policy Decision Point**. For every access request it answers one question:

> May **this subject**, on **this device**, perform **this action** on **this resource**, **right now**?

It returns one of four outcomes, always with a written explanation:

| Outcome | Meaning |
|---|---|
| `ALLOW` | Full access |
| `ALLOW_LIMITED` | Read-only access: the session may only `READ`; `WRITE`, `DOWNLOAD` and `ADMIN` are refused |
| `STEP_UP` | Prove it again with multi-factor authentication (MFA) first |
| `DENY` | No access |

The outcomes are ordered `ALLOW < ALLOW_LIMITED < STEP_UP < DENY`; "stricter" always means further
right.

What it does on every request:

1. **Checks the evidence.** Device-health reports and "this user already passed MFA" claims count
   only if they carry a valid digital signature from a trusted key.
2. **Looks up the truth.** Roles, data classification and whether the device is managed come from the
   organisation's directory, never from the request.
3. **Measures risk.** Ten behavioural scorers (Layer 2) compare the login with the user's own
   history, with known-bad sources and with attack patterns. Bayes' rule turns their evidence into a
   probability of attack.
4. **Chooses the cheapest safe action.** A cost model picks ALLOW, STEP_UP or DENY by minimising
   expected loss.
5. **Applies policy.** Written policies (YAML) set a floor the risk result cannot go below.
6. **Explains and records.** The decision carries every reason, and is written to a tamper-evident
   audit trail before it is returned. If the audit write fails, the answer is DENY.

One policy model covers three kinds of resources, which is the SASE idea:

| Resource kind | SASE component | Example |
|---|---|---|
| `PRIVATE_APP` | ZTNA (Zero Trust Network Access) | Internal payroll application |
| `WEB` | SWG (Secure Web Gateway) | Outbound website |
| `SAAS_DATA` | CASB / DLP (Cloud Access Security Broker / Data Loss Prevention) | Files in a SaaS drive |

---

## 2. Where it sits in a Zero Trust architecture

NIST SP 800-207 splits Zero Trust into a **control plane** that decides and a **data plane** that
enforces.

```
                         CONTROL PLANE
  +--------------------------------------------------------------------+
  |  Policy Decision Point (PDP)                                       |
  |  +----------------------------+     +---------------------------+  |
  |  |  Policy Engine (PE)        |     |  Policy Administrator (PA)|  |
  |  |  Dwarpal Layer 1 + 2       |---->|  Dwarpal Layer 3: sessions|  |
  |  |  "should this be allowed?" |     |  revocation, JIT admin    |  |
  |  +-------------^--------------+     +-------------+-------------+  |
  |                |                                  |                |
  |   Policy Information Points (PIPs)                |                |
  |   directory (identity, resources, devices)        |                |
  |   threat intel, behaviour history, reputation     |                |
  |   signed evidence (device agent, identity provider)                |
  +---------------------------------------------------+----------------+
                                                      |
                          DATA PLANE                  v
  subject + device ---> Policy Enforcement Point (PEP) ---> resource
                        gateway / proxy / app plugin (Layer 4)
```

| NIST 800-207 role | Status in Dwarpal |
|---|---|
| Policy Engine (PE) | **Done** (Layers 1 and 2): `engine.PolicyEngine` and the risk scorers |
| Policy Administrator (PA) | **Done** (Layer 3): sessions with proof of possession, continuous evaluation and revocation (`session.PolicyAdministrator`); privileged access (`pam.PrivilegedAccessManager`); two-person policy bundles (`admin.PolicyInstaller`) |
| Policy Information Points (PIP) | **Done as interfaces with in-memory implementations**: `pip.AttributeDirectory`, `pip.ThreatIntel`, behaviour stores |
| Policy Enforcement Point (PEP) | Not built (Layer 4). The PEP contract (`engine.DecisionPoint`) is defined |
| Continuous diagnostics, SIEM | Audit trail is ready to ship to a SIEM (Layer 5) |

So Dwarpal is **more than a PDP**: alongside the decision engine it includes the parts of the Policy
Administrator that change policy, the information points the decision reads, a tamper-evident audit
trail and a learning loop.

Mapping to the CISA Zero Trust Maturity Model (v2.0) pillars:

| CISA pillar | What Dwarpal uses |
|---|---|
| Identity | Subject type, roles, department, MFA method and its strength, reputation |
| Devices | Managed or not, signed posture (patched, encrypted, antivirus), device reputation |
| Networks | IP, ISP (ASN), country, Tor, hosting providers, geolocation and travel speed |
| Applications and workloads | Resource kind, workload subjects (no "hosting provider" penalty for machines) |
| Data | Classification (PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED), read-only obligations |
| Cross-cutting: visibility, automation, governance | Explained decisions, HMAC audit chain, two-person policy changes |

---

## 3. Principles it is built on

### 3.1 Zero Trust tenets (NIST SP 800-207, section 2.1)

| Tenet | How Dwarpal implements it |
|---|---|
| Every resource is protected, wherever it is | Same engine for private apps, web and SaaS data |
| All communication secured regardless of location | Network location gives no trust; it is only evidence |
| Access is granted per session | Each request is decided on its own; nothing is "inside" |
| Access is decided by dynamic policy | Policy + live risk + device state + time |
| Monitor and measure the integrity of all assets | Signed device posture; device reputation |
| Authentication and authorisation are dynamic and strictly enforced | Step-up when risk rises; MFA counted by its real strength |
| Collect as much information as possible to improve | Learning loop with anti-poisoning rules; audit trail |

### 3.2 Security design principles

| Principle | Source | Where it lives |
|---|---|---|
| **Fail-safe defaults / fail-closed** | Saltzer and Schroeder 1975 | Default policy effect is DENY; any engine error, `StackOverflowError`, failed audit write or missing signal (on `FAIL_CLOSED` resources) means DENY |
| **Complete mediation** | Saltzer and Schroeder | Every request passes all seven stages; no cache of "allowed" answers |
| **Least privilege** | Saltzer and Schroeder | Grants vs constraints; read-only obligation; workload subjects get no human grants |
| **Separation of privilege** | Saltzer and Schroeder | Policy changes need two different administrators' signatures |
| **Economy of mechanism** | Saltzer and Schroeder | One runtime dependency; closed policy language (no scripting); ~5k lines |
| **Open design** | Saltzer and Schroeder, Kerckhoffs | Security rests on keys, not on secret code; fully open source |
| **Defence in depth** | NSA / NIST | Signatures, then gates, then risk, then policy, then obligations, then audit; each layer stops attacks the others miss |
| **Never trust the client** | Zero Trust | Request carries only identifiers; claims count only if signed |
| **Monotonic decisions** | Dwarpal design rule | Each stage can only make the outcome stricter. One exception: a STEP_UP already satisfied by fresh, verified MFA |
| **Glass box, not black box** | Dwarpal design rule | Every decision lists prior, evidence, posterior, thresholds and matched policy |
| **Evidence over claims** | Dwarpal design rule | Self-reported device health is a hint, not evidence |
| **Shift left (DevSecOps)** | DevSecOps | Threat model, abuse-case tests and security gates from the first commit (section 11) |

---

## 4. Architecture

### 4.1 Package map

| Layer | Package | Files | Lines | Responsibility |
|---|---|---|---|---|
| 1 | `domain` | 17 | 453 | Request, subject, device, posture, resource, network, evidence; validation and sanitising |
| 1 | `crypto` | 8 | 450 | Ed25519, canonical signed messages (10 types), key ring with 5 key purposes, SHA-256 digests |
| 1 | `pip` | 3 | 112 | Attribute directory and threat-intelligence snapshot |
| 1 | `engine` | 16 | 968 | `PolicyEngine`, the seven stages, hard gates, MFA settings |
| 1 | `risk` | 5 | 208 | Risk factors, scorer interface, Bayesian aggregation |
| 1 | `decision` | 3 | 175 | Outcomes, cost model, decision object with user and analyst views |
| 1 | `policy` | 10 | 939 | Policy language, safe YAML loader, linter, combining algorithms |
| 1 | `audit` | 6 | 330 | HMAC-SHA256 chained audit trail, audited decision point |
| 1 | `admin` | 2 | 212 | Two-person signed policy bundles, throttled rejection auditing |
| 1 | `runtime` | 1 | 50 | `DecisionPipeline`: assembles the layers in the only safe order |
| 2 | `risk.scorers` | 10 | 732 | The ten behavioural scorers and their maths helpers |
| 2 | `behavior` | 9 | 640 | Login history, reputation ledger, failure log, learning loop |
| 3 | `session` | 7 | 1,088 | Policy Administrator: sessions, proof of possession, re-authentication, revocation, signed failure reports |
| 3 | `pam` | 4 | 632 | Privileged access: just-in-time elevation, approvals, break-glass, elevated directory |
| 3 | `guard` | 2 | 150 | Replay cache and rate limiter shared by sessions, PAM and policy administration |
| 4 | `wire` | 5 | 657 | Strict JSON reader and writer with hard limits |
| 4 | `edge` | 10 | 1,202 | Contracts for every enforcement point: request and result types, header protocol, wire format, TLS settings and pinning |
| 4 | `api` | 6 | 1,261 | The engine API over mutual TLS (server) and `RemoteSessionAuthority` (the enforcement point's client) |
| 4 | `gateway` | 10 | 1,754 | ZTNA reverse proxy, login guard, routes, header policy, sample internal app |
| 4 | `agent` | 4 | 725 | Client agent: session keys, signed requests, step-up; simulated device agent |
| 4 | `devidp` | 7 | 971 | Development identity provider: PBKDF2 passwords, simulated WebAuthn, key-bound MFA proofs |
| 4 | `swg` | 16 | 1,967 | Secure web gateway: forward proxy, host canonicalisation, block lists, categories, SSRF guard |
| 4 | `casb` | 9 | 1,232 | SaaS data guard: validated detectors, DLP policy, redaction |
| | **Total** | **170** | **16,937** | Layers 1 to 3: 7,168 lines. Layer 4: 9,769 lines |

### 4.2 The full request path

```
AccessRequest (identifiers + signed evidence) + SignalSnapshot (honeytokens, deny-lists)
  |
  v
LearningDecisionPoint                     (Layer 2: learns after the decision, never before)
  |
  v
AuditedDecisionPoint                      (Layer 1: writes the HMAC-chained record; DENY if it cannot)
  |
  v
PolicyEngine: seven stages, in order
  [1] Evidence verification   posture and login proofs checked against the KeyRing
  [2] Hard gates              freshness, honeytokens, deny-lists: instant DENY
  [3] Attribute resolution    roles, classification, "managed" taken from the directory
  [4] Risk                    10 Layer-2 scorers -> Bayes (M3) -> cost-optimal action (M2)
  [5] Policy                  YAML grants and constraints; the effect is a floor
  [6] Step-up resolution      fresh, verified, device-bound MFA counted as evidence
  [7] Obligations             a read-only session may only READ
  |
  v
Decision { outcome, restricted, deviceVerified, matchedPolicyId, policyVersion,
           risk (prior, factors, posterior), reasons, decidedAt }
  -> userMessage()    generic text for the person asking (teaches an attacker nothing)
  -> analystReport()  the full explanation for the security team
```

Any exception in any stage ends in DENY. `runtime.DecisionPipeline.standard(...)` builds
`learning(audited(core))`, so nothing is learned from a decision the audit trail did not record.

---

## 5. Layer 1: the core decision engine

### 5.1 Domain model and input safety

The request supplies **identifiers only** (subject id, device id, resource id, action, network
facts, time) plus optional signed evidence. All other attributes come from the directory.

| Rule | Detail |
|---|---|
| Identifier allow-list | `[A-Za-z0-9._:@/-]{1,128}` and no `..`; blocks log injection (CWE-117), path tricks and control characters at construction |
| Canonical labels | Roles and departments lower-cased with `Locale.ROOT` (immune to the Turkish dotted-I problem); countries upper-cased |
| Numbers | Probabilities in [0, 1]; costs positive and at most 1e12; NaN and infinity refused |
| Free text | `Sanitize.text` escapes control characters, line and paragraph separators and Unicode bidirectional overrides (Trojan Source, CVE-2021-42574), then truncates |
| Size limits | 64 roles per subject; 256-character evidence; 512-character reasons; 500-character policy descriptions |
| Immutability | All domain objects are immutable records with defensive copies, proven by `ImmutabilityTest` |

Subject types are `HUMAN` and `WORKLOAD` (service accounts and machines). Actions are `READ`, `WRITE`,
`DOWNLOAD` and `ADMIN`. Each resource has a fail mode: `FAIL_CLOSED` (default: deny if a risk signal
is unavailable) or `FAIL_STEP_UP` (keep working but require MFA).

### 5.2 Signed evidence and the key ring

Zero Trust must not trust the client. A compromised laptop will happily report itself as "patched",
and a stolen session can claim "already passed MFA". So both claims count only when signed.

**Algorithm.** Ed25519 (EdDSA on Curve25519) from the JDK's own SunEC provider: 64-byte signatures,
deterministic (no random nonce to get wrong), constant-time. Only Ed25519 keys are accepted.

**Canonical encoding.** The bytes that are signed are built so that two different messages can
never produce the same bytes:

```
message = len(domain) || domain || len(f1) || f1 || len(f2) || f2 || ...
          (each len = 4-byte big-endian length, each field = UTF-8 bytes)
```

- *Length prefixes* stop the "ab"+"c" = "a"+"bc" ambiguity.
- *Domain separation*: the first field names the message type and version, so a signature made for
  one purpose can never be replayed as another.

| Signed message | Domain tag | Signed fields | Signed by |
|---|---|---|---|
| Device posture | `dwarpal/device-posture/v1` | device id, patched, encrypted, antivirus, signing time | Endpoint agent key bound to that device |
| Authentication | `dwarpal/authentication/v2` | subject id, **device id**, MFA method, time of authentication, signing time | Identity provider key |
| Policy bundle | `dwarpal/policy-bundle/v1` | sequence number, SHA-256 of the exact policy text, signing time | Each approving administrator |

Binding the authentication proof to the device id makes the session **device-bound** (the idea
behind token binding and DPoP): a proof stolen from the victim's laptop does not work from the
attacker's machine.

**Key ring checks**, in order (`crypto.KeyRing.verify`); the first failure rejects the proof with a
stated reason:

1. The key id is known.
2. The key's **purpose** matches (`DEVICE_AGENT`, `IDENTITY_PROVIDER` or `POLICY_SIGNER`); a device
   key can never sign a login, an identity-provider key can never approve policy.
3. The key's **owner binding** matches (a device-agent key belongs to exactly one device).
4. The key was valid both when the proof was signed and now (validity window).
5. The signature is not dated more than 2 minutes in the future (clock-skew allowance).
6. The signature is not older than the evidence's maximum age (posture 24 hours, login 15 minutes).
7. The Ed25519 signature verifies over the canonical message.

Successful verifications are cached (keyed by SHA-256 of key, message and signature; LRU of 10,000
entries) so repeated requests do not pay for signature checks again. Failures are never cached.

**Assurance levels** of device posture: `SELF_REPORTED` (a hint), `AGENT_SIGNED` (verified
signature), `HARDWARE_ATTESTED` (reserved for TPM attestation; cannot be claimed because it is not
verified yet). Whatever the request claims, the engine sets the level from the evidence it verified.

### 5.3 Hard gates

Some evidence is so strong that no calculation is needed; these gates deny immediately.

| Gate | Denies when | Why |
|---|---|---|
| Freshness | Request time is more than the allowed skew from the engine clock | Replayed captures and future-dated requests (which would distort time-of-day and travel scoring). Switched off for What-If replay of recorded traffic |
| Honeytoken | The subject or device is a decoy that no legitimate process ever uses | A hit is close to proof of compromise (MITRE Engage) |
| Deny-list | Subject, device or source IP is deny-listed | Incident response: block now, investigate later |

### 5.4 Attribute resolution (Policy Information Point)

`pip.AttributeDirectory` is the authority for: the subject's roles, department and type; the
resource's kind, classification and fail mode; and whether a device is managed. Unknown ids are
denied. When the request's copy disagrees with the directory, the directory wins and the mismatch
is written into the explanation (useful to an analyst: someone tried to claim a role).

### 5.5 Risk (model M3, with Layer 2 as the evidence source)

Each Layer-2 scorer returns a **log-likelihood ratio** (LLR): how much more likely this observation
is under attack than under normal use. Bayes' rule in log-odds form adds them to the base rate (full
formulas in section 8.1):

- Positive LLR: evidence of attack. Negative LLR: reassurance.
- **Asymmetric caps.** Attack evidence (impossible travel, a known-bad IP) is hard to fake;
  "looks familiar" (same device id, usual network) is exactly what a cookie thief replays. So each
  attack factor may count up to x1000, but each reassuring factor at most x10 and all reassurance
  together at most x10. Spoofed familiarity can soften strong attack evidence; it can never cancel it.
- Total reassurance is **scaled proportionally**, so the result never depends on scorer order.
- If a scorer throws, the risk is marked **degraded** and the resource's fail mode applies.

Then the **cost model (M2)** picks the action with the lowest expected loss (section 8.2).

### 5.6 Policy language

Policies are YAML, loaded by a hardened loader into a **closed condition language**: there is no
scripting, no expressions and no code, so a policy file can never execute anything.

**Effects** come in two kinds:

| Effect | Kind | Floor it sets |
|---|---|---|
| `PERMIT` | Grant | ALLOW |
| `PERMIT_LIMITED` | Grant | ALLOW_LIMITED (read-only) |
| `REQUIRE_STEP_UP` | Constraint | STEP_UP |
| `DENY` | Constraint | DENY |

- A **grant** authorises. Without at least one matching grant, the default effect (DENY) applies.
- A **constraint** only tightens. "Restricted data needs MFA" must never mean "anyone who passes MFA
  may read restricted data".
- A read-only grant **survives** constraints: passing MFA lifts the step-up, not the read-only limit.
- Every effect is a **floor**: risk can make the outcome stricter, never looser.

**Conditions** (17 operators): `all`, `any`, `not`, `always`, `roleIn`, `departmentIn`, `countryIn`,
`regionIn`, `resourceIdIn`, `subjectType`, `resourceKind`, `classificationAtLeast`,
`classificationAtMost`, `deviceHealthyWithAssurance`, `actionIn`, `deviceManaged`, `riskAbove`.

**Combining algorithms** (from XACML / NIST SP 800-162): `DENY_OVERRIDES` (the most restrictive
match wins; the default) and `FIRST_APPLICABLE` (file order).

**Safe loader** (`policy.SafePolicyLoader`):

| Protection | Against |
|---|---|
| SnakeYAML 2.7 `SafeConstructor`; global tags rejected | Code execution through YAML deserialisation (CVE-2022-1471) |
| No aliases or anchors; 256 KiB size cap; depth 16; 10,000 nodes; 1,000 policies | "Billion laughs" and resource exhaustion |
| Duplicate keys rejected | A second `effect:` hidden from a reviewer |
| Strict schema (unknown keys are errors) | A typo like `efect:` silently disabling a rule |
| Strings required for codes and versions | The YAML "Norway problem" (`NO` read as `false`) |
| File loading: regular files only, symbolic links not followed, strict UTF-8, size read with a hard cap | Link tricks, encoding confusion, huge files |
| Linter gate: identical conditions with different effects are errors; rules shadowed under `FIRST_APPLICABLE` are warnings, and warnings fail the load by default | Conflicting or dead rules reaching production |
| Error messages sanitised and truncated | Parser messages leaking or forging file content |

**Reference policy set** (`src/main/resources/policies/default-policy.yaml`, version
`2026.11.03-1`, `DENY_OVERRIDES`, default DENY):

| Id | Rule | Effect |
|---|---|---|
| P-01 | Humans may use (read, write, download) internal private apps (classification at most INTERNAL) | PERMIT |
| P-02 | Finance may use (not administer) confidential private apps (no other resource kinds) | PERMIT |
| P-03 | Confidential or higher only from a healthy device with at least agent-signed posture | DENY otherwise |
| P-04 | Restricted resources always need fresh strong authentication | REQUIRE_STEP_UP |
| P-05 | Administrative actions always need fresh strong authentication | REQUIRE_STEP_UP |
| P-06 | Administrative actions only with the `admin` role, which exists only through a just-in-time grant (no standing admin) | PERMIT |
| P-10 | Public web destinations | PERMIT |
| P-20 | Humans may use (not administer) internal SaaS data | PERMIT |
| P-21 | SaaS data from unmanaged devices is read-only | PERMIT_LIMITED |
| P-90 | P(attack) above 0.9 | DENY (hard ceiling over the cost model) |

### 5.7 Step-up resolution: MFA as evidence

If the outcome so far is STEP_UP and the request carries a **verified** authentication proof that
is **fresh** (at most 15 minutes old), **not from the future**, **bound to this subject and device**,
and **stronger than a password**, the engine treats it as evidence and decides again (formula in
section 8.3). Strong MFA collapses the risk; weak MFA barely moves it, so under real suspicion the
engine asks for something stronger, or denies.

Each method has a **bypass probability** β, the chance that an attacker gets past it:

| Method | β (stated assumption) | Why |
|---|---|---|
| Password only | 1.0 | Does not satisfy step-up at all |
| Push approval | 0.30 | MFA fatigue / prompt bombing |
| SMS one-time code | 0.20 | SIM swap, interception, real-time phishing |
| TOTP app code | 0.10 | Real-time phishing proxies |
| Push with number matching | 0.05 | Defeats blind approval; still phishable |
| WebAuthn / passkey | 0.01 | Phishing-resistant: bound to the real website's origin |

The engine refuses to start if the cost model's β differs from the β of the method the Policy
Administrator challenges with (default: push with number matching, β = 0.05), so the two parts can
never disagree about how strong the challenge is.

This is the only stage that can lower an outcome, and only from STEP_UP to ALLOW or ALLOW_LIMITED:
a requirement being met, not a policy being loosened. Read-only restrictions survive it.

### 5.8 Obligations

A read-only (`ALLOW_LIMITED`) session may only `READ`. The engine itself denies `WRITE`, `DOWNLOAD`
and `ADMIN` under a restriction, rather than trusting every enforcement point to interpret
ALLOW_LIMITED correctly.

### 5.9 The decision and its explanation

| Field | Content |
|---|---|
| `outcome`, `restricted` | The answer, and whether the session is read-only |
| `deviceVerified` | Whether the device proved its identity with a signature |
| `matchedPolicyId`, `policyVersion` | Which rule decided, under which policy version |
| `risk` | Prior, every factor with its LLR and evidence text (marked `[capped]` when capped), posterior P(attack), failed scorers |
| `reasons` | Each stage's contribution, in order |

Two views: `userMessage()` is deliberately generic, so a rejected attacker learns nothing about what
to evade; `analystReport()` is the full glass-box explanation for the security team.

### 5.10 Tamper-evident audit trail

Every decision and every policy installation is appended to an **HMAC-SHA256 hash chain**
(section 8.10). Changing, deleting, inserting or reordering any record breaks every MAC after it.
Because the chain is keyed (key of at least 32 bytes, kept outside the log's storage), someone with
write access to the log but not the key cannot rebuild it. Removing records from the *end* is caught
by comparing with the latest chain **head**, which is copied somewhere the log writer cannot alter
(the SIEM).

**No audit, no access:** `AuditedDecisionPoint` returns DENY if the record cannot be written. The
chain advances only after the sink accepts the record, so a failed write leaves no gap.

### 5.11 Policy administration: the two-person rule

`admin.PolicyInstaller` installs a new policy set only if:

1. Its **sequence number** is higher than the installed one (no rollback to an older, weaker policy).
2. At least **two distinct administrators** (distinct key owners, not just distinct keys) signed it
   with `POLICY_SIGNER` keys, over the exact text (its SHA-256) and the sequence number.
3. Each approval is at most **7 days** old.
4. The text passes the safe loader and the linter.
5. The installation is **written to the audit trail first**; if that fails, the old policy stays.

The swap is atomic: requests see either the old policy or the new one, never a mix.

### 5.12 IAM, encryption and privileged access

**The four "A"s of IAM** and where each one meets the core:

| IAM function | What happens | Hook in the core |
|---|---|---|
| Authentication | The identity provider logs the user in with password and MFA | It signs (subject, device, method, time); the core verifies it with an `IDENTITY_PROVIDER` key and turns the method into evidence through its β |
| Authorisation | The enforcement point asks "may this happen?" | `DecisionPoint.decide`, the only entry point |
| Auditing | SOC console, SIEM | HMAC-chained JSON records; the chain head is anchored in the SIEM |
| Administration | Policy changes | `PolicyInstaller` (two-person rule, rollback guard). Admin actions are `Action.ADMIN`, which policy P-05 always sends through step-up |

The step-up loop: the engine says STEP_UP → the Policy Administrator challenges (for example with
WebAuthn) → the identity provider signs the result bound to the device → the next request carries
it → the engine updates P(attack) with that method's β → ALLOW.

**Encryption: where it is needed and where it is not.**

| Data | Threat | Control | Status |
|---|---|---|---|
| Signed claims (posture, login, policy) | Forgery, tampering | Ed25519 signatures give integrity and origin; encryption would not stop forgery | Done |
| Audit trail | Editing or deleting history | HMAC-SHA256 chain and external head anchor | Done |
| Enforcement point to engine traffic | Eavesdropping, spoofed answers | Mutual TLS 1.3 | Layer 4 |
| Audit and session data at rest | Disk theft, insiders reading personal data | Encrypted storage (AES-256-GCM) and data minimisation; session tokens already stored only as hashes | Layer 5 |
| Keys (audit key, admin private keys) | Theft | Never in the repository (secret scanning), loaded from environment or KMS; admin keys on hardware tokens in production | Every layer |

The core keeps request data in memory only for one decision, so its confidentiality comes from not
storing anything; its integrity is cryptographic.

**Privileged Access Management (PAM).**

| PAM control | Status |
|---|---|
| Four-eyes approval for policy changes | Done (`PolicyInstaller`, two approvers) |
| No shared admin identities; every key bound to a named administrator | Done |
| Privileged actions audited, including rejected attempts | Done |
| Step-up for every admin action | Done (policy P-05) |
| Just-in-time admin elevation, break-glass account, admin rate limiting | Done (Layer 3 part B, section 7.2) |
| Database least privilege (audit tables insert-only) | Layer 5 |

---

## 6. Layer 2: behavioural risk scorers

Layer 2 never decides. It produces evidence (LLRs) that Layer 1 weighs. Each scorer looks at the
request through a **read-only view** of the stores; only the learning loop writes to them.

### 6.1 The ten scorers

| # | Scorer | Detects | Model | Default parameters |
|---|---|---|---|---|
| 1 | `network-novelty` | New IP, ISP or country for this user | Rule of succession with back-off IP -> ASN -> country (M1) | P(new given attack): IP 0.99, ASN 0.90, country 0.60 |
| 2 | `device-novelty` | Unknown or unproven device | Same (M1); only signature-proven device ids count as known | P(new device given attack) 0.95 |
| 3 | `impossible-travel` | Too far, too fast | Haversine distance minus both GeoIP accuracy radii, over elapsed time (M7) | 1000 km/h; LR = 0.60 / 0.02 = 30 |
| 4 | `login-time` | Unusual hour for this user | Circular kernel density of von Mises kernels vs uniform (M6) | κ = 8 (about +/- 80 min), at least 8 logins, shrinkage 10 |
| 5 | `subject-trust` | User's reputation | Beta reputation (M4) with exponential forgetting (M5) | Half-life 30 days in the reference set-up |
| 6 | `device-trust` | Device's reputation | Same; silent for unproven devices | Same |
| 7 | `brute-force` | Password guessing on one account | Poisson likelihood ratio, clamped at 0 | 15 min window; λ legit 0.2, λ attack 5 |
| 8 | `password-spray` | One IP failing on many accounts | Same, counting distinct accounts per IP | 15 min; λ legit 0.5 (shared NAT), λ attack 10 |
| 9 | `attack-surge` | Organisation-wide credential campaign | Same, on the org-wide failure total, capped at x10 | 15 min; λ normal 20, λ attack 200 |
| 10 | `ip-reputation` | Abuse-listed IP, Tor exit, hosting provider | Fixed likelihood ratios; strongest category only | Abuse x50, Tor x20, hosting x10 (humans only) |

Notes that matter for security:

- **Unproven devices.** If the device did not prove its id with a signature, its novelty can only
  raise risk, never lower it, and it borrows no reputation. Typing a victim's device id buys nothing.
- **Hosting providers** are suspicious only for humans; workloads legitimately run in data centres.
- **Out-of-order data** (a request older than the last login) gives no travel speed rather than a
  wrong one.

### 6.2 Behaviour stores (all size-bounded)

| Store | Holds | Bounds |
|---|---|---|
| `InMemoryBehaviorHistory` | Per user: login count, distinct values per feature (IP, ASN, country, device), novelty flags and minute-of-day of the last 200 logins, last login | 100,000 users (LRU), 256 values per feature, 200 recent logins |
| `TrustLedger` | Good and bad events per subject and device, with timestamps | 200,000 entities, 1,000 events each, half-life decay |
| `FailureLog` | Failed logins per subject; per IP a record of (subject, time); org-wide failures per minute | 100,000 keys, 1,000 events per key, 120 one-minute buckets; evidence younger than 1 hour is never evicted, so an attacker cannot flush it by flooding |
| `ThreatIntel` | Abuse IPs, Tor exits, hosting ASNs (immutable snapshot; a feed update replaces the whole snapshot, read through a supplier) | 2,000,000 entries |

### 6.3 The learning loop and its anti-poisoning rules

`behavior.LearningDecisionPoint` learns **after** the decision has been made and audited. An attacker
who could teach the baseline their own habits would become "normal", so learning is deliberately
narrow:

| Rule | Prevents |
|---|---|
| Learn only from full `ALLOW` decisions (not read-only, not step-up, not deny, not degraded) | An attacker's denied or challenged attempts shaping the baseline |
| Skip requests more than 5 minutes from the engine clock | Back-dated or future-dated events rewriting history |
| Earn reputation only when P(attack) at most 0.01 | Borderline logins building trust |
| Record a device as known only if it proved its identity | Typed device ids becoming "familiar" |
| Honeytoken hit: bad mark on the device only if the device is proven | Framing a victim's laptop by typing its id |
| Learning errors are counted, never thrown | Learning failures turning into access failures |
| Wrapping order `learning(audited(core))` | Learning from a decision the audit refused |

---

## 7. How the layers work together, and Layer 3

```
                  Layer 2 (evidence)                     Layer 1 (decision)
  request ------> 10 scorers read-only  --LLRs-->  Bayes M3 -> cost model M2 -> policy floor
                  (history, trust,                    -> step-up as evidence -> obligations
                   failures, intel)                              |
                        ^                                        v
                        |                               Decision + explanation
                        |                                        |
                        +------ learning loop <-- audit chain <--+
                          (only full, low-risk ALLOWs, proven devices)
```

- **One contract.** A scorer implements `RiskScorer.score(request, signals)` and returns an optional
  `RiskFactor(name, llr, evidence)`. New detectors plug in without touching the engine.
- **One currency.** Every scorer speaks in log-likelihood ratios, so ten different detectors
  (statistics, geography, reputation, threat intel) add up in one Bayesian sum.
- **One decision maker.** Only Layer 1 decides. Layer 2 cannot override policy, cannot write to its
  own stores during scoring, and cannot loosen a decision.
- **One model of MFA.** The same β is used by the cost model (when choosing STEP_UP) and by the
  step-up stage (when counting a passed MFA as evidence).
- **Closed loop.** Layer 1's final, audited decisions feed Layer 2's learning, under the rules in
  section 6.3.

Layer 3 sits on top: it never decides itself, it asks the engine again on every request.

```
          Layer 1-2: Policy Engine                       Layer 3: Policy Administrator
login --> decide(login) -- ALLOW -->  A: open session (token + session key + limits)        --> client
use   --> check token, key proof, replay, limits --> decide(use) again (continuous evaluation)
          ALLOW: go on    STEP_UP: re-authenticate    DENY: revoke    incident: revoke user/device
admin --> B: request role (eligible, WebAuthn, reason) --> approver signs --> role exists for 1 h
          break-glass: sealed credential --> 30 min, SOC alerted, reviewed afterwards
```

### 7.1 Layer 3 part A: sessions

| Element | Design |
|---|---|
| Token | 256-bit random; only its SHA-256 is stored; never printed or audited |
| Proof of possession | The client makes an Ed25519 session key at login; every use is signed with it over (session, request id, subject, device, resource, action, time), at most 2 min old (the idea of DPoP) |
| Replay | Each request id is single-use per session, remembered 4 min |
| Device binding | A login with signed device posture must also carry the device agent's signature over this session key, for this login, within 2 min, once |
| Key-bound MFA | The identity provider signs the session key's thumbprint into each MFA proof (`authentication/v3`); the PA refuses MFA bound to any other key |
| Continuous evaluation | The engine decides every use again; a deny-list entry, honeytoken or rising risk ends the session on the next request |
| Limits | Idle 30 min; lifetime 10 h; re-authentication every 8 h / 4 h / 1 h / 15 min for PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED (stricter of opening and current classification); requests within 2 min of the PA clock |
| Revocation | By session, user or device; removed first, audited second |
| Bounds | 100,000 sessions, 5 per user, 200,000 replay entries; refuse when full |
| Login failures | Only identity-provider-signed, recent, single-use failure reports reach the brute-force and spray detectors |

### 7.2 Layer 3 part B: privileged access

| Element | Design |
|---|---|
| No standing admin | ADMIN is granted only to the `admin` role (policy P-06), and nobody holds it permanently |
| Just-in-time elevation | Eligible person, at most 1 h, written reason, WebAuthn at most 5 min old and single-use; a **different** person signs (request, person, role, duration) with an approver key; unapproved requests lapse after 30 min |
| In force | `ElevatedDirectory` adds active grants to the roles the engine sees; the role disappears on the first decision after the window or a revocation; every admin action still needs fresh, key-bound MFA (P-05) |
| Break-glass | Designated accounts open a sealed credential (signs role and reason, once); 30 min; SOC paged at once; mandatory signed review by someone else; misuse ends the grant |
| Rate limits | 5 genuine requests per person per hour, 20 genuine approvals per approver per hour, 3 break-glass uses per account per day; only authenticated actions count, so junk cannot lock anyone out |
| Accountability | Nothing is requested, granted or opened without its audit record; refusals audited with throttling |

Exposure arithmetic: a standing admin account is an admin 8,760 hours a year; with three 1-hour
elevations a week it is 156 hours, 98% less, each hour tied to an approver and a reason. Full details,
the maths and the red-team results are in [layer-3-report.md](layer-3-report.md).

### 7.3 Layer 4: enforcement points and the SASE edge

Layer 4 puts the decisions in front of real traffic. Enforcement points (PEPs) never decide; they ask
the engine through one API and enforce the answer. Full report: [layer-4-report.md](layer-4-report.md).

```
 client agent --HTTPS--> ZTNA gateway ----+
 browser -----proxy----> web gateway -----+--mutual TLS 1.3--> engine API --> PA / PAM / engine
 SaaS upload ----------> data guard ------+       (each PEP: own certificate, own resource scope)
```

| Element | Design |
|---|---|
| Engine API | JDK `HttpsServer`, TLS 1.3, client certificate required; callers known by exact certificate subject, each with a role and (for a PEP) the resources it fronts; per-caller rate limits; 64 KiB strict JSON; generic error bodies; every call audited; a deadline per request |
| PEP client | `RemoteSessionAuthority`: pinned to the API's certificate during the handshake, one deadline for the whole exchange, bounded answers checked against the question; any failure is a deny |
| ZTNA gateway | Reverse proxy; path prefix to resource, method to action; subject and device from the session it opened, network from the socket; only GRANTED is forwarded; client-supplied `Dwarpal-*` headers removed; the app trusts only the gateway |
| Client agent and IdP | A fresh Ed25519 session key per application; login with password and a (software) security key over a single-use challenge; MFA proof bound to the session key; every request signed |
| Web gateway | Forward proxy for HTTP and HTTPS tunnels, decided by host name: one canonical form, block lists and categories from local files, look-alike names, raw IPs refused, every resolved address checked against internal ranges; the engine decides, and the stricter of the local filter and the engine wins |
| SaaS data guard | Reads, downloads and uploads through sessions; uploads scanned by validated detectors (Luhn, Verhoeff, PAN, IFSC, keys, tokens) and blocked, redacted or audited by the data's classification; values never logged |
| Sessions at the edge | The PA opens a session only on fresh, verified MFA bound to the session key, and each MFA proof opens one session, whichever PEP asks. Single decisions exist only for web browsing |

---

## 8. Mathematics reference

All formulas below are implemented exactly as written. Parameter values marked "assumption" are
stated design assumptions, to be calibrated on real data in Layer 5.

**Reference configuration** (used by the tests and the accuracy simulation; deployers set their
own): prior P(attack) = 0.001; attack cap per factor ln 1000; reassurance caps ln 10;
costs C_B = 1000, C_F = 1, C_D = 20; challenge β = 0.05.

**The nine models of the original plan, and their status:**

| Id | Model | Problem it answers | Status | Section |
|---|---|---|---|---|
| M1 | Novelty likelihood ratios (rule of succession, back-off) | "Is this new for this user?" | Done (Layer 2) | 8.4 |
| M2 | Three-action cost model | "Which action loses least?" | Done (Layer 1) | 8.2 |
| M3 | Bayes with a base rate | "How likely is an attack, honestly?" | Done (Layer 1) | 8.1 |
| M4 | Beta reputation | "How trustworthy is this user or device, and how sure are we?" | Done (Layer 2) | 8.5 |
| M5 | Exponential decay | "How fast should old evidence fade?" | Done for reputation; per-signal SOC decay in Layer 5 | 8.5 |
| M6 | Circular login-time density | "Is this an unusual hour for this user?" | Done (Layer 2) | 8.6 |
| M7 | Impossible travel with GeoIP radii | "Could one person have moved that fast?" | Done (Layer 2) | 8.7 |
| M8 | Change-impact analysis | "What would this policy edit change?" | Linter done; What-If replay in Layer 5 | 8.13 |
| M9 | MFA fatigue | "How strong is each MFA method?" (the β values) | β per method done; PAM accepts only WebAuthn; sensitivity analysis in Layer 5 | 8.3 |

Two further detectors were added in Layer 2 on the same footing: **Poisson rate tests** (8.8) and
**IP reputation** (8.9).

How they fit together:

```
features -> M6 / M7 feature models -> M1 likelihood ratios -> M3 Bayes posterior p
         -> M4 trust (with M5 decay) -> M2 cost-optimal action (beta from M9) -> decision + explanation
         -> M8 change impact for policy edits
```

### 8.1 M3: Bayes with a base rate (risk aggregation)

Bayes' rule in log-odds form, where each scorer k contributes a log-likelihood ratio:

```math
\operatorname{logit} P(\text{attack} \mid x) \;=\; \operatorname{logit} P(\text{attack}) \;+\; \sum_k \ell_k,
\qquad
\ell_k = \ln \frac{p(x_k \mid \text{attack})}{p(x_k \mid \text{legit})},
\qquad
\operatorname{logit} p = \ln\frac{p}{1-p}
```

The posterior is recovered with the sigmoid:

```math
P(\text{attack} \mid x) = \frac{1}{1 + e^{-z}}, \qquad z = \operatorname{logit} P(\text{attack}) + \sum_k \ell_k'
```

**Asymmetric caps** turn each raw ℓ into the ℓ' actually used. With attack cap A = ln 1000,
per-factor reassurance cap r = ln 10 and total reassurance cap R = ln 10:

```math
\ell_k' =
\begin{cases}
\min(\ell_k,\, A) & \ell_k \ge 0 \\[4pt]
-\min(-\ell_k,\, r)\cdot s & \ell_k < 0
\end{cases}
\qquad
s = \min\!\left(1,\; \frac{R}{\sum_{j:\,\ell_j<0} \min(-\ell_j,\, r)}\right)
```

The proportional factor s keeps the result independent of scorer order.

*Why the base rate matters* (Axelsson 2000): if 1 login in 1,000 is an attack, a detector with 99%
detection and a 1% false-alarm rate is still wrong about 91% of the time when it fires
(0.99 x 0.001 / (0.99 x 0.001 + 0.01 x 0.999) ≈ 0.09). Starting from the prior stops the engine from
over-reacting, which is where analyst alert fatigue comes from.

*Assumption:* factors are conditionally independent (naive Bayes). Correlated scorers overcount; the
caps bound the damage.

### 8.2 M2: the cost-optimal action (three-action decision theory)

With p = P(attack | evidence), β = probability an attacker passes the step-up challenge,
C_B = cost of a breach, C_F = cost of challenging a legitimate user (friction), C_D = cost of wrongly
blocking a legitimate user:

```math
\begin{aligned}
L(\text{ALLOW})   &= p \, C_B \\
L(\text{STEP\_UP}) &= p \, \beta \, C_B + (1-p)\, C_F \\
L(\text{DENY})    &= (1-p)\, C_D
\end{aligned}
```

The engine picks the action with the smallest expected loss; ties go to the stricter action. The
crossover points have closed forms:

```math
\text{STEP\_UP beats ALLOW when } \; p > \frac{C_F}{C_F + C_B(1-\beta)}
\qquad\qquad
\text{DENY beats STEP\_UP when } \; p > \frac{C_D - C_F}{(C_D - C_F) + \beta\, C_B}
```

(If C_D ≤ C_F, DENY always beats STEP_UP.)

With the reference costs:

| β (challenge method) | Step up above | Deny above |
|---|---|---|
| 0.01 (WebAuthn) | 0.00101 | 0.655 |
| 0.05 (number-matching push, reference) | 0.00105 | 0.275 |
| 0.30 (plain push) | 0.00143 | 0.0596 |

The key consequence: **thresholds follow from MFA strength.** With weak MFA the engine denies sooner,
because a challenge an attacker can pass is not much protection; with phishing-resistant MFA it
prefers a challenge to a block. Source: cost-sensitive classification, Elkan 2001; the three-action
form with β is Dwarpal's own derivation.

### 8.3 MFA as Bayesian evidence (step-up resolution)

A legitimate user passes their MFA (almost) always; an attacker passes with probability β. After a
verified pass of method m:

```math
P(\text{attack} \mid \text{passed}) \;=\; \frac{p\,\beta_m}{p\,\beta_m + (1-p)}
```

The cost model then chooses again with this new probability. The policy floor still applies.

**Where β comes from (M9, MFA fatigue).** For push approval, an attacker who sends n prompts
succeeds if the user approves any one of them. If q_i is the chance the user approves prompt i:

```math
P(\text{success by prompt } n) = 1 - \prod_{i=1}^{n} (1 - q_i)
```

This value is β for push MFA. There is no peer-reviewed measured value for q (vendor claims about
number matching are vendor claims), so β is a stated parameter per method, and the planned
sensitivity analysis (Layer 5) shows how decisions change as β varies. Phishing-resistant methods
(WebAuthn) are not exposed to fatigue or relay attacks, hence their much lower β.

### 8.4 M1: novelty with the rule of succession and back-off

How often does this user show up from something new? Over the last w logins (w ≤ 200), let k be the
number of times the value at this level was new for them. Laplace's rule of succession gives a
probability that is never 0 or 1, even for brand-new users:

```math
P(\text{new} \mid \text{legit}) = \frac{k + 1}{w + 2}
```

Levels are checked from most to least specific (IP, then ASN, then country). For each level:

```math
\ell_{\text{level}} =
\begin{cases}
\ln \dfrac{P(\text{new} \mid \text{attack})}{P(\text{new} \mid \text{legit})} & \text{value is new: add, continue to the next level} \\[10pt]
\ln \dfrac{1 - P(\text{new} \mid \text{attack})}{1 - P(\text{new} \mid \text{legit})} & \text{value is known: add, stop}
\end{cases}
```

So a new IP inside a known ISP scores less than a new IP in a new ISP in a new country. Using recent
logins (not all-time) means a user who has just started travelling is judged on their current habits.
Adapted from Freeman et al., NDSS 2016 (login-history likelihoods with back-off).

### 8.5 M4 and M5: Beta reputation with exponential forgetting

Each subject and device has weighted counts of good events g and bad events b. Each event's weight
decays exponentially (M5), halving every half-life T:

```math
w(\text{event}) = e^{-\lambda\,\text{age}} = 0.5^{\,\text{age}/T}, \qquad T = \frac{\ln 2}{\lambda},
\qquad g = \sum_{\text{good}} w, \quad b = \sum_{\text{bad}} w
```

Jøsang and Ismail's Beta reputation (2002) gives an expected trustworthiness and an uncertainty:

```math
E = \frac{g + 1}{g + b + 2}, \qquad u = \frac{2}{g + b + 2}
```

The scorer's evidence is the posterior odds of bad behaviour against good behaviour:

```math
\ell_{\text{trust}} = \ln \frac{b + 1}{g + 1}
```

Fifty recent good logins and no bad ones give ln(1/51) ≈ -3.93 (reassuring, then capped at -ln 10).
A device seen at a honeytoken gets b > 0 and turns suspicious; old behaviour fades, so a laptop that
was clean a year ago does not vouch for itself today.

### 8.6 M6: login time as a circular density

Time of day is circular: 23:59 is next to 00:01. Each past login's minute of day becomes an angle:

```math
\theta = \frac{2\pi \cdot \text{minute}}{1440}
```

The user's habit is a kernel density of von Mises kernels (the circular normal distribution), one per
past login:

```math
f(\theta) = \frac{1}{n} \sum_{i=1}^{n} \frac{e^{\kappa \cos(\theta - \theta_i)}}{2\pi\, I_0(\kappa)},
\qquad
I_0(\kappa) = \sum_{j=0}^{\infty} \frac{(\kappa^2/4)^j}{(j!)^2}
```

Compared with a uniform density 1/(2π) (an attacker logs in at any time), with shrinkage for users
with little history:

```math
\ell_{\text{time}} = -\,\frac{n}{n + 10} \cdot \ln\!\big(2\pi f(\theta)\big)
```

κ = 8 gives each login a spread of about 1/√κ radians ≈ 81 minutes. The scorer needs at least 8
logins. Computed stably with the log-sum-exp trick. Source: Mardia and Jupp, *Directional
Statistics* (2000).

### 8.7 M7: impossible travel

Great-circle distance between the last login and this one (haversine formula, R = 6371.0088 km):

```math
d = 2R \arcsin\!\sqrt{\sin^2\!\frac{\Delta\varphi}{2} + \cos\varphi_1 \cos\varphi_2 \sin^2\!\frac{\Delta\lambda}{2}}
```

GeoIP locations are uncertain, so both accuracy radii a₁ and a₂ are subtracted before computing speed:

```math
v = \frac{\max(0,\; d - a_1 - a_2)}{\Delta t}
```

If v > 1000 km/h (faster than an airliner), the factor is:

```math
\ell_{\text{travel}} = \ln\frac{P(\text{impossible} \mid \text{attack})}{P(\text{impossible} \mid \text{legit})} = \ln\frac{0.60}{0.02} = \ln 30 \approx 3.40
```

The radius correction is Dwarpal's own; it stops VPN-level GeoIP errors from flagging honest users.

### 8.8 Poisson rate tests (brute force, password spray, attack surge)

Counts of failures in a window follow a Poisson distribution. The likelihood ratio of seeing k events
under the attack rate λ_a versus the normal rate λ_l:

```math
\frac{P(k \mid \lambda_a)}{P(k \mid \lambda_l)} = \frac{\lambda_a^k e^{-\lambda_a} / k!}{\lambda_l^k e^{-\lambda_l} / k!}
\quad\Longrightarrow\quad
\ell = \max\!\Big(0,\; k \ln\frac{\lambda_a}{\lambda_l} - (\lambda_a - \lambda_l)\Big)
```

Clamped at 0 so that "few failures" is never reassurance (an attacker cannot buy trust by failing
less). The attack-surge factor is also capped at ln 10, since it says something about the whole
organisation, not this user.

| Scorer | Count k | λ_l | λ_a | First k that adds risk |
|---|---|---|---|---|
| Brute force | Failures on this account, 15 min | 0.2 | 5 | k = 2 (ℓ = 1.64); k = 3 gives 4.86 |
| Password spray | Distinct accounts failing from this IP, 15 min | 0.5 | 10 | k = 4 (ℓ = 2.48); k = 5 gives 5.48 |
| Attack surge | All failures in the organisation, 15 min | 20 | 200 | k = 79 (ℓ = 1.90); capped at 2.30 from k = 80 |

### 8.9 IP reputation

Fixed likelihood ratios for listed sources; only the strongest category counts:

| Category | LR | ℓ |
|---|---|---|
| On an abuse blocklist | 50 | 3.91 |
| Tor exit node | 20 | 3.00 |
| Hosting-provider ASN (humans only) | 10 | 2.30 |

Ratios must be at least 1: being listed can only add risk. This is the threat-intelligence term
p(attack | IP) of Freeman et al.

### 8.10 Audit chain

```math
\text{mac}_n = \text{HMAC-SHA256}\big(K,\; \text{canonical}(\texttt{dwarpal/audit/v1},\, \text{seq}_n,\, \text{at}_n,\, \text{type}_n,\, \text{actor}_n,\, \text{payload}_n,\, \text{mac}_{n-1})\big),
\qquad \text{mac}_0 = 0^{64}
```

The genesis value mac₀ is a string of 64 zero characters. Verification recomputes the chain from
record 1 and reports the first bad sequence number; comparing
the final MAC with the externally anchored head detects truncation.

### 8.11 Policy bundle approval

```math
\sigma_i = \text{Ed25519.sign}\big(sk_i,\; \text{canonical}(\texttt{dwarpal/policy-bundle/v1},\, \text{seq},\, \text{SHA-256}(\text{policy text}),\, t_i)\big)
```

Accepted when at least two σ_i verify under `POLICY_SIGNER` keys with distinct owners, each t_i is at
most 7 days old, and seq is greater than the installed sequence.

### 8.12 The final outcome

```math
\text{outcome} = \max\big(\text{gate},\; \text{cost-optimal}(p),\; \text{policy floor}\big)
```

over the order ALLOW < ALLOW_LIMITED < STEP_UP < DENY, followed by step-up resolution (the only
allowed downward move, STEP_UP to ALLOW or ALLOW_LIMITED) and obligations (read-only means READ only).

### 8.13 M8: change impact of a policy edit

Before a new policy P₂ replaces P₁, the question is which requests would be decided differently:

```math
\Delta = \{\, r \;:\; D_{P_1}(r) ≠ D_{P_2}(r) \,\}
```

Margrave (Fisler et al., ICSE 2005) and Cedar (OOPSLA 2024) compute this exactly with decision
diagrams or SMT solvers. Dwarpal's plan is empirical: **What-If replay** of recorded traffic through
both policies (Layer 5; the freshness gate is switched off for replay, which the engine already
supports). Today's structural part is the linter, which blocks identical conditions with different
effects and shadowed rules before deployment.

---

## 9. Worked examples

All numbers below come from the formulas in section 8 with the reference configuration, for a user
with 200 logins in their history. The prior gives logit(0.001) = -6.907.

### 9.1 Normal morning login

Known IP, known device (proven by signature), 09:10 when the user usually logs in around 09:00, 50
recent good events and no bad ones.

| Factor | Raw ℓ | After caps |
|---|---|---|
| network-novelty (known IP; user's IP new-rate 4/202) | ln(0.01 / 0.980) = -4.59 | |
| device-novelty (known device; new-rate 2/202) | ln(0.05 / 0.990) = -2.99 | |
| login-time (6.5x as typical as a random time) | -0.952 x ln 6.53 = -1.79 | |
| subject-trust (g = 50, b = 0) | ln(1/51) = -3.93 | |
| **Total reassurance** | per-factor caps give 8.70; scaled by s = 0.265 | **-ln 10 = -2.30** |

z = -6.907 - 2.303 = -9.21, so **P(attack) ≈ 0.0001**. That is below the step-up threshold of
0.00105, so the outcome is **ALLOW**, and since P ≤ 0.01 the login also earns reputation. However
familiar everything looks, risk can only fall tenfold below the base rate.

### 9.2 Account takeover from abroad

The attacker has the password, comes from a new IP in a new ISP in a new country, on an unknown
device, 2 hours after the user logged in 7,000 km away.

| Factor | ℓ |
|---|---|
| network-novelty: new IP ln(0.99 / (4/202)) = 3.91, new ASN ln(0.90 / (2/202)) = 4.51, new country ln(0.60 / (1/202)) = 4.80; sum 13.22 | capped at ln 1000 = **6.91** |
| device-novelty: ln(0.95 / (2/202)) | **4.56** |
| impossible-travel: 7,000 km in 2 h = 3,500 km/h | **3.40** |
| **Total** | **14.87** |

z = -6.907 + 14.87 = 7.97, so **P(attack) ≈ 0.9997** → above 0.275 → **DENY** (and policy P-90
denies above 0.9 anyway). An odd login hour such as 03:00 would add a further +5.3.

### 9.3 Medium risk: which MFA is enough?

Suppose the evidence gives P(attack) = 0.05 (step-up territory). The user has just passed MFA:

| Method | β | P(attack) after passing | Decision |
|---|---|---|---|
| Push approval | 0.30 | 0.0155 | STEP_UP again: stronger authenticator required |
| TOTP | 0.10 | 0.0052 | STEP_UP again |
| Number-matching push | 0.05 | 0.0026 | STEP_UP again |
| WebAuthn / passkey | 0.01 | 0.00053 | **ALLOW** |

The same "MFA passed" is worth very different amounts. At lower suspicion (say P = 0.002) any of these
methods is enough: 0.05 x 0.002 / (0.05 x 0.002 + 0.998) ≈ 0.0001 → ALLOW.

### 9.4 Brand-new user (cold start)

No history: w = 0, so P(new | legit) = 1/2 at every level. New IP +0.68, new ASN +0.59, new country
+0.18, new device +0.64; total +2.10. z = -6.907 + 2.10 = -4.81, so **P ≈ 0.008** → **STEP_UP**. After
number-matching push: 0.0004 → ALLOW. A new user proves themselves once, and from then on the
baseline grows from their own allowed logins.

### 9.5 Password spray

One IP fails against 5 different accounts in 15 minutes, then tries a sixth with the right password:
ℓ = 5 ln 20 - 9.5 = **+5.48**. On top of a new-network factor this crosses the deny threshold, while a
single shared office NAT with one failed login adds nothing (k = 1 gives a negative value, clamped to 0).

---

## 10. What makes Dwarpal different from enterprise products

Large organisations today buy Zero Trust as cloud services: identity platforms with conditional
access and risk detection (for example Microsoft Entra ID with ID Protection, Okta, Ping Identity),
access proxies (Google BeyondCorp / Chrome Enterprise Premium, Cloudflare Access) and SASE suites
(Zscaler, Palo Alto Networks Prisma Access, Netskope). Open-source projects provide policy engines
(Open Policy Agent, AWS Cedar) or identity servers (Keycloak).

Dwarpal uses the **same NIST model** and the **same signal families** these products use (new
device, unfamiliar location, impossible travel, password spray, anonymous IPs, device compliance).
The difference is in **how the evidence is combined, explained, protected and governed**. The
comparison below is with what these products publicly document; their internal models are
proprietary.

### 10.1 Comparison

| Aspect | Typical enterprise product | Dwarpal | Why it matters |
|---|---|---|---|
| **Risk output** | A level (low / medium / high) plus named detections; the model behind it is proprietary | A probability, with the prior, every factor's LLR, the caps applied and the thresholds, in each decision | An analyst or auditor can recompute any decision by hand |
| **Choosing the action** | Administrators write rules such as "if risk is high, block; if medium, require MFA" | The action minimises expected loss; thresholds follow from three business costs and the MFA strength | Thresholds are justified, and move automatically when the MFA method changes |
| **Base rate** | Implicit inside trained models | An explicit prior that the whole calculation starts from | Fewer false alarms; one number to tune and defend |
| **MFA strength** | Method allow-lists ("authentication strengths", "phishing-resistant" requirements): a method qualifies or it does not | Each method has a bypass probability β; passing MFA is Bayesian evidence; how much MFA is enough depends on how suspicious the request is | Push approval can be enough for a mildly unusual login and not enough for a highly suspicious one (section 9.3) |
| **Spoofed familiarity** | Not publicly documented | Asymmetric caps: reassurance at most x10 per factor and in total; attack evidence up to x1000 per factor | A thief replaying the victim's device id and browser cannot cancel impossible travel |
| **Device and login claims** | Trusted inside the vendor's own ecosystem (its agent, its identity provider, its tokens) | Vendor-neutral signed evidence: any agent or identity provider with a registered Ed25519 key, documented canonical messages, bound to subject and device, with key purposes | Open, inspectable trust; no lock-in to one vendor's agent |
| **Changing access policy** | One administrator holding the right role edits policy (often after step-up or just-in-time role activation); the change is logged afterwards | Two different administrators sign the exact policy text and a sequence number; older versions are refused; the install is audited before it takes effect | One stolen admin account or one malicious insider cannot change who gets access |
| **Audit integrity** | Logs stored and protected by the vendor; the customer trusts the vendor (some cloud services, such as AWS CloudTrail, offer signed digest files) | HMAC chain the organisation verifies itself, with an external head anchor | Evidence for forensics and non-repudiation without trusting a third party |
| **Logging failure** | Logging is usually asynchronous; access continues if the log pipeline is down | No audit, no access: a decision that cannot be recorded is a DENY | No unrecorded access, ever |
| **Authorisation and conditions** | Usually in separate places: app assignment grants access, conditional-access policies add requirements | One closed language with explicit semantics: grants authorise, constraints only tighten, read-only survives constraints | Fewer gaps between "who is assigned" and "under which conditions" |
| **Read-only sessions** | Enforced by a separate proxy or the application | An obligation enforced inside the decision itself | An enforcement point that misreads "limited" cannot leak downloads |
| **Learning** | Vendor machine learning on global data; administrators can mark sign-ins safe or compromised | Per-user baselines that learn only from full, low-risk ALLOWs on proven devices, with bounded, flood-resistant stores | Explicit, tested resistance to baseline poisoning |
| **Policy safety** | Policies edited in a web console | Hardened YAML loader (no code execution, no aliases, strict schema) plus a linter that blocks conflicts before deployment | Policy-as-code that is safe to review in a pull request |
| **Deployment and transparency** | Closed-source cloud service, priced per user per month, data processed by the vendor | Open source, self-hosted, one runtime dependency, JDK cryptography, sub-millisecond decisions on a laptop | Fits organisations that cannot send identity data to a cloud vendor, and teaching labs |
| **Verifying the vendor** | Certifications and audit reports (SOC 2, ISO 27001, FedRAMP) | Anyone can rebuild it (reproducible builds), read the SBOM, run the 531 tests and re-run CodeQL | Trust by verification rather than by reputation |
| **SASE coverage** | ZTNA, SWG and CASB are often separate products or modules, each with its own policy console | One policy language and one engine decide for private apps, the web and SaaS data; the three PEPs only enforce | One place to read and test who may do what, everywhere |
| **Enforcement point trust** | Connectors and gateways authenticate to the vendor cloud and are trusted for everything they forward | Each PEP has its own certificate, pinned both ways, and is limited to the resources it fronts; it cannot state roles, classification or device management | A stolen gateway credential reaches only that gateway's applications, and still needs a user's MFA and session key |
| **MFA at the edge** | The identity provider decides MFA; the gateway trusts its token | The PA itself verifies the identity provider's signature, the MFA's age and its binding to the session key, and uses each proof once | A token or MFA result copied from another machine opens nothing |
| **Web filtering** | Cloud proxies decrypt TLS and use large commercial category feeds | Host-name filtering without decryption, from local lists the organisation controls; look-alike and SSRF checks built in | No certificate on every laptop, no traffic sent to a vendor; less visibility into page contents |
| **DLP** | Hundreds of trained classifiers, document fingerprinting, OCR | A small set of validated detectors (checksums, not just patterns) with linear-time scans and redaction | Few false positives and predictable cost; far smaller coverage |

### 10.2 Where enterprise products are ahead

Stated plainly, so the comparison stays honest:

| Area | Enterprise products | Dwarpal today |
|---|---|---|
| Threat intelligence | Signals from billions of sign-ins across all customers | Whatever feeds the deployer supplies |
| Model calibration | Models trained and measured on real attack data | Probabilities are stated assumptions, tested on synthetic data |
| Device trust | Hardware attestation (TPM, Secure Enclave), MDM compliance | Agent-signed posture; hardware attestation reserved |
| Sessions | Mature session management at global scale, credential vaulting and session recording | Sessions, continuous evaluation, revocation and JIT admin done (Layer 3); no vaulting or recording |
| Enforcement | Global gateways and points of presence | No enforcement point yet (Layer 4) |
| Integrations | Thousands of applications through SAML and OpenID Connect | Programmatic API only |
| Operations | High availability, 24/7 support, admin consoles, compliance certifications | Single-process library, command line, documentation |

### 10.3 Where Dwarpal fits

- Organisations that must **explain every access decision** (audits, regulated industries, disputes
  about who accessed what).
- Organisations that **cannot or will not send identity data to a cloud vendor**.
- A **decision core** that a gateway, VPN replacement or SaaS proxy can call, sub-millisecond, in-process.
- **Teaching and research**: every formula is visible, testable and replaceable.

---

## 11. DevSecOps: security built in from the first line

Security work happens at every stage, not at the end.

| Stage | Controls |
|---|---|
| **Plan and design** | STRIDE threat model kept with the code (`docs/threat-model.md`); OWASP ASVS 4.0.3 mapping; NIST 800-207 role names used as class names; abuse cases written as tests before or with each feature |
| **Code** | Fail-closed by construction; input allow-lists; immutable objects; no reflection, no scripting, no object deserialisation; all cryptography from the JDK; one runtime dependency (SnakeYAML 2.7) |
| **Commit (local)** | `.githooks/pre-commit` blocks key files, `.env` files and build output; blocks private keys and tokens (AWS, GitHub, Slack patterns); blocks invisible bidi characters; runs gitleaks if installed |
| **Build** | `-Xlint:all -Werror` (every compiler warning fails the build); maven-enforcer requires JDK 25 and Maven 3.9; JaCoCo coverage gate at 80%; reproducible builds (fixed output timestamp) |
| **Test** | 267 tests: unit, abuse cases, attack scenarios, property-based, fuzzing, concurrency, latency, accuracy simulation, source hygiene (no invisible characters in source) |
| **Static analysis** | SpotBugs 4.10.5 with FindSecBugs 1.14.0; CodeQL `security-extended` on every push and weekly |
| **Supply chain** | CycloneDX SBOM as a build artifact; dependency review on pull requests (fails on moderate or worse); Dependabot for Maven and GitHub Actions; OSV.dev scan of all dependencies |
| **CI hardening** | Every GitHub Action pinned to a full commit SHA; least-privilege tokens (`contents: read` by default); `persist-credentials: false` on checkout; gitleaks secret scan over the full history |
| **Suppressions** | Only named classes, each proven safe by a test (`ImmutabilityTest`); no project-wide suppression |
| **Review gate** | Nothing is committed or pushed until the project owner has reviewed and approved it |

### 11.1 CI pipeline

```
push / pull request
   |
   +--> secrets-scan       gitleaks over the full history
   +--> build-test-sast    mvn verify (compile with -Werror, 267 tests, coverage gate)
   |                       -> SpotBugs + FindSecBugs -> CycloneDX SBOM artifact
   +--> analyze            CodeQL security-extended (also weekly)
   +--> dependency-review  pull requests only: block vulnerable new dependencies
```

### 11.2 Toolchain

| Tool | Version | Purpose |
|---|---|---|
| JDK | 25 LTS (Temurin 25.0.5) | Language, Ed25519, HMAC-SHA256, SHA-256; ML-DSA and ML-KEM available |
| Maven | 3.9 | Build |
| SnakeYAML | 2.7 | Policy parsing (only runtime dependency) |
| JUnit | 5.14.4 | Tests |
| JaCoCo | 0.8.16 | Coverage gate |
| SpotBugs / FindSecBugs | 4.10.5.0 / 1.14.0 | Bug and security static analysis |
| CycloneDX Maven plugin | 2.9.3 | SBOM |
| maven-enforcer | 3.7.0 | JDK and Maven version rules |
| CodeQL, gitleaks, dependency-review | pinned SHAs | CI security gates |

### 11.3 Post-quantum readiness

Ed25519 is not quantum-safe: a large quantum computer running Shor's algorithm could forge it. NIST IR
8547 deprecates such signatures after 2030 and disallows them after 2035. HMAC-SHA256 and SHA-256
remain adequate (Grover's algorithm only halves their effective strength).

JDK 25 ships ML-DSA (FIPS 204, JEP 497) and ML-KEM (FIPS 203, JEP 496). Measured on this machine:
ML-DSA-65 signature 3,309 bytes, public key 1,974 bytes, verification about 0.14 ms (Ed25519 about
0.67 ms). The plan is **hybrid signatures**: every proof carries both an Ed25519 and an ML-DSA
signature, and both must verify, so the system stays secure if either algorithm is broken.

---

## 12. Testing and quality evidence

### 12.1 Test suite (531 tests)

| Test class | Tests | What it proves |
|---|---|---|
| PolicyAdministratorTest | 28 | Layer 3A: opening, every check on a use, replay, stolen tokens and keys, limits, re-authentication, read-only, continuous evaluation, revocation, capacity, no audit no session, fuzzing, concurrency, latency, the stolen-laptop scenario |
| ScorersTest | 21 | Every scorer's formula against hand-computed values |
| PrivilegedAccessTest | 20 | Layer 3B: JIT window, eligibility, MFA rules, self-approval, exact approvals, lapse, revocation, break-glass and review, rate limits, bounds, no audit no elevation |
| SafePolicyLoaderTest | 20 | Malicious, malformed and oversized policy files are refused |
| PolicyEngineTest | 20 | Pipeline behaviour, fail-closed paths, explanations, no standing admin rights |
| EvidenceAndStepUpTest | 17 | Signature rules, freshness, device binding, MFA as evidence |
| BehaviorStoresTest | 17 | Store bounds, flooding resistance, learning rules |
| AuditLogTest | 11 | Chain detects edits, deletions, insertions, reordering and truncation |
| BreachRegressionTest | 10 | Every attack found in red-team passes stays blocked |
| AttackScenariosTest | 10 | End-to-end stories: normal morning login, brand-new user, credential stuffing from abroad, impossible travel, password spray, brute force, a real trip (strong MFA once, then learned), cloud server with a stolen password and a spoofed laptop id, Tor exit at the usual hour, repeated attacks trying to poison the baseline |
| SanitizeAndLimitsTest | 9 | Log injection, Trojan Source characters, size limits |
| SessionHardeningTest | 8 | Layer 3 second red-team pass: reclassification, back-dating, MFA replay, no standing admin, dead sessions, audit floods |
| SessionPartsTest | 8 | Replay cache, limits, token secrecy, signed failure reports |
| PolicyInstallerTest | 11 | Two-person rule, rollback refusal, expired approvals, wrong key purpose, junk floods neither flood the audit trail nor lock anyone out |
| PolicySetTest | 8 | Grants vs constraints, combining algorithms |
| BayesianRiskAggregatorTest | 8 | Caps, order independence, posterior values |
| KeyRingTest | 7 | Purpose, binding, validity, skew, age, cache |
| CostModelTest | 7 | Expected losses and closed-form thresholds |
| DomainValidationTest | 6 | Identifier and number validation |
| PolicyLinterTest | 5 | Conflicts and shadowing |
| PropertyTest | 4 | Over 7,000 random cases: more attack evidence never lowers P(attack) or loosens the action; scorer order never matters |
| FuzzAndConcurrencyTest | 3 | Random requests never crash the engine or corrupt the audit trail; parallel load keeps the chain intact; p99 latency under 20 ms |
| RateLimiterTest | 3 | Windows, bounded keys, settings |
| DecisionPipelineTest | 2 | Safe wrapping order |
| JustInTimeAdminSessionTest | 1 | Both halves of Layer 3 together: admin inside a session lives exactly as long as the grant |
| AccuracySimulationTest | 1 | 60 synthetic users, legitimate and attack traffic |
| ImmutabilityTest | 1 | Every object with a SpotBugs exposure suppression really is immutable |
| SourceHygieneTest | 1 | No invisible or bidi characters anywhere in the source |

Layer 4 (enforcement points):

| Test classes | Tests | What they prove |
|---|---|---|
| EndToEndTest, CrossPartRedTeamTest | 9 | All parts through the real API over mutual TLS: agent to gateway to PA; browser tunnels through the web gateway; SaaS uploads through the data guard; SOC revocation; API outage is a deny; the cross-part attacks stay blocked |
| ApiServerTest, ApiRedTeamTest, ApiScopeTest, ApiBodiesTest, ApiPartsTest, ApiLatencyTest | 40 | Mutual TLS, exact callers, roles and resource scopes, strict bodies, generic errors, slow-loris, floods, fuzzing, pinning, audit, latency |
| Gateway*Test, ClientAgentTest, DevIdentityProviderTest | 64 | ZTNA flow on real sockets, header and path tricks, method override, redirects, stolen tokens, replay, slow logins, MFA and phishing resistance, lockout, latency |
| Swg*Test, WebAccessTest, WebGateway*Test, HostNameAndListsTest, AddressesAndParsingTest, HttpsProxyTest, WebLatencyTest | 62 | Host canonicalisation, block lists, look-alikes, numeric IPs, SSRF, strict HTTP heads, tunnels, limits, HTTPS-proxy mode |
| DataGuardTest, CasbRedTeamTest, DetectorsTest, InspectionAndResultsTest, DetectorPerformanceTest | 50 | Validated detectors, DLP actions per classification, redaction, encodings, evasion with invisible characters, linear-time scans, read-only sessions |
| EdgeContractTest, EdgeValidationTest, TlsContextsTest, JsonTest, MfaAtOpenTest | 39 | Shared contracts, header stripping, TLS 1.3 settings and pinning, the strict JSON reader, MFA required at session open |

### 12.2 Results

| Measure | Value |
|---|---|
| Tests | 267 passing |
| Coverage | 96.9% of lines, 88.7% of branches (gate: 80%); every Layer 3 package above 80% branch coverage |
| Static analysis | 0 SpotBugs / FindSecBugs findings; CodeQL green on the last push |
| Dependencies | 9 in total, all clean on OSV.dev |
| Latency, full pipeline (10 scorers, audit, learning) | p50 0.08 to 0.3 ms, p99 under 1.2 ms (requirement: p99 under 20 ms) |
| Latency, one session use (token, key proof, replay check, engine, audit) | p50 0.7 to 1.1 ms, p99 1.3 to 3.4 ms |
| Accuracy simulation (60 synthetic users) | 0 of 300 legitimate logins denied; 0 of 60 normal logins asked for MFA; 0 of 360 password-only attacks allowed |
| CI on GitHub | Checks run on every push (secret scan, build/test/SAST, CodeQL); see the Actions tab for the latest commit |

The accuracy numbers come from our own traffic generator, so they show the engine is consistent with
its threat model, not real-world accuracy. Real-world calibration is Layer 5.

---

## 13. Standards and research behind the design

### 13.1 Standards and frameworks

| Reference | Used for |
|---|---|
| NIST SP 800-207, *Zero Trust Architecture* (2020) | PE / PA / PEP / PIP roles, tenets |
| NIST SP 1800-35, *Implementing a Zero Trust Architecture* | Reference deployments, SASE components |
| CISA *Zero Trust Maturity Model* v2.0 (2023) | Pillars and maturity mapping |
| NIST SP 800-162 and OASIS XACML 3.0 | Attribute-based access control, combining algorithms |
| OWASP ASVS 4.0.3 | Verification requirements (mapping in `docs/security-architecture.md`) |
| NIST SP 800-63B | Authenticator strength, phishing resistance |
| NIST IR 8547 (draft, 2024) | Post-quantum transition timeline |
| FIPS 203 / FIPS 204 | ML-KEM / ML-DSA |
| RFC 8032 | Ed25519 |
| RFC 2104, FIPS 180-4 | HMAC, SHA-256 |
| MITRE ATT&CK T1110 (brute force, spraying), T1078 (valid accounts); MITRE Engage | Attack patterns, honeytokens |
| CVE-2022-1471, CVE-2021-42574, CWE-117 | YAML deserialisation, Trojan Source, log injection |

### 13.2 Research papers

| Model | Paper |
|---|---|
| M3 | S. Axelsson, "The base-rate fallacy and the difficulty of intrusion detection", *ACM TISSEC* 3(3), 2000 |
| M2 | C. Elkan, "The foundations of cost-sensitive learning", *IJCAI* 2001 |
| M1, IP reputation | D. M. Freeman, S. Jain, M. Dürmuth, B. Biggio, G. Giacinto, "Who are you? A statistical approach to measuring user authenticity", *NDSS* 2016 |
| M4 | A. Jøsang, R. Ismail, "The Beta reputation system", *Bled eCommerce Conference* 2002 |
| M6 | K. V. Mardia, P. E. Jupp, *Directional Statistics*, Wiley, 2000 |
| Principles | J. H. Saltzer, M. D. Schroeder, "The protection of information in computer systems", *Proc. IEEE* 63(9), 1975 |
| Zero Trust in practice | R. Ward, B. Beyer, "BeyondCorp: A new approach to enterprise security", *;login:* 39(6), 2014 |
| M8 | K. Fisler et al., "Verification and change-impact analysis of access-control policies" (Margrave), *ICSE* 2005; J. Cutler et al., "Cedar: A new language for expressive, fast, safe, and analyzable authorization", *OOPSLA* 2024 |
| Trojan Source | N. Boucher, R. Anderson, "Trojan Source: Invisible vulnerabilities", *USENIX Security* 2023 |

---

## 14. Assumptions and known limits

Stated openly, each with where it will be addressed:

| Limit | Effect | Addressed in |
|---|---|---|
| **Stolen, unlocked laptop used at the victim's home with their password** | Looks exactly like the victim to Layers 1 and 2 | **Narrowed by Layer 3:** cut off at the next re-authentication (at most 4 h for INTERNAL, 15 min for RESTRICTED), and no session left after 30 min idle |
| **Assumed probabilities** (P(new given attack), MFA β, Poisson rates, likelihood ratios) | Decisions are only as good as these numbers | Layer 5: calibration from real logs, sensitivity analysis |
| **Correlated evidence** (network novelty and impossible travel) | Counted twice under naive Bayes; bounded by the caps | Layer 5: correlation-aware weighting |
| **Single decisions outside a session** | Engine-only callers may still send unbound MFA proofs (`authentication/v2`) | Closed for sessions in Layer 3; retire v2 once the enforcement point (Layer 4) always goes through the PA |
| **Hardware attestation not verified** | Posture at most AGENT_SIGNED | Future: TPM / platform attestation |
| **Audit key in process memory** | Protected by the operating system, not an HSM | Deployment: KMS or HSM |
| **Ed25519 is not quantum-safe** | Long-term forgery risk after about 2030 | Hybrid Ed25519 + ML-DSA (JDK 25 ready) |
| **In-memory stores** | Behaviour history, sessions and grants are lost on restart | Layer 4/5: persistent stores (tokens stay hashed) |
| **No runnable demo yet** | The engine is exercised through tests only | Next step |

---

## 15. Progress log

### Day 1: 2026-11-01

| Step | Work |
|---|---|
| 1 | Idea defined: a Zero Trust access decision engine. Research across NIST SP 800-207, NIST SP 1800-35, CISA ZTMM, SASE (ZTNA, SWG, CASB) and the research papers in section 13. Name chosen: Dwarpal |
| 2 | Plan stress-tested against itself and weak points designed out before coding; requirements written (functional and non-functional, such as p99 latency under 20 ms) |
| 3 | Scope clarified: Dwarpal is the Policy Engine plus parts of the Policy Administrator and the information points, not only a PDP |
| 4 | Constraints fixed: Java as main language, 5-day deadline, one developer-analyst, 8 GB RAM, no Docker. Mathematical models M1 to M9 selected |
| 5 | **Layer 1 built**: domain model, safe policy loader and linter, Bayesian risk (M3), cost model (M2), seven-stage pipeline, hard gates, explained decisions. DevSecOps pipeline from the first commit: CI, SpotBugs, CodeQL, coverage gate, SBOM |
| 6 | Red-team passes against the core; every attack kept as a permanent regression test |
| 7 | **Defence in depth added**: Ed25519 signed device posture and login proofs, device-bound sessions, key ring with key purposes, MFA as Bayesian evidence with per-method β, HMAC audit chain with "no audit, no access", two-person signed policy bundles with rollback guard; OWASP ASVS mapping and security architecture document |
| 8 (22:30) | GitHub repository created; **Layer 1 pushed** (`3044460`) |
| 9 | **Layer 2 built**: ten scorers (M1, M4/M5, M6, M7, Poisson rate tests, IP reputation), behaviour stores, learning loop, attack scenarios; two red-team passes over both layers |
| 10 | Post-quantum assessment: NIST IR 8547 timeline, ML-DSA available in JDK 25, hybrid plan agreed for after submission |

### Day 2: 2026-11-02

| Time | Work |
|---|---|
| 00:04 | **Layer 2 pushed** (`300cf29`) after review |
| 08:32 | **Moved to JDK 25 LTS** (`89af015`); ML-DSA measured; accuracy simulation (60 users) and property tests (7,000+ random cases) added |
| 09:09 | Repository made public; all GitHub Actions updated to Node 24 releases pinned to commit SHAs (`0f8f46b`); CodeQL and dependency review active |
| 09:11 | CodeQL job permissions aligned with GitHub's template (`9b69af4`); all CI checks green |
| 10:20 | **Layers 1 and 2 completed** (`d7dff6b`): safe policy loading from files, local pre-commit hook, reproducible builds, consolidated report; all CI checks green |
| 12:21 | Project state document pushed (`a717096`) |
| 12:30 | **Layer 3 part A built** (sessions): tokens, proof of possession, replay cache, limits, re-authentication, continuous evaluation, revocation, signed failure reports; red-team pass 1 (R1) |
| 13:15 | Red-team pass 2 on part A (R2 to R6): reclassification, back-dating, MFA replay (key-bound MFA, `authentication/v3`), no standing admin in the reference policy, dead sessions |
| 14:15 | **Layer 3 part B built** (privileged access): just-in-time elevation with signed approvals, break-glass with review, rate limits; red-team pass 3 (R7, quota exhaustion); 267 tests green; reviewed, approved and pushed |

### Commit history

| Commit | Date | Content |
|---|---|---|
| `3044460` | 2026-11-01 22:30 | Layer 1: hardened Zero Trust policy engine core |
| `300cf29` | 2026-11-02 00:04 | Layer 2: behavioural risk scorers |
| `89af015` | 2026-11-02 08:32 | JDK 25 LTS, accuracy and property testing |
| `0f8f46b` | 2026-11-02 09:09 | CI actions on Node 24, pinned to SHAs |
| `9b69af4` | 2026-11-02 09:11 | CodeQL job permissions |
| `d7dff6b` | 2026-11-02 10:20 | Completion of layers 1 and 2 |
| `a717096` | 2026-11-02 12:21 | Project state document |
| (Layer 3 commit) | 2026-11-02 | Layer 3: Policy Administrator (sessions, privileged access) |

### Documents in the repository

| Document | Content |
|---|---|
| `README.md` | Overview, build commands |
| `SECURITY.md` | Vulnerability reporting, built-in safeguards |
| `docs/threat-model.md` | STRIDE threat model, attack cases, residual risks |
| `docs/security-architecture.md` | Defence in depth, IAM and PAM, encryption, ASVS mapping, post-quantum readiness |
| `docs/layer-1-report.md`, `docs/layer-2-report.md`, `docs/layer-3-report.md` | Per-layer reports (Layer 3 in full detail) |
| `docs/report-layers-1-2.md` | Consolidated report |
| `docs/project-state.md` | This document |

---

## 16. Roadmap

The whole project has six layers:

| Layer | Name | Content | Status |
|---|---|---|---|
| 1 | Core decision engine | One explained decision per request from signed evidence, policy and Bayesian risk; audit chain; two-person policy changes | Done |
| 2 | Behavioural risk scorers | Ten detectors that turn a login into evidence; poisoning-resistant learning | Done |
| 3 | Policy Administrator | A: sessions bound to a client key, re-checked on every request, revocable. B: no standing admin, just-in-time elevation, break-glass | Done |
| 4 | Enforcement and SASE edge | The gateway in front of applications (ZTNA proxy, web gateway, SaaS/DLP controls) calling Layers 1 to 3 over an mTLS API; what the demo talks to | Next |
| 5 | SOC loop and analytics | SIEM shipping of the audit chain, alerts, analyst feedback with decaying signals (M5), What-If replay (M8), calibration and accuracy measurement | Planned |
| 6 | Console, demo and deployment | Web front end for users, admins and analysts; demo deployment (for example Vercel) | When requested |
| Cross-cutting | Post-quantum | Hybrid Ed25519 + ML-DSA signatures on every proof (signature field grows from 256 characters to about 4.5 KB) | After submission |

---

## 17. Glossary

| Term | Meaning |
|---|---|
| ABAC | Attribute-based access control: decisions from attributes of subject, resource, action and environment |
| ASN | Autonomous System Number: identifies the network operator (ISP, hosting company) an IP belongs to |
| β (beta) | Probability that an attacker passes a given MFA method |
| Base rate / prior | How common attacks are before looking at any evidence |
| CASB | Cloud Access Security Broker: controls use of SaaS data |
| DPoP | Demonstrating Proof of Possession: binding a token to a key the client holds |
| Break-glass | An emergency account whose sealed credential grants privilege without an approver, under alerting and mandatory review |
| HMAC | Keyed hash: proves a record was made by someone holding the key |
| Honeytoken | A decoy account, device or credential; any use signals compromise |
| JIT elevation | Just-in-time privilege: a role held only for an approved, short window |
| LLR | Log-likelihood ratio: ln of how much more likely the evidence is under attack than under normal use |
| Logit | ln(p / (1 - p)): probability on the log-odds scale |
| PDP / PE / PA / PEP / PIP | Policy Decision Point / Engine / Administrator / Enforcement Point / Information Point (NIST 800-207) |
| PAM | Privileged Access Management: controls on administrator rights |
| Posterior | Probability of attack after the evidence |
| Proof of possession | A signature with a key only the legitimate client holds, sent with each use of a token |
| SASE | Secure Access Service Edge: networking and security (ZTNA, SWG, CASB) delivered as one service |
| SBOM | Software Bill of Materials: list of every component in the build |
| Step-up | Asking for additional authentication before allowing access |
| SWG | Secure Web Gateway: controls outbound web access |
| ZTNA | Zero Trust Network Access: per-application access instead of network-wide VPN access |

---

## 18. Appendix: configuration reference

| Setting | Value | Where |
|---|---|---|
| Prior P(attack) | 0.001 (reference) | `BayesianRiskAggregator` |
| Attack cap per factor | ln 1000 (reference) | `BayesianRiskAggregator` |
| Reassurance cap per factor / total | ln 10 / ln 10 | `BayesianRiskAggregator` |
| Costs C_B / C_F / C_D | 1000 / 1 / 20 (reference) | `CostModel` |
| Challenge method and β | Number-matching push, 0.05 | `AssuranceSettings` |
| MFA β | Password 1.0, push 0.30, SMS 0.20, TOTP 0.10, number match 0.05, WebAuthn 0.01 | `AuthMethod` |
| Step-up freshness | 15 minutes | `AssuranceSettings` |
| Posture freshness | 24 hours | `AssuranceSettings` |
| Signature clock skew | 2 minutes | `KeyRing` |
| Verification cache | 10,000 entries (LRU) | `KeyRing` |
| Policy approvals | 2 distinct owners, at most 7 days old, at most 16 per bundle | `PolicyInstaller`, `PolicyBundle` |
| Audit key | At least 32 bytes | `AuditLog` |
| Policy file limits | 256 KiB, depth 16, 10,000 nodes, 1,000 policies | `SafePolicyLoader` |
| Learning: max clock skew / max risk for reputation | 5 minutes / 0.01 | `DecisionPipeline` |
| Novelty window | Last 200 logins | `InMemoryBehaviorHistory` |
| Novelty P(new given attack) | IP 0.99, ASN 0.90, country 0.60, device 0.95 | `NoveltyScorer` |
| Impossible travel | 1000 km/h; LR 0.60 / 0.02 | `ImpossibleTravelScorer` |
| Login time | κ 8, at least 8 logins, shrinkage 10 | `LoginTimeScorer` |
| Brute force / spray / surge | 15 min; λ 0.2 vs 5 / 0.5 vs 10 / 20 vs 200 (cap ln 10) | `FailureRateScorer`, `AttackSurgeScorer` |
| IP reputation | Abuse 50, Tor 20, hosting 10 (humans) | `IpReputationScorer` |
| Store bounds | 100,000 users; 200,000 trust entities; 100,000 failure keys; 2,000,000 intel entries | `behavior`, `pip` |
| Session limits | Idle 30 min; lifetime 10 h; re-authentication 8 h / 4 h / 1 h / 15 min by classification; 5 per user, 100,000 total | `SessionLimits` |
| Proofs of possession and bindings | At most 2 min old; replay entries kept 4 min, 200,000 at most | `SessionLimits`, `NonceCache` |
| Session revocation on denial | Action READ, hard gate, fail-closed, or P(attack) at least 0.05 | `SessionLimits` |
| Elevation | At most 1 h (hard cap 8 h); requests lapse after 30 min; WebAuthn at most 5 min old; approvals at most 5 min old | `PamSettings` |
| Break-glass | 30 min; 3 per account per day; failed-attempt pages at most 5 per hour | `PamSettings`, `PrivilegedAccessManager` |
| PAM rate limits | 5 genuine requests per person per hour; 20 genuine approvals per approver per hour | `PamSettings` |
| Audit throttles | Refusals 20 per type and person per minute; policy rejections 10 per name and 100 overall per hour | `PolicyAdministrator`, `PrivilegedAccessManager`, `PolicyInstaller` |

### How to build and verify

```bash
git config core.hooksPath .githooks
mvn verify spotbugs:check cyclonedx:makeAggregateBom
```
