# Layer 3 report: the Policy Administrator

*Status 2026-11-02: Layer 3 complete (parts A and B), reviewed and approved. Built on Layers 1 and 2.*

## 1. Where Layer 3 sits in the whole project

Dwarpal has **six layers**. Each one is usable on its own and is the base for the next.

| Layer | Name | In one or two sentences | Status |
|---|---|---|---|
| 1 | Core decision engine | Decides ALLOW / read-only / STEP_UP / DENY for one request from signed evidence, policy and Bayesian risk, and explains why. Protected by signatures, an HMAC audit chain and two-person policy changes. | Done |
| 2 | Behavioural risk scorers | Ten detectors (new network or device, impossible travel, odd hour, reputation, brute force, spray, attack surge, bad IPs) that turn a login into evidence for Layer 1. They learn each user's habits without being poisoned. | Done |
| **3** | **Policy Administrator** | **Turns the engine's "yes" into short, client-bound sessions that are re-checked on every request and revocable at once (part A), and removes standing admin rights with just-in-time, approved, time-boxed elevation and break-glass (part B).** | **Done (this report)** |
| 4 | Enforcement and SASE edge | The gateway that actually stands in front of applications (ZTNA proxy, web gateway, SaaS/DLP controls) and calls Layers 1 to 3 over an authenticated API (mTLS). This is what the demo front end will talk to. | Next |
| 5 | SOC loop and analytics | Ships the audit trail to a SIEM, raises alerts, lets analysts feed verdicts back (with decaying signals, M5), and replays recorded traffic against a proposed policy (What-If, M8). Calibrates the assumed probabilities on data and measures accuracy. | Planned |
| 6 | Console, demo and deployment | The web front end for users, admins and analysts (sessions, approvals, alerts, explanations), deployed for the demo (for example on Vercel). | When you ask for the demo |

Cross-cutting, after the college submission: hybrid post-quantum signatures (Ed25519 + ML-DSA) for
every signed message.

Layer 3 has **two parts**: **A, sessions**, and **B, privileged access**.

## 2. What Layer 3 is about

Layers 1 and 2 answer one question per request. A real user logs in once and then works for hours,
and an administrator needs extra power for a short time. NIST SP 800-207 gives this to the **Policy
Administrator (PA)**: it turns decisions into sessions, keeps judging them, and ends them when the
engine, a policy or an incident says so. Privileged Access Management (PAM) is the same idea for
administrator rights: nobody holds them permanently.

```
          Layer 1-2: Policy Engine                       Layer 3: Policy Administrator
login --> decide(login) -- ALLOW -->  A: open session (token + session key + limits)        --> client
use   --> check token, key proof, replay, limits --> decide(use) again (continuous evaluation)
          ALLOW: go on    STEP_UP: re-authenticate    DENY: revoke    incident: revoke user/device
admin --> B: request role (eligible, WebAuthn, reason) --> approver signs --> role exists for 1 h
          break-glass: sealed credential --> 30 min, SOC alerted, reviewed afterwards
```

## 3. Part A: sessions

### 3.1 What a session is

| Element | Design | Why |
|---|---|---|
| Token | 256-bit random, base64url; only its SHA-256 is stored; never printed or audited | A dump of the store or a log line gives nothing to present |
| Session key | The client generates an Ed25519 key pair at login; the session is bound to its public key | A stolen token is useless without the private key |
| Proof of possession | Every use is signed with the session key over (session, request id, subject, device, resource, action, time), at most 2 min old | The idea of DPoP (RFC 9449): a proof cannot be moved to another request |
| Replay protection | Each request id is single-use per session; kept 4 min (proof age + clock skew) | A captured request cannot be sent again |
| Device binding at login | If the login carries a signed device report, the device agent must also sign this session key for this login, within 2 min, once | A device report (valid 24 h) cannot be replayed to open a session for another key |
| Key-bound MFA | The identity provider signs the session key's thumbprint into each MFA proof (`authentication/v3`); the PA refuses any MFA claim not bound to the session key | A captured MFA proof is useless with another key |
| Live clock | Requests more than 2 min from the PA clock are refused | No back-dated or future-dated logins |
| Continuous evaluation | The engine decides every use again | A deny-list entry, honeytoken hit or rising risk applies on the next request |
| Limits | Idle 30 min; lifetime 10 h; re-authentication every 8 h / 4 h / 1 h / 15 min for PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED, using the stricter of the opening and the current classification | The more sensitive the data, the shorter an unattended or stolen session lasts |
| Revocation | By session, user or device; removed first, audited second | The SOC's kill switch; a broken audit trail never keeps a session alive |
| Bounds | 100,000 sessions, 5 per user (oldest closed, dead ones closed as expired first), 200,000 replay entries; refuse when full | No memory exhaustion; never forget a live replay entry |
| Audit | Opening, ending and every refusal; refusals throttled to 20 per type and user per minute | Accountability without letting a flood flood the trail |
| Login failures | Only identity-provider-signed, recent, single-use failure reports reach the brute-force and spray detectors | Nobody can lock users out with fake failures |

### 3.2 Every use, step by step

| Step | Check | On failure |
|---|---|---|
| 1 | Request time within 2 min of the PA clock | REJECTED |
| 2 | Token well-formed (43 base64url characters) and matches a live session | REJECTED (counted) |
| 3 | Not past its lifetime, not idle 30 min | Ended, audited as expired |
| 4 | Same subject and device as the session | **Revoked as token theft** |
| 5 | Same resource | REJECTED, session continues |
| 6 | Signature with the session key over this exact request | REJECTED, audited |
| 7 | Request id not used before | REJECTED, audited |
| 8 | Any MFA claim is bound to this session's key | REJECTED, audited |
| 9 | Read-only session: READ only | DENIED, session continues |
| 10 | Re-authentication due? Needs fresh (15 min), signed, step-up-grade, key-bound MFA | STEP_UP |
| 11 | **The engine decides again** | ALLOW: granted. Read-only: granted, session becomes read-only for good. STEP_UP. DENY: ends the session if the action was READ, a hard gate fired, signals failed closed, or P(attack) ≥ 0.05; otherwise only that action is refused |

## 4. Part B: privileged access

### 4.1 No standing admin

The reference policy used to let every employee perform ADMIN actions on internal apps (with MFA).
Now the grants P-01, P-02 and P-20 cover READ, WRITE and DOWNLOAD only, and a new grant **P-06**
allows ADMIN only to holders of the `admin` role. Nobody has that role in the identity store. It
exists only while a just-in-time grant is active: `ElevatedDirectory` adds active grants to the
roles the engine sees, so the role appears and disappears on the very next decision. P-05 still
demands fresh MFA for every single admin action.

### 4.2 Just-in-time elevation

| Step | Rule |
|---|---|
| Request | The subject must be **eligible** for the role (configured, like eligible assignments in enterprise PAM); duration at most 1 h (settings cannot exceed 8 h); a written justification (10 to 500 characters); **WebAuthn at most 5 min old**, signed by the identity provider, **used once** |
| Approve | A **different person** signs (request id, subject, role, duration) with an `ELEVATION_APPROVER` key bound to them, at most 5 min old; a request nobody approves lapses after 30 min |
| Active | The role exists from approval until the end of the window; every admin action still needs fresh, key-bound MFA |
| End | At the end of the window, on revocation (by grant or subject), or by `purgeExpired()`; audited |

### 4.3 Break-glass

For emergencies when no approver can be reached: a designated account (for example `bg-admin-1`)
opens its **sealed credential** (a `BREAK_GLASS` key, kept offline), which signs the role and the
justification. The role lasts **30 minutes**, the **SOC is paged at once**, and the use goes on a
**review list**. Someone else must sign a verdict, `justified` or `misuse`; misuse ends the grant at
once and pages the SOC again. At most 3 uses per account per day; each signature works once.

### 4.4 Rate limits, and what counts

| Operation | Limit | Counted when |
|---|---|---|
| Elevation requests | 5 per subject per hour | After the requester's MFA is verified |
| Approvals | 20 per approver per hour | After the approval signature is verified |
| Break-glass | 3 per account per day | After the sealed credential is verified |
| Failed break-glass pages | 5 per account per hour | Each failed attempt |
| Refusal audit records | 20 per type and person per minute | Each refusal |
| Policy-install rejections audited one by one | 10 per requester name and 100 overall per hour, then one summary | Each rejection; a correctly approved bundle is **never** blocked |

The "counted when" column is the lesson of red-team finding R7: a limit that counts before checking
who is asking lets anyone lock a real administrator out.

## 5. The maths of Layer 3

**Re-authentication deadline** for a session on a resource of classification c (current and at opening):

```math
t_{\text{reauth}} = t_{\text{last verified MFA}} + \min\big(I(c_{\text{open}}),\ I(c_{\text{now}})\big),
\qquad I = 8\,\text{h},\ 4\,\text{h},\ 1\,\text{h},\ 15\,\text{min}
```

**Window of an attacker at an unlocked laptop** (user stops at t₀, attacker arrives at t₁):

```math
W = \begin{cases} 0 & t_1 - t_0 \ge 30\ \text{min} \\ \min\big(t_{\text{reauth}},\ t_{\text{expiry}}\big) - t_1 & \text{otherwise} \end{cases}
```

Before Layer 3, W had no bound.

**Replay cache retention.** Proofs are accepted at most A = 2 min old and S = 2 min in the future,
so a value must be remembered for R = A + S = 4 min, exactly as long as any message carrying it can
still verify.

**Token guessing.** With N live sessions, one guess succeeds with probability N / 2²⁵⁶ ≈ 10⁻⁷² for
N = 100,000, and a correct guess is still useless without the session key.

**Privilege exposure.** Measured in hours per year during which an account holds admin rights:

```math
E_{\text{standing}} = 365 \times 24 = 8{,}760\ \text{h}
\qquad
E_{\text{JIT}} = \sum_{\text{grants}} \text{duration} \;\;(\text{e.g. } 3 \text{ per week} \times 1\ \text{h} = 156\ \text{h})
```

That is a 98% smaller window for a stolen admin account to be useful, and every hour of it is tied to
a named approver and a written reason. Break-glass adds at most 3 × 30 min = 1.5 h per account per
day, each use paged and reviewed.

## 6. Red-team passes on Layer 3

Every breach below was first reproduced as a working exploit, then fixed, and is now a permanent
regression test (details in [threat-model.md](threat-model.md), v0.7 and v0.8).

| # | Breach (before the fix) | Fix |
|---|---|---|
| R1 | A captured login replayed with the attacker's own session key opened a session as the victim's verified laptop | Device agent must bind the session key at login |
| R2 | A resource reclassified to CONFIDENTIAL kept the 4 h re-authentication of INTERNAL | Stricter of opening and current classification |
| R3 | A login dated 3 h in the past opened a session | Requests must be within 2 min of the PA clock |
| R4 | A captured MFA proof plus the password opened a session on a device without an agent | Key-bound MFA proofs (`authentication/v3`) |
| R5 | Every employee had standing admin rights on internal apps | No standing admin: P-06 plus just-in-time grants |
| R6 | Idle sessions counted towards the per-user limit and were never reported as expired | Dead sessions closed and audited first; scheduled purge |
| R7 | Junk sent in someone's name used up their elevation, approval or policy-install quota | Only authenticated actions count; junk is refused and throttled |
| P6, P7 | SpotBugs findings in the builder; refusal floods could flood the audit trail | Audit log required by construction; throttled refusal audits |

Attacks that were tried and held without changes: stolen token from another machine; replay of a
captured request; a READ proof reused for WRITE; stale, future-dated and mislabelled proofs; token
presented from another device; download in a read-only session; 2,000 malformed tokens; 50 parallel
replays (exactly one wins); forged, replayed, re-targeted, stale and future failure reports;
self-approval; approvals signed for another duration, role or request, or with a policy-signing key;
stale approvals; lapsed requests; push or stale MFA for privilege; replayed MFA; break-glass by a
normal account, for another role, with another justification, replayed, or self-reviewed; audit
trail down while opening a session, approving, or breaking glass.

## 7. Tests and results

| Measure | Result |
|---|---|
| New tests in Layer 3 | 71 (sessions 45, PAM 20, rate limiter 3, policy installer and engine 3) |
| Whole project | **267 tests, all passing** (196 after Layer 2) |
| Coverage | 96.9% lines, 88.7% branches overall; `session` 95.7% / 86.0%; `pam` 97.0% / 82.4%; `guard` 98.3% / 83.3% |
| Static analysis | SpotBugs + FindSecBugs: 0 findings |
| Compiler | `-Xlint:all -Werror`: clean |
| Latency of one session use | p50 0.7 to 1.1 ms, p99 1.3 to 3.4 ms over several runs (target 20 ms) |
| Concurrency | 200 parallel uses all served; 50 parallel replays, exactly 1 accepted |

## 8. How this compares with enterprise products

| Aspect | Typical enterprise (identity platform sessions, PIM, CyberArk-style PAM) | Dwarpal Layer 3 |
|---|---|---|
| Session tokens | Bearer tokens; some platforms add device binding inside their own ecosystem | Every use signed with a client key; single-use request ids; device-agent binding at login |
| Continuous evaluation | Event-driven revocation for selected events (for example CAE) | The engine re-decides every request, so every signal counts on the next request |
| Re-authentication | Sign-in frequency set per policy | Set by data classification, tightened automatically when a resource is reclassified |
| JIT elevation | Eligible roles, approval, justification, MFA, time limit (similar) | Approval is a signature over the exact request (person, role, duration); MFA proof single-use; every admin action still needs fresh key-bound MFA |
| Break-glass | Excluded emergency accounts, monitored by alert rules | Sealed credential signs role and reason; 30 min; immediate page; mandatory signed review; misuse revokes |
| Audit | Vendor-held logs | HMAC chain verifiable by the organisation; no audit, no session and no elevation |
| Where they are ahead | Session management at global scale, mature consoles, vaulted credential injection, session recording | Not built (console in Layer 6; recording out of scope) |

## 9. Remaining risks (stated, scheduled)

| Risk | Plan |
|---|---|
| Single decisions sent straight to the engine (not through the PA) may still use unbound MFA proofs (v2) | Retire v2 once the enforcement point always goes through the PA (Layer 4) |
| Break-glass admin actions still need MFA from the identity provider | Offline emergency procedure for "identity provider down" (Layer 5 runbook) |
| Any approver key can approve any role; one person with two accounts could approve themselves | Per-role approver groups in the console (Layer 6) |
| Sessions, grants and replay entries live in memory; a restart ends them | Persistent stores (Layer 4/5), tokens stay hashed |
| A stolen token presented from another device ends the victim's session | Accepted: ending a possibly stolen session is the safe side |

## 10. Files

| Path | Content |
|---|---|
| `src/main/java/dev/dwarpal/session/` | Part A: `PolicyAdministrator`, `SessionStore`, `Session`, `SessionLimits`, `SessionGrant`, `SessionResult`, `FailureReportReceiver` (1,088 lines) |
| `src/main/java/dev/dwarpal/pam/` | Part B: `PrivilegedAccessManager`, `ElevatedDirectory`, `ElevationGrant`, `PamSettings` (632 lines) |
| `src/main/java/dev/dwarpal/guard/` | Shared abuse guards: `NonceCache`, `RateLimiter` (150 lines) |
| `crypto` | `KeyPurpose` +2 (`ELEVATION_APPROVER`, `BREAK_GLASS`); `SignedMessages` +7 (session use, session binding, authentication v3, failure report, elevation approval, break-glass, break-glass review); `Digests` key thumbprint |
| `domain/AuthenticationContext` | Optional key thumbprint (key-bound MFA) |
| `admin/PolicyInstaller` | Throttled auditing of rejections |
| `runtime/DecisionPipeline` | `continuous(...)`: audited, not learned |
| `policies/default-policy.yaml` | Version 2026.11.02-1: no standing admin (P-06) |
| Tests | `session` (4 classes), `pam`, `guard`, plus updates to engine, installer and loader tests |
| Docs | Threat model v0.8, this report, README, SECURITY, project state |
