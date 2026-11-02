# Dwarpal security architecture

How the core engine protects itself, and how later layers (IAM, PEP gateway, SOC) plug into the
same protections instead of inventing their own.

## 1. Defence in depth: the request's path

```
 Request ──► [1] Evidence verification  posture + login count only if signed by the right key (KeyRing);
                                        runs first so every decision knows whether the device proved itself
             [2] Hard gates             freshness, honeytokens, deny-lists: instant DENY
             [3] Attribute resolution   roles, classification, "managed" from the directory, not the request
             [4] Risk (Bayes, M3)       10 scorers; asymmetric caps: spoofed familiarity cannot cancel attack evidence
             [5] Policy (signed)        grants vs constraints; policy is a floor; read-only survives constraints
             [6] Step-up resolution     MFA as evidence: beta of the method used, fresh + device-bound
             [7] Obligations            read-only means READ only, even after MFA
         ──► Audit (HMAC chain)         no audit, no access
         ──► Learning                   only from full ALLOWs, clock-checked, bounded stores
 Any error in any stage ─────────────► DENY (fail-closed)
```

An attacker has to beat every layer, not one. Each layer has a breach-regression test.

## 2. The principles, and where each one lives

| Principle | Implementation | Code |
|---|---|---|
| Fail-safe defaults | Default DENY; unknown subject/resource DENY; no fail-open mode; stage errors and StackOverflowError DENY; audit failure DENY | `PolicyEngine`, `FailMode`, `AuditedDecisionPoint` |
| Glass box, not black box | Every decision carries its factors, policy, version and reasons; the requester sees a generic message; the full record goes into a tamper-evident chain | `Decision.analystReport`, `AuditLog` |
| Complete mediation | One `DecisionPoint` interface; every access goes through the full pipeline | `DecisionPoint` |
| Least privilege | Read-only obligations; grants need explicit PERMIT; constraints never grant | `ObligationStage`, `Effect` |
| Separation of duties | Two distinct administrators must approve every policy change | `PolicyInstaller` |
| Key separation | Each key has one purpose and one owner | `KeyPurpose`, `KeyRing` |
| Never trust the client | Request supplies identifiers; attributes come from the directory; claims need signatures | `AttributeResolutionStage`, `EvidenceVerificationStage` |
| Accountability | Decisions and admin actions (accepted *and* rejected) audited with PDP time | `AuditedDecisionPoint`, `PolicyInstaller` |
| Economy of mechanism | One crypto trust anchor for all signed claims; JDK-only crypto | `KeyRing`, `Ed25519` |

## 3. How the core connects to IAM (authentication, authorisation, auditing, administration)

| IAM "A" | What the later layer will do | Hook already in the core |
|---|---|---|
| **Authentication** | IdP logs the user in with password + MFA | IdP signs `(subject, device, method, time)`; core verifies with an `IDENTITY_PROVIDER` key and turns the method into evidence (`AuthMethod` beta) |
| **Authorisation** | PEP asks "may this happen?" | `DecisionPoint.decide`, the only entry point |
| **Auditing** | SOC console, SIEM | `AuditLog` JSON lines with HMAC chain; `head()` anchored in the SIEM |
| **Administration** | Admin console to edit policy | `PolicyInstaller`: two-person rule, rollback guard, signed bundles. The admin console itself will be protected by Dwarpal (admin actions are `Action.ADMIN`, which policy P-05 already forces through step-up) |

The step-up loop shows the correlation: the engine says STEP_UP → the PA challenges with
WebAuthn → the IdP signs the result bound to the device → the next request carries it → the engine
updates P(attack) with that method's beta → ALLOW. Weak MFA (push) under suspicion is not enough,
by the same maths.

## 4. Encryption: where it is needed and where it is not

| Data | Threat | Control | Layer |
|---|---|---|---|
| Signed claims (posture, login, policy) | Forgery, tampering | Ed25519 signatures (integrity + origin); encryption would not stop forgery | Core (done) |
| Audit trail | Editing, deleting history | HMAC-SHA256 chain + external head anchor | Core (done) |
| PEP ↔ PDP traffic | Eavesdropping, spoofed PDP answers | mTLS (TLS 1.3, both sides authenticated) | Layer 4 (gateway) |
| Audit/session data at rest | Disk theft, insider reading PII | Encrypted storage (AES-256-GCM via the database or disk), plus data minimisation | Layer 4 |
| Keys (HMAC key, admin private keys) | Theft | Never in the repo (gitleaks), loaded from environment/KMS; admin keys on hardware tokens in production | Every layer |

The core holds data only in memory for one decision, so confidentiality there comes from not
persisting anything. Integrity is the core's job, and it is cryptographic.

## 5. Privileged Access Management (PAM): is it needed?

**Yes, in the administration plane (Layer 3), and its enforcement point already exists in the core.**

| PAM control | Status |
|---|---|
| Four-eyes approval for policy changes | **Done** (`PolicyInstaller`, `requiredApprovers = 2`) |
| No shared admin identities; keys bound to named admins | **Done** (`TrustedKey.boundTo`) |
| Privileged actions audited, including rejected attempts | **Done** |
| Step-up for every admin action | **Done** via policy P-05 |
| Just-in-time admin elevation (no standing admin role) | Layer 3: time-boxed role grant, signed by an approver |
| Break-glass emergency account | Layer 3: sealed credential, any use triggers a CRITICAL alert plus mandatory review |
| Rate limiting on admin endpoints | Layer 3 (each rejected bundle is audited, so a flood is visible but costs storage) |
| Database least privilege | Layer 4: the PDP's DB user may only `INSERT` into audit tables (no `UPDATE`/`DELETE`); admins read through a separate read-only role; schema changes use a third migration account |

## 6. OWASP ASVS 4.0.3 mapping (selected)

| ASVS | Requirement (short) | Dwarpal |
|---|---|---|
| V1.4.1 | Trusted enforcement points enforce access control | Single `DecisionPoint`, PEP contract |
| V4.1.3 | Least privilege | Grants vs constraints, read-only obligation |
| V4.1.5 | Access control fails securely | Fail-closed engine, audit, gates |
| V5.1.3 / V5.1.4 | Input validation with allow-lists | `Validate.id`, strict policy schema |
| V5.5.2 | Safe deserialization (XXE/YAML) | `SafePolicyLoader` (CVE-2022-1471) |
| V6.2.1 / V6.2.2 | Approved, fail-secure crypto from proven libraries | JDK JCA, Ed25519, HMAC-SHA256; malformed signatures return `false`, never throw |
| V6.2.5 | No insecure algorithms or modes | Only Ed25519 keys accepted (RSA rejected) |
| V7.1.1 / V7.1.2 | No secrets in logs; log what is needed | Payload fields chosen explicitly; parser errors not echoed |
| V7.3.1 | Log encoding prevents injection | `Sanitize`, `Json` escaping |
| V7.3.3 | Logs protected from modification | HMAC chain |
| V10.3.2 | Integrity of updates (here: policy) | Signed bundles, sequence numbers |
| V14.2.1 / V14.2.4 | Dependencies current, controlled | Dependabot, dependency review, SBOM, pinned actions |

## 7. Why these libraries can be trusted

| Component | Source | Why |
|---|---|---|
| Crypto (Ed25519, HMAC, SHA-256; ML-DSA/ML-KEM available) | JDK 25 JCA (SunEC, SunJCE, SUN) | Maintained by the OpenJDK security team, FIPS-capable providers exist; no third-party crypto on the decision path |
| YAML parsing | SnakeYAML 2.3 | Widely used; v2 fixed CVE-2022-1471 by default; we additionally use `SafeConstructor` and strict limits |
| Tests | JUnit 5 | Test scope only |
| Logging (future service layer) | SLF4J API + Log4j 2 ≥ 2.24.x | Log4j's lesson (Log4Shell, CVE-2021-44228) is to pin patched versions and never let untrusted input reach lookups; the core deliberately has **no** logging dependency: a library should not force one, and security events go to the HMAC audit chain, which plain logging cannot make tamper-evident |

Rule for future dependencies: Apache, Eclipse, OpenJDK or OWASP origin, actively maintained, no
open critical CVEs, pinned version, listed in the SBOM, and a stated reason in this table.

## 8. Post-quantum readiness

| Primitive | Used for | Quantum status | Action |
|---|---|---|---|
| Ed25519 signatures | Device posture, login proofs, policy approvals | Broken by Shor's algorithm on a large quantum computer. NIST IR 8547 schedules quantum-vulnerable signatures for deprecation after 2030 and disallowal after 2035 | Plan hybrid Ed25519 + ML-DSA (FIPS 204) |
| HMAC-SHA256 | Audit chain | Symmetric: Grover's algorithm at most halves the security level (about 128-bit), which is considered adequate | Keep |
| SHA-256 | Hashes, digests | As above | Keep |
| (Layer 4) TLS key exchange | PEP to PDP traffic | Vulnerable to "harvest now, decrypt later" | Hybrid X25519 + ML-KEM key exchange |

Why signatures are not urgent today: Dwarpal's signatures are short-lived (login proofs 15 minutes,
posture 24 hours, policy approvals 7 days) and checked at decision time. A forger needs a quantum
computer *at the moment of the decision*, unlike encrypted traffic, which can be recorded now and
decrypted later. The long-lived exposure is the trust anchors (administrators' and IdP keys).

Plan (crypto-agility first, then hybrid):
1. **Done:** the build targets **JDK 25 LTS**, which ships ML-DSA and ML-KEM in the standard library
   (JEPs 496/497): no third-party crypto needed. Measured on Temurin 25.0.5: ML-DSA-65 signature
   3,309 bytes and public key 1,974 bytes (Ed25519: 64 and 44), but verification 0.14 ms versus
   0.67 ms for Ed25519. Hybrid costs bandwidth, not latency.
2. Add an algorithm identifier to `TrustedKey` and `SignatureProof`, and raise the signature size
   limit (an ML-DSA-65 signature is about 3.3 KB versus 64 bytes).
3. **Hybrid AND-composition**: a proof is valid only if *both* the Ed25519 and the ML-DSA signature
   verify, so the system is at least as strong as the stronger of the two. Start with policy approvals
   and IdP proofs (the long-lived trust anchors), then device agents.
4. Drop Ed25519 once ML-DSA has matured in the field.
