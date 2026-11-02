# Dwarpal: report on Layer 1 (core engine) and Layer 2 (behavioural scorers)

*Status as of 2026-11-02. JDK 25 LTS. 90 main classes (~5,100 lines), 23 test classes (~3,900 lines).*

## 1. What Dwarpal is

A **Zero Trust Policy Decision Point** (NIST SP 800-207). For every request, "may this subject, on
this device, do this action on this resource, now?", it answers **ALLOW, ALLOW_LIMITED (read-only),
STEP_UP (prove it with MFA) or DENY**, with a written explanation, and records the decision in a
tamper-evident audit trail. One policy model covers private apps (ZTNA), web (SWG) and SaaS data
(CASB), which is the SASE idea.

- **Layer 1, the core**, decides: it verifies evidence, applies policy and the decision maths, and
  protects itself (signatures, audit, two-person policy changes).
- **Layer 2, the scorers**, produce evidence: they compare each login with the user's own history,
  with known-bad sources and with attack patterns, and learn new habits without being poisoned.

Layer 2 never decides. Layer 1 makes the only decision; its final decisions feed back into Layer 2's
learning.

## 2. Status at a glance

| Area | Status |
|---|---|
| Decision pipeline (7 stages, fail-closed, explained) | Done |
| Decision maths (Bayes with base rate, cost-optimal action, MFA strength) | Done |
| Signed evidence (device posture, login proofs) and key ring | Done |
| Safe policy language, loader (text and file), linter | Done |
| Tamper-evident audit trail | Done |
| Two-person, signed, rollback-proof policy changes | Done |
| 10 behavioural scorers, bounded stores, safe learning loop | Done |
| DevSecOps pipeline (local hook, CI gates, SBOM, pinned actions, JDK 25 enforced) | Done |
| Runnable demo / dashboard (requirement FR-13) | **Not done** |
| Sessions, token issuing, revocation, continuous evaluation (Policy Administrator) | Layer 3 |
| IAM / PAM admin console, login and MFA service feeding the failure log | Layer 3 |
| What-If policy replay, calibration of assumed probabilities, SIEM shipping | Layer 4 |
| Hybrid Ed25519 + ML-DSA signatures | After submission (JDK 25 ready, verified) |

## 3. The decision pipeline

```
request -> [1] Evidence verification   signed posture / signed login checked against the KeyRing
           [2] Hard gates              freshness, honeytokens, deny-lists: instant DENY
           [3] Attribute resolution    roles, classification, "managed" from the directory
           [4] Risk                    10 Layer-2 scorers -> Bayes with base rate
           [5] Policy                  YAML grants vs constraints; read-only survives constraints
           [6] Step-up resolution      fresh, device-bound MFA as evidence (per-method beta)
           [7] Obligations             a read-only session may only READ
        -> Decision (+ explanation) -> audit (HMAC chain) -> learning (only from full ALLOWs)
any error at any stage -> DENY
```

The outcome only gets stricter along the way; the single exception is a STEP_UP that verified,
fresh MFA has already satisfied. Assembled in the only safe order by `runtime.DecisionPipeline`.

## 4. What Layer 1 contains

| Package | Lines | Contents |
|---|---|---|
| `domain` | 428 | Request, subject (human or workload), device and posture, resource, network, evidence; strict identifier validation; sanitiser for free text |
| `engine` | 968 | `PolicyEngine` (the PE), the 7 stages, hard gates (honeytoken, deny-list, freshness), MFA settings |
| `risk` | 208 | Evidence as log-likelihood ratios; Bayesian aggregation with spoof-resistant caps |
| `decision` | 175 | Outcomes, three-action cost model, decisions with a user view and an analyst view |
| `policy` | 939 | Closed condition language, safe YAML loader, linter, grant-vs-constraint evaluation |
| `crypto` | 377 | Ed25519, canonical signed messages, key ring (purpose, owner, validity, freshness, verification cache) |
| `pip` | 112 | Authoritative directory (identity, resource catalogue, device inventory) and threat-intel snapshot |
| `audit` | 330 | HMAC-SHA256 chained trail, JSON records, audited decision point ("no audit, no access") |
| `admin` | 178 | Signed policy bundles: two distinct administrators, rollback guard, audited install |
| `runtime` | 41 | `DecisionPipeline`: learning(audited(core)) in the safe order |

Key design choices: the request supplies only **identifiers**; every attribute that matters comes
from the directory, and every claim (device health, "already passed MFA") counts only with a valid
signature from a key of the right purpose, bound to that device or subject. Policies separate
**grants** (PERMIT, PERMIT_LIMITED) from **constraints** (REQUIRE_STEP_UP, DENY): a constraint
alone never authorises, and never erases a read-only grant.

## 5. What Layer 2 contains

| Scorer | Detects | Model |
|---|---|---|
| `network-novelty` | New IP / ISP / country for this user | Rule of succession over the last 200 logins, IP -> ASN -> country back-off |
| `device-novelty` | Unknown or unproven device | Same; only signature-proven device ids count as known |
| `impossible-travel` | Too far, too fast | Haversine distance minus both GeoIP radii, over elapsed time |
| `login-time` | Odd hour for this user | Circular kernel density (von Mises kernels) vs uniform |
| `subject-trust`, `device-trust` | Reputation | Beta reputation with half-life forgetting |
| `brute-force` | Guessing one account | Poisson likelihood ratio, clamped at zero |
| `password-spray` | One IP failing on many accounts | Same, distinct accounts per IP |
| `attack-surge` | Org-wide credential campaign | Same on the org total, capped at x10 |
| `ip-reputation` | Abuse lists, Tor, hosting providers | Fixed likelihood ratios, strongest category only |

Supporting code (`behavior`, 640 lines): login history, reputation ledger and failure log, all
size-bounded; read-only views for scorers; the learning loop (`LearningDecisionPoint`).

## 6. The maths, with sources

| Id | Formula | Source |
|---|---|---|
| M3 | `logit P(attack|x) = logit P(attack) + Σ ln LR_k`, per-factor and total caps | Bayes; base-rate fallacy, Axelsson 2000 |
| M2 | Pick the action with least expected loss; step up when `p > C_F/(C_F + C_B(1-β))`, deny when `p > (C_D-C_F)/(C_D-C_F+β C_B)` | Cost-sensitive decisions, Elkan 2001 (three-action form is ours) |
| MFA | After passing method m: `p' = p β_m / (p β_m + 1 - p)`, then decide again | Bayes; per-method β are stated assumptions |
| M1 | `P(new|legit) = (k+1)/(w+2)`; evidence `ln(P_att/P_legit)` per level | Adapted from Freeman et al., NDSS 2016 (rule of succession) |
| M4 | `E = (r+1)/(r+s+2)`, `LLR = ln((s+1)/(r+1))`, weights halve every 30 days | Jøsang & Ismail 2002 |
| M6 | `LLR = -c ln(2π f(θ))`, `f` = mean of von Mises kernels | Mardia & Jupp, directional statistics |
| M7 | `v = max(0, d - a1 - a2)/Δt` with haversine `d` | Haversine; radius correction is ours |
| Poisson | `k ln(λa/λl) - (λa - λl)`, clamped at 0 | Standard likelihood ratio |

Property tests check over 7,000+ random cases that more attack evidence never lowers P(attack),
never yields a more permissive action, and that scorer order never changes the result.

## 7. Security engineering: what was found and fixed

Every item below was first reproduced as a working exploit test, then fixed, and is kept as a
permanent regression test. Full details: [threat-model.md](threat-model.md).

| Group | Items |
|---|---|
| Core breaches (B1-B9) | Spoofed familiarity cancelling attack evidence; forged log lines; case-variant role skipping a deny rule; download under read-only; requester choosing their own classification; stale/future requests; rule-order bypass; a step-up constraint acting as a grant (payroll after MFA); a step-up constraint erasing a read-only grant (admin from an unmanaged device) |
| Defence in depth (D1-D11) | Signed posture and login proofs, device-bound sessions, MFA as evidence, HMAC audit chain, no audit no access, two-person policy changes, rollback guard, key purposes, Trojan Source gate |
| Layer 2 (L1-L8, C1-C8) | Baseline poisoning, lock-out DoS via fake failures, gaming the failure model, memory exhaustion, future-dated login blinding travel checks, scorers writing to stores, typed device ids buying familiarity, store flushing, learning a decision audit had denied, MFA strength defined twice, wrong time model, slow verification, lost spray evidence for out-of-order events |
| Pipeline (P1-P5) | Mutable action tags, persisted CI tokens, blanket SAST suppression, float equality, parser messages leaking file content |

## 8. DevSecOps: how security is built in

| Stage | Control |
|---|---|
| Design | STRIDE threat model kept with the code; OWASP ASVS mapping; NIST 800-207 roles as class names |
| Code | Fail-closed by construction; input allow-lists; immutable objects; no reflection, scripting or deserialisation of objects; JDK-only crypto; one runtime dependency |
| Commit (local) | `.githooks/pre-commit`: blocks key/env/build files, private keys and tokens, invisible bidi characters; runs gitleaks when installed |
| Build | `-Xlint:all -Werror`; JDK 25 and Maven 3.9 enforced; 80% coverage gate; reproducible build timestamps |
| Test | 196 tests: unit, abuse cases, breach regressions, property tests, fuzzing, concurrency, latency, accuracy simulation, source hygiene |
| CI | gitleaks secret scan; build + tests + coverage; SpotBugs + FindSecBugs SAST; CodeQL (security-extended, weekly re-scan); dependency review on PRs; CycloneDX SBOM artifact |
| Supply chain | All GitHub Actions pinned to commit SHAs on Node 24 releases; least-privilege workflow tokens; `persist-credentials: false`; Dependabot for Maven and Actions |
| Suppressions | Only named classes, each proven by a test (`ImmutabilityTest`); no project-wide suppression |

## 9. Results

| Measure | Value |
|---|---|
| Tests | 196 passing (19 engine, 17 evidence/step-up, 10 breach regressions, 20 policy loader, 21 scorers, 17 stores/learning, 11 audit, 9 admin, 10 attack scenarios, 4 property, 3 fuzz/concurrency/latency, 1 accuracy, ...) |
| Coverage | 97.1% lines, 91.4% branches |
| SAST | 0 findings (SpotBugs 4.10.5 + FindSecBugs, 129 classes); CodeQL green |
| Dependencies | 9, all clean on OSV.dev |
| Latency (full pipeline) | p50 0.08-0.3 ms, p99 under 1.2 ms (target 20 ms) |
| Accuracy (60 synthetic users) | 0/300 legitimate logins denied; 0/60 normal logins asked for MFA; 0/360 password-only attacks allowed |

## 10. Known limits (stated, not hidden)

- **Stolen unlocked laptop at the victim's home** with their password looks exactly like the victim
  (60/60 allowed in simulation). Needs Layer 3 session limits and periodic re-authentication.
- **Assumed probabilities** (e.g. P(new country | attack), MFA β, Poisson rates) are documented
  assumptions until calibrated in Layer 4; the accuracy numbers come from our own generator, so they
  show consistency with the threat model, not real-world accuracy.
- **Correlated evidence** (network novelty and impossible travel) is counted twice (naive Bayes),
  bounded by the caps.
- **Request-id replay** inside the freshness window needs Layer 3 session state.
- **Ed25519 is not quantum-safe**; the hybrid plan is ready on JDK 25.
- **No runnable demo yet**: the engine is exercised through tests only.

## 11. How to build

```bash
git config core.hooksPath .githooks
mvn verify spotbugs:check cyclonedx:makeAggregateBom
```
