# Layer 1 report: the Dwarpal core engine

## What it is

The **Policy Engine** of a Zero Trust architecture (NIST SP 800-207). A Policy Enforcement Point
asks "may this user, on this device, do this action on this resource, right now?" and Dwarpal
answers **ALLOW, ALLOW_LIMITED (read-only), STEP_UP (prove it with MFA) or DENY**, with the
reasons written down.

It decides for three kinds of resources with one policy model (the SASE idea): private apps
(ZTNA), web destinations (SWG) and SaaS data (CASB/DLP).

## Why it exists (the problem)

| Industry problem | Dwarpal's answer |
|---|---|
| Access engines are black boxes: admins can't say why someone was blocked | Every decision carries its evidence, matching policy and reasons, and is stored in a tamper-evident trail |
| Risk scores use arbitrary weights and thresholds | Bayes with a base rate (Axelsson 2000) and a cost-optimal choice of action (after Elkan 2001) |
| MFA is treated as all-or-nothing | Each MFA method has its own strength (beta): WebAuthn counts far more than push approval, which is open to MFA fatigue |
| Engines trust what the request says | Attributes come from a directory; device health and login claims count only when cryptographically signed |
| One admin, or one stolen key, can change access policy | Two distinct administrators must sign every policy change |

## How it works

```
request -> [1] Evidence verification   signed posture / signed login checked against the KeyRing
           [2] Hard gates              freshness, honeytokens, deny-lists: instant DENY
           [3] Attribute resolution    roles, classification, "managed" from the directory
           [4] Risk                    10 Layer-2 scorers -> Bayes with base rate (M3)
           [5] Policy                  YAML grants vs constraints; read-only survives constraints
           [6] Step-up resolution      fresh, device-bound MFA as evidence (per-method beta)
           [7] Obligations             a read-only session may only READ
        -> Decision (+ explanation) -> audit (HMAC chain) -> learning (only from full ALLOWs)
any error at any stage -> DENY
```

- **Fail-closed:** any error, missing signal or unwritable audit record means DENY.
- **Monotonic:** each stage can only make the answer stricter (except a step-up already
  satisfied by verified, fresh MFA).

## What it contains

| Package | Purpose |
|---|---|
| `domain` | Requests, subjects (human or workload), devices, resources, validation and sanitising |
| `risk` | Evidence as log-likelihood ratios; Bayesian aggregation with spoof-resistant caps |
| `decision` | Outcomes, cost model, explained decisions (generic message for users, full report for analysts) |
| `policy` | Safe YAML policy loader, condition language, linter, grant-vs-constraint evaluation |
| `engine` | The 7-stage pipeline, honeytoken/deny-list/freshness gates, MFA step-up logic |
| `crypto` | Ed25519 signatures, key ring with one purpose per key, canonical signed messages |
| `pip` | Directory of authoritative attributes (identity, resources, device inventory) |
| `audit` | HMAC-SHA256 chained audit trail; audited decision point |
| `admin` | Signed policy bundles: two-person rule, rollback guard |

## How it was secured (DevSecOps)

- **Red-team passes:** 8 working exploits found in early versions and fixed (e.g. a forged role
  case bypassing a deny rule, a service account getting payroll after MFA). Each is now a
  permanent regression test.
- **Pipeline:** secret scanning, 196 tests (whole project) with an 80% coverage gate, SpotBugs + FindSecBugs,
  CodeQL, dependency review, SBOM, GitHub Actions pinned to commit SHAs.
- **Results (whole project, JDK 25):** 97.1% line / 91.4% branch coverage, zero SAST findings,
  zero known-vulnerable dependencies, one runtime dependency (SnakeYAML 2.7); all crypto from the JDK.
- **Standards:** controls mapped to OWASP ASVS 4.0.3 and NIST SP 800-207.

## What it is used for

- **Now:** a tested, explainable decision core that later layers call.
- **Layer 2:** real risk scorers (login-history likelihoods, impossible travel, time-of-day, trust).
- **Later:** identity provider and admin console (IAM, PAM), a real gateway, and SIEM/SOC integration.
  The hooks for all of these already exist.

## Known limits (documented, not hidden)

Request replay within the freshness window, no TPM attestation yet, audit key not HSM-backed,
MFA strength values are assumptions (to be tested by sensitivity analysis). Full list in
[threat-model.md](threat-model.md).
