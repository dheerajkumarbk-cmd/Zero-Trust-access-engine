# Dwarpal

*Never trust. Always verify. Explain every decision.*

Dwarpal (द्वारपाल, "gatekeeper") is an explainable, decision-theoretic Zero-Trust **Policy
Decision Point** following NIST SP 800-207. It decides ALLOW / ALLOW_LIMITED / STEP_UP / DENY for
private apps (ZTNA), web (SWG) and SaaS data (CASB) with one policy model, as in SASE.

## Decision pipeline

```
request ─► Hard gates ─► Risk (Bayes, M3) ─► Cost-optimal action (M2) ─► Policy floor ─► Decision + explanation
            honeytoken     log-likelihood        ALLOW / STEP_UP / DENY      YAML policies
            deny-lists     ratios, prior          minimising expected loss    (deny-overrides)
```

The outcome only ever gets stricter along the pipeline (the one exception: a STEP_UP already
satisfied by verified, fresh, device-bound MFA); any internal error denies.

Before risk scoring, the request is made trustworthy: attributes come from the directory, device
posture and login claims count only when signed (Ed25519) by keys in the `KeyRing`. Every decision
is written to an HMAC-chained audit trail ("no audit, no access"), and policy changes need two
administrators' signatures (`PolicyInstaller`). See [docs/security-architecture.md](docs/security-architecture.md).

## The maths

- **M3, Bayes with base rate** (Axelsson 2000): `logit P(attack|x) = logit P(attack) + Σ ln LR_k`
- **M2, cost-optimal action** (after Elkan 2001, three-action extension):
  step up when `p > C_F / (C_F + C_B(1-β))`, deny when `p > (C_D-C_F) / (C_D-C_F+β·C_B)`.
  `β` = probability an attacker passes step-up, so weaker MFA makes the engine deny sooner.
- **M1, novelty likelihood ratios** (adapted from Freeman et al. 2016): `P(new|legit) = (k+1)/(w+2)`
  over the last 200 logins, backing off IP -> ASN -> country; plus IP reputation (Freeman's p(attack|x)).
- **M4, Beta reputation** (Josang & Ismail 2002): `E = (r+1)/(r+s+2)`, with half-life forgetting.
- **M6, circular login time:** circular kernel density (von Mises kernels) vs uniform; handles several daily habits.
- **M7, impossible travel:** haversine distance minus both GeoIP accuracy radii, over elapsed time.
- **Failure bursts:** Poisson likelihood ratio for brute force, password spray and org-wide surges, clamped at zero.

Reports: [Layer 1](docs/layer-1-report.md), [Layer 2](docs/layer-2-report.md).

## Build

Requires JDK 17+ and Maven 3.9+.

```bash
mvn verify                       # compile, tests (incl. abuse cases), coverage gate
mvn spotbugs:check               # SAST with FindSecBugs
mvn cyclonedx:makeAggregateBom   # SBOM -> target/bom.json
```

See [SECURITY.md](SECURITY.md) and [docs/threat-model.md](docs/threat-model.md).
