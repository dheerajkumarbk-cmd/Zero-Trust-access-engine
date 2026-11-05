# Dwarpal

*Never trust. Always verify. Explain every decision.*

Dwarpal (द्वारपाल, "gatekeeper") is an explainable, decision-theoretic Zero-Trust **Policy
Decision Point** following NIST SP 800-207. It decides ALLOW / ALLOW_LIMITED / STEP_UP / DENY for
private apps (ZTNA), web (SWG) and SaaS data (CASB) with one policy model, as in SASE.

## Decision pipeline

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

The outcome only ever gets stricter along the pipeline (the one exception: a STEP_UP already
satisfied by verified, fresh, device-bound MFA); any internal error denies.

Before risk scoring, the request is made trustworthy: attributes come from the directory, device
posture and login claims count only when signed (Ed25519) by keys in the `KeyRing`. Every decision
is written to an HMAC-chained audit trail ("no audit, no access"), and policy changes need two
administrators' signatures (`PolicyInstaller`). See [docs/security-architecture.md](docs/security-architecture.md).

## Sessions and privileged access (Layer 3)

The **Policy Administrator** (`session.PolicyAdministrator`) turns an allowed login into a session:
a 256-bit token stored only as a hash, bound to a key the client holds. Every request on the session
is signed with that key, used once, and decided again by the engine (continuous evaluation).
Sessions end on idle (30 min), at 10 h, or by revocation, and need fresh, key-bound MFA again after
8 h / 4 h / 1 h / 15 min depending on the data's classification.

**Privileged access** (`pam.PrivilegedAccessManager`): nobody holds admin rights permanently. An
eligible person asks for a role for at most 1 h with WebAuthn and a reason; a different person
approves by signing exactly that request. Break-glass accounts open a sealed credential for 30 min,
page the SOC at once and must be reviewed. See the [Layer 3 report](docs/layer-3-report.md).

## Enforcement points and the SASE edge (Layer 4)

The decision point is useless until something enforces it. Layer 4 puts three enforcement points
(PEPs) in front of real traffic, all reaching the engine only through one **engine API**:

```
 client agent --HTTPS--> ZTNA gateway ----+
 browser -----proxy----> web gateway -----+--mutual TLS 1.3--> engine API --> PA / PAM / engine
 SaaS upload ----------> data guard ------+       (each PEP: own certificate, own resource scope)
```

| Package | Role (SASE name) | What it does |
|---|---|---|
| `api` | engine API | HTTPS with client certificates; per-caller roles, resource scopes and rate limits; strict JSON; generic errors; every call audited. `RemoteSessionAuthority` is the PEP side: pinned to the API, one deadline, any failure is a deny |
| `gateway`, `agent`, `devidp` | ZTNA | Reverse proxy in front of private apps; every request on a session is signed by the client agent and decided again; a development identity provider with passwords (PBKDF2) and a software security key (WebAuthn, simulated) |
| `swg` | Secure web gateway | Forward proxy filtering by host name: block lists, categories, look-alike names, raw IPs, internal addresses; no TLS interception |
| `casb` | CASB / DLP | SaaS reads and uploads through sessions; validated detectors (Luhn, Verhoeff, PAN, keys, tokens); block, redact or audit by classification |
| `edge`, `wire` | contracts | The shared request/result types, header protocol, wire format, TLS settings and a strict JSON reader |

A session opens only on fresh, verified MFA bound to the client's session key, and each MFA proof
opens one session. Single decisions without a session exist only for web browsing. See the
[Layer 4 report](docs/layer-4-report.md).

## The SOC loop (Layer 5)

Decisions flow back into decisions. The audit trail is stored encrypted and anchored (`siem`); detection
rules read only verified records and raise alerts, which become cases (`response`); an analyst confirms or
rejects each case with a signed verdict; playbooks then block, watch or revoke, within guard rails, through
the same signal feed the engine reads; and `analytics` replays recorded traffic through a proposed policy
(What-If), calibrates probabilities and measures accuracy on the same trail. See the
[Layer 5 report](docs/layer-5-report.md).

## The SOC platform (Layer 5.2)

The SOC loop gets the tools an analyst works in, and they are one system with the loop, not beside it. Collectors
(`siem.platform`) bring in firewall syslog, signed endpoint batches and cloud logs and write them into the same
audit chain as Dwarpal's own decisions; one search language serves analysts and correlation rules; UEBA (`ueba`)
learns what is normal for each person, device and peer group with statistics that can be checked by hand and ranks
alerts P1 to P4; the SOAR (`soar`) turns signed verdicts into guarded actions, including isolating a device that the
device's own signed acknowledgement confirms; and the SOC API (`socapi`) serves queue, cases, risk, search and
reports over mutual TLS. Evidence that anybody on the network could have forged may be watched and ranked, but never
triggers a destructive action. See the [Layer 5.2 report](docs/layer-5-2-report.md).

## The lab (Layer 6)

`bin\lab.cmd` (or `bin/lab.sh`) starts Dwarpal on a simulated organisation with a browser console: alert queue,
cases with signed verdicts, hunt, entity risk, an audit explorer that verifies the chain, a scenario lab that launches
the attacks on demand with a guide, and administrator pages for two-person policy changes and privileged access. It is
built to a stated baseline (OWASP ASVS, NIST SP 800-53 and 800-207, SOC 2, ISO 27001) and costs nothing to run. See the
[Layer 6 report](docs/layer-6-report.md) and the [runbook](docs/runbooks/lab.md).

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

Reports: [Layer 1](docs/layer-1-report.md), [Layer 2](docs/layer-2-report.md), [Layer 3](docs/layer-3-report.md),
[Layer 4](docs/layer-4-report.md), [Layer 5](docs/layer-5-report.md), [Layer 5.2](docs/layer-5-2-report.md), [Layer 6](docs/layer-6-report.md),
and the full [project state](docs/project-state.md).

## Build

Requires **JDK 25 LTS** and Maven 3.9+ (the build refuses older JDKs with a clear message).

```bash
git config core.hooksPath .githooks   # once per clone: local secret / bidi pre-commit checks
mvn verify                       # compile, tests (incl. abuse cases), coverage gate
mvn spotbugs:check               # SAST with FindSecBugs
mvn cyclonedx:makeAggregateBom   # SBOM -> target/bom.json
```

See [SECURITY.md](SECURITY.md), [docs/threat-model.md](docs/threat-model.md) and the full
[report on layers 1 and 2](docs/report-layers-1-2.md).
