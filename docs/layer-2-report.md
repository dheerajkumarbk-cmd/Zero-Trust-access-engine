# Layer 2 report: behavioural risk scorers

## What it is

Layer 1 decided *how* to combine evidence. Layer 2 produces the evidence: ten scorers that
compare each login with the user's own past behaviour, with known-bad sources and with attack
patterns, plus the stores that remember that behaviour and a learning loop that keeps it up to date without letting
attackers poison it.

## The scorers and their maths

| Scorer | Detects | Formula | Source |
|---|---|---|---|
| `network-novelty` | Login from a new IP / ISP / country | P(new\|legit) = (k+1)/(w+2) over the last 200 logins (rule of succession), backing off IP -> ASN -> country | Adapted from Freeman et al., NDSS 2016 |
| `device-novelty` | Unknown or unproven device | same; only signature-proven device ids count as known | as above |
| `impossible-travel` | Too far, too fast | v = max(0, haversine - both GeoIP radii) / hours | Haversine; radius correction is ours |
| `login-time` | Odd hour for this user | circular kernel density vs uniform: LLR = -c ln(f(theta) 2pi) | Mardia & Jupp (von Mises kernels) |
| `subject-trust`, `device-trust` | Reputation | E = (r+1)/(r+s+2), LLR = ln((s+1)/(r+1)), half-life forgetting | Josang & Ismail, 2002 |
| `brute-force` | Many guesses at one account | Poisson LLR k ln(la/ll) - (la - ll), clamped >= 0 | T1110.001 |
| `password-spray` | One IP failing on many accounts | same, counting distinct accounts | T1110.003 |
| `attack-surge` | Org-wide credential campaign | same Poisson on the total, capped at x10 (raises the base rate, cannot lock everyone out) | Bayesian base rate |
| `ip-reputation` | Abuse lists, Tor exits, hosting providers | fixed LRs x50 / x20 / x10, strongest only | Freeman's p(attack\|x) term |

All output log-likelihood ratios, so Layer 1's Bayes and cost model use them unchanged.

## Why these choices

- **No cold-start hack:** a brand-new user has n=0, so novelty is only mild evidence and the first
  login asks for MFA instead of being blocked.
- **Habit-aware:** someone who changes IP every day is not punished for a new IP.
- **Circular time:** 23:30 and 00:30 are an hour apart; a naive average says noon.
- **Uncertainty is explicit:** "no history" (E=0.5, u=1) is different from "mixed history".

## Results on the full pipeline (40 days of normal history for "Alice")

| Scenario | Outcome | Main evidence |
|---|---|---|
| Normal login from home | ALLOW (P=0.0001) | everything familiar |
| Brand-new user's first login | STEP_UP (P=0.008) | mild novelty |
| Stolen password, Moscow, unknown PC, 22:00 | DENY (P=0.985) | new country + device + odd hour |
| Same laptop in London 30 min after Mumbai | DENY (P=0.75) | 14,285 km/h |
| Login from an IP that failed on 12 accounts | DENY (P=0.98) | password spray |
| Real Alice during a brute-force attack | STEP_UP (P=0.09) | proves herself, not locked out |
| Trip to Bengaluru: no MFA / push / WebAuthn | STEP_UP / STEP_UP / ALLOW | push too weak, security key enough |
| Same hotel an hour later | ALLOW | location learned after verification |
| Stolen password from an AWS server in Mumbai, laptop id typed in | DENY (P=0.96) | unverified device, hosting provider |
| Tor exit at Alice's usual hour | DENY (P=0.67) | Tor + new country |
| 30 attack attempts | all DENY | baseline and reputation untouched |

## Accuracy on a synthetic organisation

60 users (40 home workers, 10 mobile roamers, 10 frequent travellers), 45 days of history each.
Expectations were written down before the first run.

| Case | ALLOW | STEP_UP | DENY |
|---|---|---|---|
| Normal login | 60 | 0 | 0 |
| Odd hour | 0 | 60 | 0 |
| Domestic trip (then with WebAuthn) | 10 (60) | 50 (0) | 0 |
| New company laptop | 0 | 60 | 0 |
| Foreign credential stuffing | 0 | 0 | 60 |
| Domestic cloud server, typed laptop id | 0 | 0 | 60 |
| Same-city residential proxy (evasive) | 0 | 60 | 0 |
| Impossible travel | 0 | 0 | 60 |
| Tor exit | 0 | 0 | 60 |
| Password-spray IP | 0 | 0 | 60 |
| Stolen unlocked laptop at the victim's home | 60 | 0 | 0 |

Legitimate users wrongly denied: **0 of 300**. Attacks with a stolen password let in: **0 of 360**.
The last row is the known blind spot (password, device and network all genuine), left to Layer 3.
Limit: the generator and the engine come from the same team, so this checks consistency with the
threat model, not real-world accuracy.

## Security of Layer 2 itself

| Threat | Protection |
|---|---|
| Baseline poisoning (attacker makes their country "familiar") | Only a full ALLOW is learned; STEP_UP, DENY, restricted and degraded decisions are not |
| Lock-out DoS (spamming DENYs to ruin a victim's reputation) | Ordinary DENYs never create bad marks |
| Gaming the failure model (fail once to look like a typo) | Failure evidence clamped at >= 0 |
| Memory exhaustion via rotating IPs / usernames | Every store size-capped with LRU eviction |
| Future-dated login blinding travel detection | Learner checks its own clock (found by red-team, fixed) |
| Scorers tampering with stores | Scorers get read-only views (`BehaviorHistory`, `TrustView`, `FailureView`) |
| Typed device ids buying familiarity | Only signature-proven devices count as known |
| Flushing the failure store with junk | Recent evidence is never evicted; keyless org-wide counter |
| Learning a decision audit turned into DENY | One factory builds learning(audited(core)) |

## Numbers

194 tests in total (including 10 end-to-end attack scenarios, a 60-user accuracy simulation,
property tests over 7,000+ random cases, a 3,000-request fuzz test and an 8-thread concurrency
test), 0 SAST findings, 0 known-vulnerable dependencies, built on JDK 25 LTS.
Full-pipeline latency p50 0.3 ms, p99 1.2 ms (target 20 ms).

## Known limits

Network novelty and impossible travel are correlated and both count (naive Bayes);
per-scorer probabilities such as P(new country | attack) are assumptions to be calibrated in the
evaluation layer; a NAT with many mistyping users can look like a spray.
