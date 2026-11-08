# Dwarpal: team guide

*For the five people presenting the project. Written 2026-11-07. Everything here is checked against the code and the
project state document ([project-state.md](project-state.md)); where this guide is shorter than that document, that
document has the detail.*

This guide has five parts. Each part is something one person can learn, explain and demo in about five minutes. The
split is a suggestion, not the final distribution: parts can be swapped, merged or shared.

| Part | What it covers | Suggested owner |
|---|---|---|
| 1. The core: the decision engine | Layers 1 to 3: how one access request is decided, signed evidence, policy, sessions, privileged access | The project owner |
| 2. The maths | Nine models (M1 to M9) in plain words, with worked examples | The maths person |
| 3. The layers, one by one | What each of the six layers does and why it exists | One person (can be combined with part 1's introduction) |
| 4. The SOC side | Layers 5 and 5.2: logs, detection, cases, response, the nine attack scenarios | One person (can be combined with part 3) |
| 5. The lab, the proof and the presentation | Layer 6 console, the live demo script, tests and security evidence, comparison with commercial products, future work | One person |

Before the parts, everyone needs the same two pages: what Dwarpal is, and how to run it.

---

## 0. What everyone must know

### 0.1 One sentence

Dwarpal (Hindi for "gatekeeper") is a **Zero Trust Policy Decision Point**: for every access request it answers

> May **this person**, on **this device**, do **this action** on **this resource**, **right now**?

and gives one of four answers, always with a written reason:

| Answer | Meaning |
|---|---|
| `ALLOW` | Go ahead |
| `ALLOW_LIMITED` | Read-only access |
| `STEP_UP` | Prove it is you again (multi-factor authentication) |
| `DENY` | No |

### 0.2 Why it matters (the 30-second pitch)

Old security trusted anyone "inside the network". Zero Trust (NIST SP 800-207) trusts nobody by default and decides
every request using evidence: who, what device, how risky this looks, what the data is worth. Companies buy this as
cloud products (Microsoft Entra, Okta, Zscaler, CrowdStrike). Dwarpal builds the same ideas from scratch, in Java with
one dependency, so every decision can be explained and every number can be checked by hand. It is free to run and
open to read, which makes it a learning tool as well as a project.

### 0.3 What it is made of, in one picture

```
 person + device --> enforcement point (Layer 4) --> DECISION ENGINE (Layers 1-3) --> answer + reason
                                                          |  reads: signed evidence, directory, behaviour history
                                                          v
                                    audit trail (tamper-evident) --> SOC platform (Layers 5, 5.2)
                                                          |           detect, correlate, rank, open cases
                                                          v
                                    analyst decides --> automatic response --> feeds back into the engine
                                                          |
                                                          v
                                    the lab (Layer 6): a browser console to watch and drive all of it
```

### 0.4 How to run it (the demo environment)

Needs JDK 25 and Maven (both free). From the project folder:

```
bin\lab.cmd
```

It builds one jar, starts a simulated company (60 people, 8 simulated days) and prints a web address
(`https://localhost:8443`) and five demo logins:

| Login | Role | Sees |
|---|---|---|
| `ana`, `ben` | Analysts | Alert queue, cases, hunt, audit explorer, scenario lab |
| `cleo` | SOC lead | Everything an analyst sees, plus the daily report and the run export |
| `dana` | Administrator | Policy, playbooks, privileged access, reset. Not the analyst queue (separation of duties) |
| `uma` | Ordinary user | "Why was I denied" page only |

Each login has a password and a security-key PIN (a second factor), printed when the lab starts. The browser must trust
the lab's own certificate authority once (`lab\pki\ca.pem`, see [runbooks/lab.md](runbooks/lab.md)).

### 0.5 Honest limits (say these before anyone asks)

* The company, the people and the attacks are **simulated**. Numbers therefore measure consistency with the design,
  not real-world accuracy. Every report in the console says so on its first line.
* The lab starts from "day zero" each time it is started (certificates and logins are kept).
* One process on one machine, in memory. A company would run these as separate services with a database.

---

## Part 1. The core: the decision engine (Layers 1 to 3)

*Owner suggestion: the project owner. This is the heart of the project.*

### 1.1 The path of one request

Every request goes through seven stages. Each stage can only make the answer **stricter**, never looser (the one
exception: a step-up that was satisfied by a verified MFA).

| # | Stage | What happens | Why |
|---|---|---|---|
| 1 | Check the evidence | A device-health report or an "I passed MFA" claim counts only if it carries a valid digital signature from a trusted key | Never trust the client |
| 2 | Hard gates | Certain facts deny at once (for example a known stolen token, a deny-listed device) | Some things are never negotiable |
| 3 | Look up the truth | Roles, data sensitivity and "is this device company-managed" come from the directory, not from the request | The request can lie |
| 4 | Measure risk | Ten behavioural scorers compare the login with the person's own history and with known-bad sources; Bayes' rule turns them into a probability of attack | Risk is a number you can explain |
| 5 | Choose the cheapest safe action | A cost model picks ALLOW, STEP_UP or DENY by least expected loss | Friction and breaches both cost something |
| 6 | Apply policy | Written YAML policies set a floor the risk result cannot go below | Humans stay in charge |
| 7 | Explain and record | The decision lists every reason and is written to the audit trail **before** it is returned. If the write fails, the answer is DENY | No decision without a record |

Default behaviour is DENY: any error, missing signal on a sensitive resource, or failed audit write means no.

### 1.2 Signed evidence

Anything that could be faked is signed. Device health is signed by the device agent; "this user passed MFA" is signed
by the identity provider and is bound to the session key it was issued for. Keys live in a key ring where each key is
usable for **one purpose only** (a key that signs device reports cannot sign analyst verdicts). Unsigned claims are
hints, never evidence. A typed-in device id buys an attacker nothing.

### 1.3 Policy

Policies are short YAML rules, for example "admin actions need fresh phishing-resistant MFA". The language is closed
(no scripting) so a policy cannot run code. Policy changes need **two different administrators' signatures** (separation
of privilege), and a **What-If replay** shows what a proposed change would have decided on last week's real traffic
before anyone approves it.

### 1.4 Behaviour and learning (Layer 2, in one paragraph)

Ten scorers look for: a new network, a new device, impossible travel, an unusual login hour, a poor reputation for the
user or the device, brute force on one account, password spray from one address, an organisation-wide attack surge, and
bad IP reputation (abuse lists, Tor, hosting providers). They only **produce evidence**; they never decide. A learning
loop updates each person's baseline, but only from full, low-risk, audited ALLOW decisions on proven devices, so an
attacker cannot teach the system that their behaviour is normal.

### 1.5 Sessions and privileged access (Layer 3)

* **Sessions with proof of possession.** After a good login the client holds a session key; every use is signed with
  it, is single-use, and is decided again by the engine (continuous evaluation). A stolen token without the key is
  useless. Sessions end on idle, on lifetime, on re-authentication time (shorter for more sensitive data) or when a
  signal says so.
* **No standing admin.** Nobody is an administrator permanently. An eligible person asks for an admin role for at most
  an hour with a reason and a fresh WebAuthn key; **a different person approves**; the role vanishes on its own.
  Exposure falls from 8,760 hours a year to about 156 (98% less).
* **Break-glass.** For emergencies, a sealed credential opens admin for 30 minutes, pages the SOC at once, and must be
  reviewed afterwards by someone else.

### 1.6 The tamper-evident audit trail

Every record is chained to the one before it with a keyed hash, so changing or deleting history breaks the chain. The
head of the chain is also written to a second place (an anchor), so even rewriting the whole file and re-chaining it is
caught. The console's "Audit explorer" can verify the chain at the click of a button, which is a good demo moment.

### 1.7 Things to say out loud in the demo

* "Each stage can only make it stricter."
* "If we cannot record it, we deny it."
* "Every decision comes with the numbers that produced it."

---

## Part 2. The maths (for the maths person)

*Owner suggestion: the maths person. Nine models, M1 to M9. Full derivations with citations are in
[project-state.md](project-state.md) section 8; worked examples in section 9. This part is a reading plan and a plain-
words version.*

### 2.1 The big idea

Every scorer says how much its observation favours "attack" over "legitimate", as a **log-likelihood ratio** (LLR):

LLR = ln( P(observation if attack) / P(observation if legit) )

Positive means suspicious, negative means reassuring, zero means no information. Because they are logarithms, ten
different detectors simply **add up**. Start from how rare attacks are (the base rate), add the LLRs, convert back to a
probability. That is the whole risk calculation.

### 2.2 The nine models

| Model | Question it answers | Idea in one line | Reading |
|---|---|---|---|
| M1 | Is this new for this user? | Rule of succession: P(new) = (k+1)/(w+2), never exactly 0 or 1; if the exact IP is new, back off to the ISP, then the country | section 8.4 |
| M2 | Which action loses least? | Expected loss of ALLOW, STEP_UP and DENY; pick the smallest. The thresholds have closed forms | section 8.2 |
| M3 | How likely is an attack, honestly? | Bayes in log-odds form, starting from a base rate of 1 in 1,000, with caps so no single factor dominates | section 8.1 |
| M4 | How trustworthy is this user or device, and how sure are we? | Beta distribution over good and bad events | section 8.5 |
| M5 | How fast should old evidence fade? | Exponential decay with a half-life (30 days for reputation) | section 8.5 |
| M6 | Is this an unusual hour for this user? | Login times live on a 24-hour circle, so use a circular density (von Mises kernels) | section 8.6 |
| M7 | Could one person move that fast? | Haversine distance minus both location-accuracy radii, over elapsed time; limit 1,000 km/h | section 8.7 |
| M8 | What would this policy edit change? | Replay recorded requests through old and new policy and count the differences | section 8.13 |
| M9 | How strong is each MFA method? | Chance an attacker passes: for push prompts, 1 minus the product of (1 minus each approval chance) | section 8.3 |

Also in section 8: Poisson rate tests for brute force, password spray and attack surge (8.8), IP reputation (8.9),
the audit chain (8.10), policy bundle approval (8.11) and the final outcome (8.12).

### 2.3 Four calculations the maths person should be able to do on a whiteboard

1. **Base rate.** If 1 in 1,000 logins is an attack and a detector has 99% detection and a 1% false-alarm rate, then
   when it fires it is wrong about 91% of the time: 0.99 x 0.001 / (0.99 x 0.001 + 0.01 x 0.999) = 0.09. This is why
   alert fatigue exists and why the engine starts from the base rate.
2. **Normal login.** Prior logit = -6.907. Familiar network, device, hour and a good reputation give about -2.30 after
   caps, so z = -9.21 and P(attack) is about 0.0001: ALLOW.
3. **Takeover from abroad.** New IP, ISP, country (capped at +6.91), unknown device (+4.56), 3,500 km/h travel
   (+3.40): total +14.87, z = +7.97, P(attack) about 0.9997: DENY.
4. **Which MFA is enough?** At P(attack) = 0.05 after a passed MFA: push (β 0.30) leaves 0.0155 so ask again; WebAuthn
   (β 0.01) leaves 0.00053, so ALLOW. After MFA, P = p·β / (p·β + (1 − p)).

### 2.4 Honest statements about the maths

* The scorers are assumed independent (naive Bayes). Correlated scorers would overcount, so the caps limit the damage.
* There is no measured value for how often people approve a fatigue prompt. β is a **stated parameter per method**, and
  the sensitivity analysis shows how decisions change as it varies.
* The simulated data was written by the same team as the engine, so accuracy figures show consistency, not truth.

### 2.5 Reading list (all cited in the project state)

Axelsson 2000 (base-rate fallacy), Elkan 2001 (cost-sensitive learning), Jøsang and Ismail 2002 (Beta reputation),
Mardia and Jupp 2000 (directional statistics), Freeman et al. 2016 (user authenticity), Fisler et al. 2005 and Cedar
2024 (policy change impact).

---

## Part 3. The layers, one by one

*Owner suggestion: one person; can be combined with part 4. Aim: someone who sees the architecture slide can say what
each layer does without notes.*

| Layer | Name | In one sentence | What you can show |
|---|---|---|---|
| 1 | Core decision engine | Takes a request and returns ALLOW, ALLOW_LIMITED, STEP_UP or DENY with reasons, after checking signatures, gates, risk, cost and policy | A decision with its list of reasons |
| 2 | Behavioural risk scorers | Ten detectors that produce evidence from history, geography, reputation and attack patterns; they never decide | Scenarios A1 to A5 and A7 in the lab (the engine refuses or challenges them) |
| 3 | Sessions and privileged access | The Policy Administrator part of Zero Trust: sessions bound to a key, continuous re-evaluation, revocation, just-in-time admin, break-glass | Session revoked on risk; admin request needing a second person |
| 4 | Enforcement points (SASE edge) | Gateways that stand in front of real traffic and enforce the engine's answer: a private-app gateway (ZTNA), a web proxy (SWG) and a data guard for cloud storage (CASB/DLP) | A request denied at the gateway; a file with a card number blocked |
| 5 | The SOC loop | Stores everything encrypted, detects attacks in the trail, opens cases, takes a signed analyst verdict, runs playbooks that deny or watch, and feeds signals back | A case moving from alert to response |
| 5.2 | The SOC platform | The analyst's working tools: SIEM collectors and search, behaviour analytics and ranking, SOAR playbooks and cases, and the SOC API | The same data viewed through search, ranking and cases |
| 6 | The lab | Launcher, browser console, scenario lab, guide, admin pages, packaging | The whole demo |

Three ideas that connect the layers (good for the closing slide):

1. **One contract.** A new detector plugs in by implementing one method; the engine is not touched.
2. **One currency.** Everything speaks log-likelihood ratios, so detectors add up.
3. **A closed loop.** Decisions are audited, audit is detected on, analysts and playbooks respond, responses become
   signals, signals change the next decision.

Mapping to the standard (NIST SP 800-207): the **Policy Engine** is Layers 1 and 2; the **Policy Administrator** is
Layer 3; the **Policy Enforcement Points** are Layer 4; **continuous diagnostics and SIEM** are Layers 5 and 5.2. The
lab (Layer 6) is the place a person sees all of it.

---

## Part 4. The SOC side (Layers 5 and 5.2) and the attack scenarios

*Owner suggestion: one person; pairs well with part 3. A SOC (security operations centre) is the team that watches for
attacks. This part is what a SOC analyst does, and how Dwarpal supports that.*

### 4.1 From decision to response

```
 decisions + logs --> keyed audit chain --> detection rules --> alerts --> ranking (P1..P4)
                                                                              |
 engine <-- signal feed <-- playbooks (guard rails) <-- signed analyst verdict <-- cases with SLA
```

### 4.2 The parts, in plain words

| Part | What it does |
|---|---|
| Collectors | Take in firewall logs (syslog), signed endpoint reports and cloud JSON. Every source has a quota and event-time checks; refused input is itself evidence |
| Search | One query language for analysts and for rules, for example `action ~ login and outcome = FAILURE \| count by subject` |
| Detection and correlation | Ten rules (break-glass use, honeytoken hit, stolen token, deny storms, MFA fatigue, impossible travel then allow, data-loss spikes...) plus YAML correlation rules (threshold, sequence across sources, absence), each tagged with MITRE ATT&CK techniques |
| UEBA and ranking | Behaviour statistics a person can check by hand; every alert gets P1 to P4 from severity, entity risk, how critical the asset is and how reliable the evidence is |
| Cases | Related alerts grouped, with an SLA clock and notes |
| Verdicts | An analyst's decision (true positive, false positive...) counts only when **signed with that analyst's own key**, once; for privileged people two analysts must agree |
| SOAR playbooks | Written as data, signed by two administrators. They can deny (always with an end date, at most 30 days), watch (fading) or revoke; a false positive undoes the case's denies |
| Device isolation | Confirmed only when the device itself signs an acknowledgement |
| SOC API | Mutual TLS; analysts identified by their certificate |

### 4.3 The rule that holds it together: provenance

An alert resting only on forgeable evidence (plain syslog, a cloud export) may be shown, ranked and may open a case, but
**never triggers a destructive action**. Four components enforce this separately (collector, ranker, playbook linter,
SOAR) and an end-to-end test checks they agree on every alert in the simulated company.

### 4.4 The nine scenarios in the lab

These are launched from **Scenario lab** in the console and explained in **Guide**. They run through the same
collectors and detectors as everything else, not as canned screenshots.

| Id | What happens | What Dwarpal does | MITRE |
|---|---|---|---|
| A1 | Credential stuffing from abroad, unknown computer | The engine refuses at once (DENY): new address, new country, unknown computer. The queue stays quiet because the engine already stopped it | T1110.004 |
| A2 | Stolen password used from a cloud server in the same country | DENY: the network belongs to a cloud provider on the threat list | T1078 |
| A3 | Residential proxy in the person's own city | The place looks right, so no refusal; STEP_UP because the computer is new. A password alone cannot pass | T1090.003 |
| A4 | Impossible travel: normal login, then London 20 minutes later | First login ALLOW, second DENY (8,000 km in 20 minutes) | T1078 |
| A5 | Login through Tor | DENY (known exit list) | T1090.003 |
| A6 | Stolen laptop with the owner's key, from a known network: hidden PowerShell, USB drive, finance files read and archived | The engine allows the login (its known blind spot). The laptop's signed sensor events raise a **P1 case** ("stolen-laptop-collection"); a playbook may isolate the laptop once an analyst signs a verdict | T1059.001, T1052.001, T1039, T1560 |
| A7 | Password spray: one address, fifteen accounts, then a success | Failures counted against the address; the login is refused (DENY) | T1110.003 |
| A8 | Beaconing: a Word-launched program calls one rare address every minute for two hours | Two sources agree (laptop sensor and firewall): **P1 case** on evidence a playbook may act on. The firewall-only alert is P2 and can never trigger an action alone | T1071 |
| A9 | Mass download (about 40 times normal) then external share from cloud storage | The cloud log is easy to forge, so the alerts are real but capped at P2 and P3: a human must decide | T1567.002 |
| L5 | Finance person downloads 60 spreadsheets at quarter end (harmless) | No correlation rule fires; the behaviour model notes it at P4, the lowest priority, and cannot act | none |
| L6 | Administrator runs the company's signed backup script (harmless) | No alert at all | none |
| QUIET | A quiet day | No incident; at most a few P3 or P4 notes | none |

Two kinds of scenario: **A1 to A5 and A7 are stopped by the engine itself** (the answer in the lab is DENY or STEP_UP,
and the alert queue stays quiet), while **A6, A8 and A9 produce alerts and cases** that an analyst works. Show one of
each.

The look-alikes L5 and L6 matter as much as the attacks: a SOC that cries wolf is as broken as one that sleeps.

### 4.5 A good five-minute story for this part

Launch **A6 (stolen laptop)**. Explain that the login is allowed, because everything about it looks right, and that this
is the engine's known blind spot. Run the scenario forward (about 14 minutes of scenario time; raise the speed or
fast-forward). Show the P1 case appear in the queue, open it, read the timeline of signed laptop events, add a note and
sign a verdict, then show the isolation in **Response**. Then launch **L5** and show that nothing dangerous happens.

---

## Part 5. The lab, the proof and the presentation

*Owner suggestion: one person. This covers what the audience sees, how we prove it is sound, and how it compares with
real products.*

### 5.1 The console (Layer 6)

A browser console on `https://localhost:8443`, built with plain HTML, CSS and JavaScript (no framework, no external
file, so nothing can be tampered with in transit and a strict content policy is possible).

| Page | For | What it shows |
|---|---|---|
| Overview | Analysts | Counts of open cases by priority, SLA breaches, who needs attention, risk leaders, which sources are reporting, the daily report (leads) |
| Alert queue | Analysts | Ranked alerts with reasons (scenarios A6, A8 and A9 produce these) |
| Cases | Analysts | A case workspace: timeline, notes, assignment, signed verdict |
| Hunt | Analysts | Free search with ready-made queries |
| Entity | Analysts | Risk for one person, device or address, and how it decayed |
| Response | Analysts | Isolations and playbook actions |
| Audit explorer | Analysts | The audit trail, with a **Verify** button for the chain |
| ATT&CK | Analysts | A grid of techniques seen |
| Scenario lab and Guide | Analysts | Launch an attack, pause, change speed, fast-forward; a walkthrough per scenario |
| Administration | Administrators | Policy and playbooks with the two-person install, What-If replay, privileged access, reset to day zero |

### 5.2 A suggested live demo (about 8 minutes)

1. Start `bin\lab.cmd`; open the console as `ana`. Show the overview. (1 min)
2. Launch **A4 impossible travel** and show the second login refused (the engine stops it, so the queue stays quiet).
   Then launch **A6 stolen laptop**, run it forward, open the P1 case; add a note; sign a verdict (if more than five
   minutes have passed since login, the console asks for the password and PIN again: that is step-up). (3 min)
3. Open **Audit explorer**, press **Verify**. Point out that your own actions are on the trail. (1 min)
4. Launch **L5 quarter-end download**. Nothing is blocked: it is a look-alike. (1 min)
5. Sign out; sign in as `dana`. Show the policy view and a proposed change needing a second administrator, then
   What-If replay. Try to open the alert queue to show administrators are not analysts. (2 min)

Fall-back: if the browser fights the certificate, the same demo can be shown from the tests and the reports.

### 5.3 How we know it is sound

| Evidence | Where | Headline |
|---|---|---|
| Automated tests | `mvn verify` | 1,174 tests, 0 failures (200 added in Layer 6) |
| Static analysis | SpotBugs with Find Security Bugs | 0 findings; every suppression has a written reason |
| CI and code scanning | GitHub Actions, CodeQL (security-extended), secret scanning | Green on the pushed layers |
| Threat model (STRIDE) | [threat-model.md](threat-model.md) | Every threat has a mitigation and a test that tries it |
| Red-team probes | each layer's report, plus 8 cross-part probes in Layer 6 | None of the final probes succeeded; the ones that did earlier were fixed |
| Standards baseline | [layer-6/standards.md](layer-6/standards.md) | OWASP ASVS, NIST SP 800-53 and 800-207, SOC 2, ISO 27001, CIS Controls, MITRE ATT&CK |

Real problems found and fixed while building (good to mention, it shows testing worked): a header-size attack, a count
query that would have leaked a colleague's activity, an audit check that missed rewritten-then-extended history, and a
reserved name that stopped the launcher from starting.

### 5.4 How it compares with products companies buy

| Enterprise product | Dwarpal |
|---|---|
| Cloud identity platform with risk detection (Entra ID Protection, Okta) | Engine with ten explainable scorers; every number checkable by hand |
| SSO with OIDC or SAML, hardware keys in the browser | A development identity provider and a simulated key |
| SIEM and SOAR (Splunk, Sentinel, Palo Alto XSOAR) | Collectors, search, correlation, playbooks and cases in one process |
| Hundreds of connectors | Three collectors and file connectors |
| Separate services, database, high availability | One process, in-memory state |
| Real endpoints and real attackers | A simulator and recorded attacks through the real collectors |

Where Dwarpal is **different, not just smaller**: glass-box decisions (every reason and number listed), signed evidence
only, a tamper-evident chain with an anchor, two-person changes everywhere, and no standing admin.

### 5.4a Questions to expect, with honest answers

* *"Is this real data?"* No, a simulation; the engine and the generator were written by the same team, so the results
  show consistency with the design, not real-world accuracy.
* *"Why not machine learning?"* Statistics we can explain and check by hand are preferred for access decisions; every
  decision must be explainable and auditable.
* *"Could it be attacked itself?"* Yes, that is what the threat model and the red-team probes are for; the report lists
  what was tried and what is still open.
* *"What does it cost?"* Nothing: free JDK, Maven and Git; no cloud account.

### 5.5 Future advancements (not required for the demo)

| Item | Why it matters |
|---|---|
| Keep lab state between runs (rebuild cases and risk from the audit trail) | Today the lab restarts at day zero |
| Sensor heartbeats | So the "sensor went silent" rule can fire |
| Container file and a remote-access recipe | So a friend can use the lab from another place |
| A static replay site on a free host | Show the story without running Java |
| Verdicts signed in the analyst's own browser or hardware key | Today the console server signs after a fresh step-up |
| Hybrid post-quantum signatures | Defence against future quantum attacks on today's signatures |
| Single sign-on with a real identity provider | Replaces the lab's development provider |

---

## Appendix: where to find things

| Need | File |
|---|---|
| Everything about the project, in order | [project-state.md](project-state.md) |
| Maths with derivations and worked examples | project-state.md sections 8 and 9 |
| Per-layer reports | layer-3, layer-4, layer-5, layer-5-2 and [layer-6-report.md](layer-6-report.md) |
| Threats and mitigations | [threat-model.md](threat-model.md) |
| Running the lab | [runbooks/lab.md](runbooks/lab.md) |
| Control baseline | [layer-6/standards.md](layer-6/standards.md) |
