# Layer 6 part J: the scenario lab and the guide

*Built by the lab session on branch `layer6/lab`. Not pushed. Everything runs on the simulated organisation (seed 7, 60
people): every number below measures consistency with the lab's own threat model, not real-world accuracy.*

## 1. What it is

A learner can launch each of the nine attack scenarios (A1 to A9 as `SimOrganisation` and `SimTelemetry` define them),
the two harmless look-alikes (L5, L6) and a quiet day, at the lab's current scenario time, and the events go in through
the real collectors, the real engine and the real detectors. The module says in plain words what the attacker does
before it runs and what the defender should see after; a walkthrough per scenario takes the learner through the
analyst console. A sandbox lets the learner write a correlation rule or a playbook and read the linter's findings.
A run exports as sanitised JSON for the static replay site.

| Piece | Where |
|---|---|
| Scenarios (text, expected results) | `dev.dwarpal.lab.scenarios.Scenario`, `ScenarioCatalog` |
| Builders (raw material at "now") | `Plans` |
| Launch limits, journal, per-launch report | `ScenarioRunner` |
| The lab that can be reset, fast-forwarded | `LabSession` (owns the `LabWorld` and the `LabRunner`) |
| Rule and playbook sandbox | `RuleSandbox` |
| Sanitised export | `RunExport` |
| Walkthroughs (one source for pages and Markdown) | `Walkthroughs`, `docs/layer-6/guide/*.md` |
| Console modules | `dev.dwarpal.console.lab.LabModule` (id `lab`), `GuideModule` (id `guide`), `ModuleKit` |
| Pages | `src/main/resources/console/modules/lab/**`, `.../guide/**` |

### How a scenario is launched

`ScenarioRunner.launch` picks the person (rotating through people the simulation's own script casts in no attack and no
look-alike, never the CEO), builds the items at `now + 30 s` and calls `LabWorld.inject`. `inject` merges the items into
the script in time order, so they play out as scenario time moves, exactly like the scripted ones; a paused clock
queues them ("begins when time moves"). Endpoint batches are numbered and signed by `LabWorld` with the device's own
agent key when they run, so injected and scripted batches of one device never collide.

The access-engine scenarios (A1 to A5, A7) are Dwarpal requests, decided by the real engine with the user's real
history. Their proof is in the audit trail, not in the queue: the module's per-launch report reads the engine's decision
(outcome, policy, chance of attack, signals) from the chain.

### What the lab actually produces (checked by `ScenarioGuideTest` on every build)

| | Engine | Queue (priority, may a playbook act) |
|---|---|---|
| A1 stuffing from abroad | DENY (about 80% chance of attack) | nothing above P4 |
| A2 cloud server, same country | DENY (`ip-reputation`) | nothing above P4 |
| A3 residential proxy | STEP_UP (about 1%; no verified second factor) | nothing above P4 |
| A4 impossible travel | ALLOW then DENY (`impossible-travel`) | nothing above P4 |
| A5 Tor | DENY (`ip-reputation`) | nothing above P4 |
| A6 stolen laptop at home | ALLOW (the thief has the owner's security key) | `stolen-laptop-collection` **P1, yes**; `encoded-powershell` P2, yes |
| A7 spray | DENY (`password-spray`) | nothing above P4 |
| A8 beaconing | | `beacon-from-document-process` **P1, yes**; `beacon-regular-destination` P2, **no** |
| A9 cloud exfiltration | | `cloud-bulk-download-then-external-share` P2, no; `cloud-download-volume` P3, no; nothing may act |
| L5 quarter-end download | | no correlation rule; UEBA P4 only |
| L6 administrator PowerShell | | nothing at all |
| Quiet day | | nothing above P3 |

Two things were found by running the lab and are stated in the guide: the SOC queue is **silent** for the login attacks
(the engine stopped them first, which is the right design but not what a learner expects), and A6 as first built
produced a STEP_UP at the odd hour of the launch, not the "allow" the simulation's script gets at the person's habit
time, so the cast now carries the owner's security key.

The test also signs a verdict on the A6 case: `APPLIED`, the laptop isolated and `PENDING_ACK` until the simulated
sensor's batch signed by the device's own key makes it `ISOLATED`; the same verdict twice is `REFUSED`.

## 2. Routes (all under `/console/api/lab/` and `/console/api/guide/`)

| Route | Role | Notes |
|---|---|---|
| `GET scenarios` | ANALYST | text and expectations for each scenario |
| `POST launch/{id}` | ANALYST | rate limited, see 3; says whether the clock is paused |
| `GET launches`, `GET launches/{n}` | ANALYST | the journal; what one launch produced (decisions, alerts, why-ranked) |
| `GET status` | ANALYST | clock state, speed, scenario time, queue by priority; failure text is a fixed sentence |
| `POST control/pause`, `resume` | LEAD | |
| `POST control/speed` | LEAD | 1 to 3,600 |
| `POST control/fastforward` | LEAD | 1 to 720 minutes, one at a time, in 10-minute steps |
| `POST control/reset` | ADMIN, **step-up** | back to day zero; launches and fast-forwards refused (409) while it runs |
| `GET sandbox/examples`, `POST sandbox/rule`, `POST sandbox/playbook` | ANALYST | see 4 |
| `GET export` | LEAD | see 5 |
| `GET guide/walkthroughs[/{id}]` | ANALYST | |

Every handler checks the person's role itself (`ModuleKit.guard`) in addition to the host's check on the registered
minimum. Bodies are strict JSON, at most 64 KiB, unknown fields refused. Errors are one short sentence; the submitted
text is never echoed.

## 3. Threat model: STRIDE with ASVS / Top 10

| # | Threat | Control | Test | Reference |
|---|---|---|---|---|
| S1 | A non-admin resets the lab | role in route registration and again in the handler; reset also needs `stepUpFresh` | `LabModuleTest` (3 tests) | ASVS V4.1, V4.2; A01 |
| S2 | A stale session performs a privileged write | host step-up and a second check inside the handler | `LabModuleTest.resetNeedsAFreshSecondFactor...` | ASVS V2.8, V4.3 |
| T1 | A learner's rule or playbook escapes the sandbox (object tags, aliases, bombs, deep nesting, giant files) | safe YAML loaders (no objects, no aliases, no duplicate keys), 16 KiB limit, 20 rules, linter refuses rules that can never fire | `ScenarioToolsTest.yamlTagsAliasesAndBombs...`, `...aRuleWithTooMany...` | ASVS V5.1, V5.5; A03, A08 |
| T2 | A learner's rule affects the live SOC | the rule runs in a private engine over a private copy of the records; alerts go to a list; test compares cases, raised alerts and chain head before and after | `ScenarioToolsTest.aGoodRuleRunsOnRecordedEvents...` | ASVS V1.4, V13.1 |
| T3 | A playbook acts on forgeable evidence | the real `PlaybookCompiler` refuses destructive steps on collected-only rules; sandbox never installs | `ScenarioToolsTest.aPlaybookOnForgeableEvidence...`, `ExamplesTest` | ASVS V11 |
| R1 | Who launched what | every write is audited by the host under the person; the journal keeps `by`, scenario, time | `LabModuleTest` | ASVS V7.1 |
| I1 | The export leaks a key, a hash, the lab directory, the host's names or real people | pseudonyms, field allow-list, key-like runs removed, final scan fails the export | `ScenarioToolsTest.theExportHolds...`, `...lastLineOfDefence...` | ASVS V8.3, V9; A02 |
| I2 | Error text echoes the submitted rule | findings name places and rule ids only | `ScenarioToolsTest.lintingNeverEchoes...` | ASVS V7.4 |
| I3 | Stored XSS through rule titles, findings, alert text, guide text | the pages insert text only with `textContent`; attributes from an allow-list; link targets restricted; a source test forbids `innerHTML`, `eval`, inline handlers and style | `FrontEndRulesTest` | ASVS V5.3; A03 |
| D1 | A scenario button held down | one launch per second, 12 per person per five minutes, a scenario cannot be launched again while it plays, world refuses more than 50,000 waiting items, past-dated items and unknown types | `LabModuleTest.aScenarioButtonHeldDown...`, `ScenarioToolsTest` (3 tests) | ASVS V11.1, V13.2; API4 |
| D2 | Expensive sandbox runs | one run at a time, one per person per 2 s, 100,000 records, 8 s budget, engine's own state limits | `ScenarioToolsTest.oneRunAtATime...` | ASVS V11.1 |
| D3 | Fast-forward or reset used to freeze the lab | one heavy operation at a time (429), fast-forward in 10-minute steps so the SOC API answers between steps | `LabModuleTest` | |
| E1 | Path parameters used for traversal or injection | identifier-only path parameters (letters, digits, `-`, `_`, 64 characters) | `LabModuleTest.badLaunches...` | ASVS V5.1.3, V12.3 |

ASVS levels touched: V4 (access control), V5 (validation and encoding), V7 (error handling), V8, V11 (business logic),
V13 (API), V14 (configuration; no new dependency).

## 4. The sandbox

* **Rule**: `RuleBook.load` with the lab's three datasets and their provenance. Findings are the linter's own: errors
  (unknown technique, duplicate id, a rule that can never fire, a provenance the dataset cannot carry) refuse the
  file; warnings are shown. `run: true` replays the first 100,000 records of the live chain through a fresh
  `CorrelationEngine` and reports matches, firings, the first 25 alerts it would have raised and the rules that matched
  nothing.
* **Playbook**: `PlaybookCompiler` in the lenient (authoring) mode against the shipped rule catalogue and guard rails;
  accepted files are described in plain words per rule. Nothing is installed (that takes two administrators in part I).
* Ten examples (good and bad) are served and run by `ExamplesTest`.

## 5. The export

`dwarpal-replay/1`: lab setting, launches, the last 500 alerts with ranking, reasons and techniques, and the events
those alerts cite (at most 3,000), all with pseudonyms (`person-1`, `device-1`, `ip-1`; documentation-range addresses
such as the C2 address are kept so the story reads). The first field says the data is simulated.

## 6. Red-team pass

Each probe is a working test. The first column says what happened on the first build.

| Probe | First result | Now |
|---|---|---|
| First launch of any lab | **Breach of the lab's own limit: refused.** The rate limiter's "never launched" marker was `Long.MIN_VALUE`; subtracting it overflowed, so the gap check refused the very first launch (found by the first probe run) | Fixed (marker is half of it); every test launches |
| Injecting an endpoint batch with the next number | Design finding: a collector refuses numbers that go backwards, so an injected batch would have made every later scripted batch of that device "replayed" | `LabWorld` numbers and signs every batch with the device key when it runs |
| Export of a lab with the A9 alert | **Would have refused every export:** the "base64-like" scan matched the 39-character rule name `cloud-bulk-download-then-external-share` and the alert id built from it (found while writing the export tests, before any export ran) | The scan needs upper case, lower case and digits and excludes `-`; the test keeps the rule name as a negative case |
| Command line with a PEM header in an event that is cited as evidence | **Self-inflicted denial:** the last-line scan refuses the whole export | PEM markers are removed from values first; the scan still refuses if one gets through |
| Launch or fast-forward during a reset | Launch went into the old, closed world and was lost | Refused with 409 while resetting; a second reset is refused with 429 |
| A6 as first built | Fidelity: the login at the launch hour was STEP_UP, not the simulation's ALLOW | The thief has the owner's security key; the test pins ALLOW |
| Reset by an analyst, a lead, and an administrator with a stale second factor | Held (403) | Regression tests |
| Object tag, alias bomb, 5,000-deep nesting, duplicate keys, oversize, control characters, empty, in a rule file | Held; no stack trace, no echo | Regression tests |
| Playbook with a destructive default, a 400-day deny, an unknown rule, an unknown step, an extra key, a secret in the version | Held | Regression tests |
| Rule that matches every event | Held: sample capped, records capped, engine's flood limits | Regression test |
| 20,000 junk lines three times over | Held: the world refuses after 50,000 waiting items; past-dated and non-item objects refused | Regression test |
| Scenario button pressed 60 times; 15 launches by one person | Held: one accepted; at most twelve in five minutes | Regression tests |
| Path parameter with `../`, `%00`, `;` | Held (400/404, not echoed) | Regression test |
| An analyst reads the export | Held (403; leads only) | Regression test |

## 7. Requests to the integration session

1. `LabSession` replaces `LabWorld` + `LabRunner` in `LabMain` and in the console host, so reset works; always ask the
   session for `world()` (a reset replaces it). `session.afterReset(hook)` lets the host rebuild what hangs off the world.
2. The host constructs `new LabModule(session)` and `new GuideModule()`.
3. Role semantics: I treat ANALYST < LEAD < ADMIN as hierarchical inside the handlers. Please make the host's `minimum`
   hierarchical in the same way, or tell me otherwise.
4. Front-end contract assumed (sent to the console session): `export default { id, title, requires, view(root, shell) }`,
   `shell.api.get(path)` / `shell.api.post(path, object)` returning parsed JSON, `shell.needStepUp()`.
5. `LabWorld.inject` and endpoint renumbering are yours now (thank you).

## 8. What this does differently from a commercial product

| Commercial | This lab |
|---|---|
| Adversary emulation runs real techniques on real hosts (Atomic Red Team, Caldera, Stratus, breach-and-attack-simulation products) | Injects prepared telemetry through the real collectors; the attack is a recording, not an execution, and the detectors were written with the same scenarios in mind |
| Detection engineering with a test harness and CI against sample logs | A sandbox that replays one lab's recorded events, with a time and size budget |
| Playbook testing in a staging tenant with mocked integrations | A linter and a plain-words description; nothing runs |
| Training ranges with scoring and instructors | A walkthrough per scenario, verified against the running lab, no scoring |
| Case and detection content from a vendor | Everything is in this repository and was run, not copied |
