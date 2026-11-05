# Layer 6 part 0: the contracts

*Written by the integration session. The part sessions build to this; changes to it go through the integration
session, which says so to every part.*

## 1. What part 0 delivers (already in the code)

| Piece | Where | What it is |
|---|---|---|
| The simulation in main code | `dev.dwarpal.sim` (`SimOrganisation`, `SimTelemetry`, `SimRequests`) | Moved out of tests. Same seed, same organisation and attacks |
| Lab certificate authority | `dev.dwarpal.lab.LabPki`, `dev.dwarpal.edge.DevPki` | Made once under `<lab>/pki`, owner-only files, renewed before they lapse. Leaves: `soc-api`, `console`, `ana`, `ben`, `cleo` |
| The whole SOC, running | `dev.dwarpal.lab.LabWorld` | Composition root of parts A to F over the simulated organisation, with the SOC API serving over mutual TLS on loopback |
| Scenario clock | `dev.dwarpal.lab.LabRunner` | Moves scenario time by a speed factor; pause, resume, speed; stops visibly on failure |
| Launcher | `dev.dwarpal.lab.LabMain` | `dwarpal lab [--dir --seed --users --speed --warmup-days --port]` |
| Thread-safe UEBA | `dev.dwarpal.lab.LockedUeba` | Part E is single-threaded; this is the only way the API and the clock share it |
| Module contract | `dev.dwarpal.console.ConsoleModule` | How H, I and J add routes and pages to the console server without touching its security code |
| Standards baseline | `docs/layer-6/standards.md` | The checklist every part is held to |

Facts about the simulated lab that parts rely on: 60 users by default, the script runs 2026-11-02 02:13 to
2026-11-09 14:00 (UTC, scenario time), 720 decided requests, nine attack/look-alike scenarios (A6, A8, A9, L5,
L6 and the others in `SimOrganisation.Scenario` and `SimTelemetry.Activity`), analysts `ana`, `ben` (sign
verdicts) and `cleo` (lead, reads reports). At speed 60 the whole script is about 3 hours of wall time.

**Not yet in part 0 (the integration session does these while the parts build, see section 6):** persistence of
SOC state through the chain, sensor heartbeats, an audit read API, `count by` through the SOC API, and the
signed delegation from the console to the SOC API. Parts must code against the interfaces below so they do not
change when those land.

## 2. Ownership: who may edit what (no two sessions edit the same file)

| Session | Parts | Owns (create and edit) | Reads only |
|---|---|---|---|
| **Console session** | **G** console server, **H** analyst console | `src/main/java/dev/dwarpal/console/**` (except `ConsoleModule.java`, which only the integration session edits), `src/main/resources/console/**` except `console/modules/admin/**`, `console/modules/lab/**`, `console/modules/guide/**`, tests under `src/test/java/dev/dwarpal/console/**` | everything else |
| **Lab session** | **J** scenario lab and guide, **I** admin and user views | `src/main/java/dev/dwarpal/lab/scenarios/**` (new), `src/main/java/dev/dwarpal/console/admin/**` and `.../console/lab/**` (modules implementing `ConsoleModule`), `src/main/resources/console/modules/admin/**`, `.../lab/**`, `.../guide/**`, tests under `src/test/java/dev/dwarpal/lab/scenarios/**`, `.../console/admin/**`, `.../console/lab/**`, `docs/layer-6/guide/**` | everything else |
| **Integration session** (this one) | part 0, 0b, K, integration, red team | `dev.dwarpal.lab` (except `scenarios`), `dev.dwarpal.socapi`, `dev.dwarpal.sim`, `ConsoleModule.java`, `docs/layer-6/standards.md`, `contract.md`, plan, reports, threat model, project state | everything |

A part that needs a change in a file it does not own sends the integration session a request (a message with the
exact change and why); the integration session makes it. This is the rule that kept 5.2's three parts from
colliding.

## 3. The console server's HTTP surface (G builds; H and the modules use it)

All paths are under one origin. Everything is JSON except the static files.

| Path | Method | Purpose |
|---|---|---|
| `/` , `/console/**` (static) | GET | The shell and modules, from an in-jar allow-list |
| `/console/api/session/login` | POST | Start login (user, password), returns the second-factor challenge |
| `/console/api/session/verify` | POST | Second factor; on success sets the `__Host-dwarpal` cookie and returns the anti-forgery token |
| `/console/api/session/stepup` | POST | Fresh second factor for privileged writes |
| `/console/api/session/logout` | POST | Destroys the session |
| `/console/api/me` | GET | Person id, roles, session expiry, step-up freshness |
| `/console/api/modules` | GET | The modules this person may see: id, title, minimum role |
| `/console/api/lab` | GET | Scenario time, speed, state (paused, running, finished, failed), counts |
| `/console/api/stream` | GET | Server-sent events: `lab.tick`, `alert.new`, `case.changed`, `isolation.changed`; one per session, capped |
| `/console/api/soc/**` | GET, POST | The SOC API calls for the person (queue, cases, case, timeline, notes, assignment, verdicts, risk, search, isolations, metrics, reports), carried over mutual TLS as that analyst |
| `/console/api/audit/**` | GET | Read-only audit explorer: page the chain, one record, verify a range, anchor state |
| `/console/api/<module id>/**` | GET, POST | Routes registered by a `ConsoleModule` |

Verdict signing in the first version: the console server asks `LabWorld.signVerdict(analystId, alertId, outcome)`
after a fresh step-up, and says so on screen ("signed by the lab's analyst key"). The `VerdictSigner`
interface (G defines it) is the seam where a WebAuthn or WebCrypto signature replaces it later.

The server talks to the SOC API through a small interface (`SocChannel`, G defines it) with one method per call,
`forAnalyst(id)`. The first implementation uses the analyst's own certificate from the lab PKI; part 0b replaces
it with a signed delegation from the `console` certificate. Nothing outside `SocChannel` knows which.

## 4. How a part reads the running world

`LabWorld` is the only object a part needs. Public, thread-safe for reading: `cases`, `book`, `soar`,
`isolation`, `store` (search), `ueba` (through `LockedUeba`), `assets`, `org` (users, keys, audit), `raised`,
`revocations`, `rankedNow()`, `dailyReport()`, `now()`, `scriptStart`, `scriptEnd`, `socApiUrl()`. Moving time:
`advanceTo`, `warmUp`; normally only `LabRunner` does that. The lab session adds scenario injection under
`dev.dwarpal.lab.scenarios` on top of `advanceTo`; it does not change `LabWorld`'s fields (it may ask for new
accessors).

## 5. Definition of done, and the red team

Each session finishes its parts to `docs/layer-6/standards.md` section 5. In addition:

* **Tests with the code**, same style as layers 4 to 5.2: JUnit, no mocks of the security parts, real HTTPS
  client against the real server. Timing probes need generous limits (see the layer 4 flakiness fixes).
* **A red-team pass on your own parts** before you report: write the attack as a working probe, watch it
  succeed or fail on your build, fix what succeeds, keep the probe as a regression test. Report both the fixed and
  the failed attempts.
* **Gate before you report:** `mvn -o verify spotbugs:check` green (JDK 25 at
  `C:\Program Files\Eclipse Adoptium\jdk-25.0.5.8-hotspot`, repo at the short path `C:\Users\Admin\dwr`).
* **Commit locally, never push.** The owner approves every push.
* **Notes for the integration session** in `docs/layer-6/part-<x>.md`: design, STRIDE and ASVS table, red-team
  findings, requests to integration, differences from enterprise products.
* **Free only.** No paid service, library with a fee, or account. Prefer the JDK and the code in this repository.

## 6. What the integration session does while the parts build (0b)

1. State rebuilt from the chain after a restart (cases, notes, assignments, isolation, verdict gate).
2. Sensor heartbeats from the simulated devices, so `sensor-heartbeat-missing` has something to miss.
3. An audit read API and chain verification entry points for the audit explorer.
4. `count by` through the SOC API's search.
5. Signed delegation from the console to the SOC API, replacing per-analyst certificates held by the console.
6. Part K (packaging), then the integration tests and the red team across the whole lab.
