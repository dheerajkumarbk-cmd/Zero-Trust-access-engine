# Layer 6 build plan: the lab (launcher, console, scenarios, packaging)

*Draft for the owner's review. Nothing here is built yet. Layer 6 is built the way layers 5 and 5.2 were: one
integration session builds the shared contracts first, part sessions build in parallel, then integration and a
red-team pass on the whole.*

## 1. Goal

Dwarpal is a policy engine, an enforcement edge and a SOC, but today it only runs inside tests. Layer 6 turns it
into a **home security lab** that starts with one command, can be watched in a browser the way analysts watch a
real SOC, can be attacked on purpose, and can be handed to a friend as a way to learn how security operations work.

It is not a mini-project demo. The test is: *would an analyst recognise the workflow?* Queue, case, evidence,
timeline, hunt, entity page, ATT&CK view, audit explorer, response actions with approvals.

Constraints that shape every choice below:

* **Free only.** No paid service, licence or cloud account. Everything runs on one home machine.
* **No new supply chain.** The console is plain HTML, CSS and JavaScript served by Dwarpal itself: no npm install,
  no framework, no CDN, no build step. A strict Content-Security-Policy (self only, no inline script) is then
  possible, and one person can read the whole front end.
* **Dwarpal protects its own console.** Analysts log in through Dwarpal's identity provider and the console sits
  behind Dwarpal's own gateway. The lab is the first real application of the product.
* **Honest about the gap to enterprise tools** (section 8), not pretending to match them.

## 2. What exists and what is missing

| Exists (layers 1 to 5.2) | Missing for a lab |
|---|---|
| Engine, scorers, administrator, gateway, SOC platform, SOC API over mutual TLS | **No process starts them together.** The only composition of all parts is the test fixture `SocWorld` |
| `SimOrganisation`, `SimTelemetry` (nine attacks, benign noise) | They live in test sources and produce a finished data set, not a live feed |
| Development PKI (`DevPki`), development identity provider | `DevPki` is test code; there is no first-run key and certificate set-up |
| In-memory cases, risk, isolations, baselines | State is lost on restart (a lab that forgets every night is not a lab) |
| SOC API returns JSON to a client that is not a browser | No browser-facing layer: sessions, cookies, CSRF, escaping, static files |

## 3. Parts

| Part | Builds | Package |
|---|---|---|
| **0. Contracts and launcher** (integration session, first) | Move the simulation and dev PKI from test to main under a `lab` package; a `dwarpal lab` command that boots everything from one lab directory; live scenario clock; persistence of SOC state through the audit chain; sensor heartbeats; the console contract | `dev.dwarpal.lab` |
| **G. Console server** | Browser-facing back end: login through Dwarpal's IdP, cookie session, CSRF, per-analyst identity towards the SOC API, static file server with strict headers, live updates, console audit | `dev.dwarpal.console` |
| **H. Analyst console** | The SOC front end (views in section 5) | `src/main/resources/console/` |
| **I. Admin and user views** | Policy bundle view and two-person install, PAM approvals, sessions, device posture, the "why was I denied" page for ordinary users | same server, role-based views |
| **J. Scenario lab and guide** | Attack runner (A1 to A9 on demand), guided walkthroughs for a learner, reset, export of a recorded run | `dev.dwarpal.lab` plus guide pages |
| **K. Packaging and hosting** | One jar, one start script, optional container file, replay build for static hosting, remote-access recipe | `docs/runbooks/`, build scripts |

```
 scenario clock --> simulated org --> collectors --> Ingestor --> audit chain (encrypted, anchored)
 (J, live)          + attacker                                          |
                                                      detection / correlation / UEBA / ranking (layer 5.2)
                                                                        |
 browser --HTTPS--> G console server --mTLS, analyst identity--> SOC API (F)  +  admin and gateway APIs
    ^   cookie, CSRF, CSP           (the lab launcher starts all of it)
    |
 H analyst console   I admin and user views   J scenario controls
```

## 4. Key design decisions (with the reason)

1. **The browser never talks to the SOC API directly.** A browser cannot hold a mutual-TLS client key safely, and
   the SOC API identifies analysts by certificate subject. The console server (G) is the only client, and it
   presents the analyst's own certificate for that analyst's calls, so the SOC API's per-analyst rules (never
   one's own case, leads-only reports, audit by name) keep working unchanged. *Difference from enterprise:*
   products use an API gateway and SSO tokens; here the certificate stands in for the token.
2. **Login uses Dwarpal's identity provider with WebAuthn-style step-up** (the simulated authenticator exists from
   layer 3). Session cookie: `__Host-` prefix, `HttpOnly`, `Secure`, `SameSite=Strict`, short idle and absolute
   lifetime, bound to a device key the way gateway sessions are.
3. **Signed verdicts need a signature the analyst owns.** Two options: the browser signs with a WebCrypto Ed25519
   key kept non-extractable (strongest, needs a current browser), or the console server signs after a fresh
   step-up. Recommended: browser signing, with a server-side fallback for the lab that is flagged on screen.
4. **State survives restart by being derived from the chain.** Cases, notes, assignments, isolations and the
   verdict gate become chain records (`SOC_STATE`), and baselines are rebuilt by replaying the event stream. No
   database: the tamper-evident trail already exists and replay is the only recovery path, which also gives the
   lab a "rebuild from evidence" demonstration. (Closes the known leftover "state lives in memory".)
5. **A live feed, not a finished data set.** A scenario clock advances simulated time (default 1 second of wall
   time = 1 minute simulated, adjustable) and streams events through the real collectors. Attacks are injected
   by button or on a schedule. Benign noise runs continuously so the queue is not an obvious tell.
6. **No framework, but real structure.** Small ES modules, one custom element per view, one `api.js` that is the
   only code that calls the server. Text is always inserted with `textContent`; there is no `innerHTML` anywhere,
   enforced by a build-time test that scans the sources. (Closes "the console must HTML-escape".)
7. **Everything the console does is audited** under the logged-in analyst, into the same chain, so the console's
   own use shows up in the audit explorer.

## 5. The analyst console (part H): views

| View | What an analyst does | Backed by |
|---|---|---|
| Overview | Open P1/P2 count, SLA clock, risk leaders, sources healthy or silent, last daily report | `/v1/metrics`, `/v1/reports`, collector health |
| Alert queue | Ranked P1 to P4, filter by entity, technique, provenance; every row says *why* it has that rank | `/v1/queue` |
| Case workspace | Timeline, evidence with chain sequence links, notes, assignment, SLA, decide (sign verdict), actions taken | `/v1/cases/*`, `/v1/verdicts` |
| Hunt | Query box for the search language with examples and syntax help, result table, `count by` chart, saved queries | `/v1/search` (add `counts`) |
| Entity page | Person, device or address: risk score as a list of contributions with half-lives, recent events, peers, related cases | `/v1/risk/*` |
| ATT&CK view | Technique grid coloured by detections, and by *coverage* (what the rules could catch, not only what fired) | `MitreCoverage` |
| Response | Isolated devices, pending acknowledgements, playbook run history, watch-only versus full mode shown | `/v1/isolations` |
| Audit explorer | Browse the chain, verify it from the page, show anchor state, open a record | read-only audit API (new) |
| Policy and what-if (part I) | See a policy in readable form, replay recent requests against a changed policy (M8) | layer 3 and 5 analytics |

Look and feel: dark by default, dense tables, keyboard shortcuts (j/k to move, enter to open, `/` to hunt), the
colour of a priority never the only signal (a text label too), usable at laptop width. A light theme follows
`prefers-color-scheme`.

## 6. Scenario lab and guide (part J)

This is what makes it a teaching tool and not only a dashboard.

* **Attack runner**: nine buttons (A1 to A9) and "run a quiet day". Each says in plain words what the attacker
  does *before* it runs, and what the defender should see afterwards.
* **Guided walkthroughs**: for each attack a short path through the console ("open the queue, find the P1, open
  the case, find the first evidence, read the timeline, decide"), the matching ATT&CK technique, and what the
  same thing looks like in a commercial product.
* **Break it yourself**: a sandbox where the learner writes a correlation rule or playbook in the safe YAML,
  watches the linter refuse a dangerous one, and runs a good one against recorded data.
* **Reset and export**: reset to day zero; export a run as a sanitised JSON replay (used by part K).

## 7. Packaging and hosting (part K): what "hosting" honestly means

| Target | How | Cost | Notes |
|---|---|---|---|
| Home machine (primary) | `dwarpal lab` starts everything; browser at `https://localhost:8443` | none | The real thing: live events, mutual TLS, persistence |
| Container (optional) | One container file, a compose file with a volume for the lab directory | none | Same code, easier to hand to a friend |
| A friend over the internet | A free overlay network or free tunnel in front of Dwarpal's own gateway | none | The visitor reaches the lab only after Dwarpal lets them in; designed in part K |
| Vercel (static) | A **replay site**: the console in "replay mode" over an exported, sanitised run (JSON), no server | none (free tier) | Shows the UI and a recorded incident; it cannot run Java. Labelled "recorded", never shown as live |

Vercel cannot host the Java lab, so it is only a showcase of recorded runs. The real home of the lab is the home
machine.

## 8. Differences from enterprise products (for the project state document)

| Enterprise (a commercial SIEM, SOAR and XDR suite) | The lab |
|---|---|
| Distributed indexing and storage, tiered retention | One process, chain-backed store, bounded memory, rebuild by replay |
| SSO with SAML or OIDC, SCIM for users | Dwarpal's identity provider; one certificate per analyst |
| Hundreds of connectors and a marketplace of playbooks | Three collectors, file connectors, playbooks as reviewed YAML |
| Case management integrated with ticketing and chat | Built-in case book; no external ticketing |
| Machine-learning detections tuned on very large data | Statistics a person can check by hand; thresholds not yet calibrated on real logs |
| Real agents on real endpoints | A simulated sensor and a small device agent |
| 24/7 support and compliance certification | Documentation, tests and red-team notes |

## 9. Integration checks and red team for Layer 6

Built after G, H, I and J land, as with layer 5.2:

* End to end through a real HTTPS client: log in, open a P1, sign a verdict, see the isolation acknowledged, find
  the analyst's actions in the audit trail, restart the lab and find the same cases.
* Red team on the console: stored XSS through every free-text field the SOC API returns (alert text, notes,
  hostnames, user-agent strings), CSRF on every write, session fixation and theft, clickjacking (frame
  ancestors), path traversal in the static server, cookie scope, open redirect after login, brute force and
  lockout, a stranger's certificate reaching the SOC API through the console, an analyst impersonating another by
  editing a request, caching of sensitive pages, the replay export leaking keys or real hostnames, log injection
  into the audit chain through console input.
* Cross-part: a restart during an isolation (the pending acknowledgement survives), clock skew between the
  scenario clock and wall time, two analysts on one case at once.
* Front-end checks without a paid tool: a scripted run of each view in the built-in browser (screenshots kept
  for the report), a source test that forbids `innerHTML`, `eval` and inline handlers, a header test for CSP and
  cookies.

## 10. Order of work (decided by the owner on 2026-11-05)

The whole of Layer 6 is built before 9 November; there is no cut line. Two part sessions, each building two parts,
run after part 0 so that token use stays lower than with four sessions:

| Session | Builds | Why together |
|---|---|---|
| **Console session** | G console server, then H analyst console | H is the front end of G; one author keeps the API and the pages consistent |
| **Lab session** | J scenario lab and guide, then I admin and user views | Both are modules on G's `ConsoleModule` contract and share no files with the console session |
| **Integration session** (this one) | Part 0, then 0b (state from the chain, heartbeats, audit API, `count by`, signed delegation), K packaging, integration checks, red team, reports | Owns the shared contracts and the cross-part truth |

The integration session keeps in contact with both, reports progress to the owner in short messages, and runs the
integration and red-team pass when both parts land. Contracts, file ownership and the definition of done are in
`docs/layer-6/contract.md`; the control baseline (OWASP ASVS L2/L3, NIST 800-53 and 800-207, SOC 2, ISO 27001,
CIS, MITRE) is in `docs/layer-6/standards.md`.

## 11. Open decisions

Answered by the owner: finish everything before 9 November; two sessions of two parts each; follow the control
frameworks used in large firms. Still open and defaulted unless the owner says otherwise:

1. Verdict signing: the console server signs after a fresh step-up with the lab's analyst key (shown on screen);
   browser or hardware-bound signing is a later swap behind one interface.
2. Friend access: home network first; the remote-access recipe is part K.
