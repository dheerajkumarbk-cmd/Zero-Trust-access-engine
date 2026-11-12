# Layer 6 report: the lab (launcher, console, scenario lab, admin views)

*Status: built, integrated and tested on the local branch `layer6/integration`; not pushed. Date: 2026-11-06.*

## 1. What was built, in one paragraph

Dwarpal is now something a person can start with one command and use. `bin\lab.cmd` builds one jar and starts the
whole system on a simulated organisation: the engine, the enforcement edge's SOC, the SIEM, UEBA and SOAR platform
and the SOC API, behind a browser console that works the way a security analyst's tools work (alert queue, cases,
signed verdicts, hunt, entity risk, audit explorer, ATT&CK view), with a scenario lab that launches the nine attack
and look-alike scenarios on demand, a guide that walks through each one, and administrator pages for two-person
policy and playbook changes, what-if replay and privileged access. It is built to a stated control baseline
(OWASP ASVS L2/L3, NIST SP 800-53 and 800-207, SOC 2, ISO 27001, CIS Controls, MITRE) and is free to run.

## 2. The parts

| Part | What it is | Package | Size |
|---|---|---|---|
| 0 Lab core (integration) | Simulation and development PKI moved into main code; `LabWorld` runs all six SOC parts behind the SOC API; scenario clock; certificates kept and renewed; launcher; thread-safe UEBA | `lab`, `sim` | 1,174 + 874 lines |
| 0b Shared pieces (integration) | `count by` through the SOC API; audit read and verify; signed per-call delegation from the console to the SOC API; scenario injection; administrators, installers, privileged access and request recorder in the lab world | `lab`, `socapi` | |
| G Console server | HTTPS (TLS 1.3) host with login through the identity provider and a second factor, `__Host-` session cookie, CSRF, step-up, throttling, exact security headers, audit, event stream, module host | `console` | 3,239 lines |
| H Analyst console | Plain HTML, CSS and JavaScript (no npm, no framework, no CDN): shell, queue, case workspace with verdicts, hunt, entity page, response, audit explorer with verify, ATT&CK grid, overview | `src/main/resources/console` | 24 scripts, 2,398 lines |
| I Admin and user views | Policy and playbook view and two-person install, what-if replay, privileged access with break-glass review, sessions and devices, "why was I denied", lab reset | `console.admin` | 1,061 lines |
| J Scenario lab and guide | Attack runner, lab controls, per-attack guide, rule and playbook sandbox, sanitised run export, reset session | `lab.scenarios`, `console.lab` | 1,748 + 644 lines |
| K Packaging | `lab-jar` profile, `bin/lab.cmd` and `bin/lab.sh`, runbook | `pom.xml`, `bin`, `docs/runbooks/lab.md` | |

How the parts were built: the integration session wrote the shared contracts first (`docs/layer-6/contract.md`,
`standards.md`, the `ConsoleModule` interface); two part sessions built two parts each on their own branches; the
integration session reviewed and merged them, wired them into one launcher and ran the cross-part checks.

## 3. Architecture

```
 browser --HTTPS, cookie, CSRF, CSP--> console server (G) --- ConsoleModule SPI --- lab, guide, admin modules (J, I)
                                             |
                       one signed assertion per call (acts for the analyst it names)
                                             v
                  SOC API over mutual TLS (layer 5.2) --> cases, risk, search, counts, reports, verdicts
                                             |
   LabSession (reset to day zero) --> LabWorld: collectors -> keyed audit chain -> detection, correlation, UEBA,
   scenario clock                         ranking -> cases -> SOAR -> signal feed, revocation, device isolation
```

Decisions worth knowing:

* **The browser never speaks to the SOC API.** The console server does, and it presents its own certificate plus
  one assertion per call signed with a key the key ring trusts only for this (bound to method, path and body, one
  use, 60 seconds). A copy of a header is useless; the console's certificate alone is nobody.
* **Administrators are not analysts.** An administrator installs policy and approves privilege but cannot open the
  SOC queue or sign a verdict (separation of duties); an analyst cannot reset the lab or install anything.
* **No front-end supply chain.** No package manager, framework or external file. A strict Content-Security-Policy
  (no inline script or style, Trusted Types) is therefore possible, and a source test fails the build on
  `innerHTML`, `eval` or inline handlers.
* **Everything the console does is evidence.** Logins, step-ups, writes and sensitive reads are written to the same
  keyed audit chain under the person's name, and the audit explorer verifies the chain (and the anchor) from the page.
* **Verdicts are signed on the console server** with the lab's analyst key after a fresh step-up, and the page says
  so; `VerdictSigner` is the seam for a browser or hardware key.

## 4. Results

| Check | Result |
|---|---|
| Tests | 1174, 0 failures (200 of them new in Layer 6, in the console, lab, admin, scenario and integration classes) |
| SpotBugs with Find Security Bugs | 0 findings; suppressions only with written reasons (simulator's seeded random generator, validated keytool launch) |
| End to end through the launcher over HTTPS | Login, queue, audit verification, lab pages, role limits for analyst, administrator and ordinary user |
| Cross-part red team | Eight probes, none succeeded (section 5) |
| Size | 318 main classes (43,688 lines), 163 test files (31,043 lines) |

## 5. Red team

Each part ran its own red team and fixed what succeeded (details in `docs/layer-6/part-g.md` to `part-j.md` and
`docs/threat-model.md` v1.5):

* **Console server (G):** a 200 KB request header was accepted (fixed: 16 KiB limit, 431); the three-sessions limit could
  end the newest session (fixed); 13 further probes failed (cross-session CSRF token, session id in the query,
  request smuggling, stalled bodies, stack-trace hunting, a copied delegation header, and others).
* **Analyst console (H):** probes for markup injection through every field, with a source test that scans all
  scripts.
* **Admin and user views (I):** a refused policy file's text was echoed back to the browser (fixed); about ten other
  probes failed (same signer twice, stale second factor, replayed or rolled-back installs, someone else's decision
  reference, `../` in references, elevation abuse, hostile YAML).
* **Scenario lab (J):** sandbox escape, scenario button as denial of service, reset by a non-admin, an export that
  leaks a key.
* **Integration:** CSRF without token or from another origin, hostile text through the whole stack, a verdict naming
  another analyst, role escalation across modules, an export scanned for passwords and certificates, path traversal
  in ten spellings, a lab reset while an analyst is logged in, the console's actions on the audit trail. None
  succeeded.
* **Found while integrating (fixed):** a count-by that leaked colleague activity; an anchor check that passed
  rewritten-then-extended history; the host reserving the module id the lab needed.

## 6. Differences from an enterprise product

| Enterprise | Dwarpal lab |
|---|---|
| SSO with OIDC or SAML, hardware keys in the browser | The development identity provider and a simulated key; step-up always asks again |
| Verdicts signed in the analyst's own key | Signed on the console server after a fresh step-up (one interface to swap) |
| Console and SOC as separate services with a database, high availability, SIEM the console cannot write to | One process, in-memory state, the same audit chain |
| Tokens issued by the identity provider for service calls | A per-call assertion signed by a delegation key the console holds |
| Hundreds of connectors, a marketplace, ticketing integrations | Three collectors, file connectors, reviewed YAML playbooks |
| Real endpoints and real attackers | A simulated sensor and recorded attacks injected through the real collectors |
| Certificates from a managed PKI with revocation | A private lab CA, 30-day certificates renewed automatically |

## 7. Limits and what comes next

* The lab starts again from day zero on every restart (certificates, logins and seed are kept). Rebuilding cases,
  risk and isolations from the audit trail touches six components; the run export keeps a run meanwhile.
* Sensor heartbeats run only in the live lab, not during the warm-up. The new scenario A10 switches one sensor off to raise `sensor-heartbeat-missing`.
* The screens have been run in a simulated page and over HTTPS but not looked at by eye in a real browser by the build
  sessions: layout, themes and shortcuts need one look (runbook: import `lab/pki/ca.pem`).
* Not built (after the submission, per the plan): the container file, a remote-access recipe for a friend, a static
  replay site on a free host, hybrid post-quantum signatures.

## 8. How to run it

See `docs/runbooks/lab.md`. In short: `bin\lab.cmd`, trust `lab\pki\ca.pem` once in your browser, open
`https://localhost:8443`, log in with a demo login printed at start (`ana`, `ben`, `cleo`, `dana`, `uma`).
