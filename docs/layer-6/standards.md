# Layer 6 standards and control baseline

Every Layer 6 part is built to this baseline and checked against it in the layer's integration pass. It is the
set of recognised frameworks and control families that large security-sensitive organisations (banks, asset
managers, data-platform vendors) use for exactly this kind of system: a web console over security data with
privileged actions. It is a **design baseline and a checklist, not a certification**; nothing here claims an
audit by anyone. Where the lab differs from what a company would run, the difference is named in the layer report.

## 1. Frameworks used, and for what

| Framework | Used for |
|---|---|
| NIST SP 800-207 (Zero Trust Architecture) | The console is a resource behind Dwarpal's own policy decision point; every request is authenticated, authorised and logged, never trusted for network position |
| OWASP ASVS 4.0.3, **Level 2 for everything, Level 3 where it is cheap** | The web application checklist: authentication (V2), session (V3), access control (V4), validation and encoding (V5), data protection (V8), communications (V9), logging (V7), API (V13), configuration (V14) |
| OWASP Top 10 (2021) and API Security Top 10 (2023) | The red-team list for the console and its JSON API |
| NIST SP 800-53 Rev. 5 (families AC, AU, IA, SC, SI, CM) | Control language for access control, audit, identification and authentication, transmission protection, input handling, configuration |
| NIST CSF 2.0 (Govern, Identify, Protect, Detect, Respond, Recover) | How the lab's features map to a programme; used in the layer report |
| NIST SP 800-61 (incident handling), SP 800-92 (log management) | The analyst workflow (detect, analyse, contain, eradicate, recover, lessons) and what the audit explorer must show |
| ISO/IEC 27001:2022 Annex A, SOC 2 Trust Services Criteria (CC6 logical access, CC7 system operations, CC8 change management) | The evidence an auditor would ask for: who can do what, who did what, how changes are approved |
| MITRE ATT&CK and MITRE D3FEND | Detection coverage view, and naming the defensive technique each control implements |
| CIS Controls v8 (3, 5, 6, 8, 13, 16) | Practical priority order: data protection, account and access management, audit log management, network monitoring, application security |
| OWASP Secure Headers Project, Mozilla Observatory grade A+ target | Exact response headers (section 3) |
| SLSA level 1 to 2 practices, CycloneDX SBOM | Build integrity: one pinned build, an SBOM (already produced), no front-end package manager at all |

## 2. Practices taken from how data-platform and asset-management firms run internal tools

The firms the owner named do not publish their internal controls, so this is not a copy of anyone's system. It is
the publicly described practice of such organisations, applied here:

* **Purpose-limited, least-privilege access.** A role sees the pages it needs; leads see reports; nobody works a
  case about themselves; the console server has no standing right to act as anyone.
* **Every access is itself evidence.** Reads of sensitive data (a case about a person, an audit record) are
  audited, not only writes.
* **Four-eyes on change.** Detection rules, playbooks and policies change only with two administrators' signatures
  (already built in 5.2 and layer 3); the console shows who approved what.
* **Lineage.** Every figure on screen can be followed back to the audit sequence numbers it rests on, and every
  alert says which evidence class it rests on (verified, sensor-signed, collected).
* **Time-bound privilege and break-glass.** Elevated rights expire; emergency access is possible, loud and reviewed
  (layer 3 PAM, shown in the admin view).
* **Segregation of duties.** The person who signs a verdict is not the person who installs a playbook; the
  console server that carries requests cannot sign for an analyst.
* **Immutable, anchored audit trail.** Already built; the console must let an analyst verify it, not just read it.
* **Fail closed, say so.** If a dependency is down the page says "unavailable", never an empty list that looks
  like "nothing wrong".

## 3. Web security baseline (testable; the integration pass checks every line)

**Transport.** HTTPS only, TLS 1.3 (reuse `TlsContexts`), HSTS `max-age=63072000; includeSubDomains`, no mixed
content, no plain HTTP listener except a redirect that sends nothing else.

**Response headers on every response**

| Header | Value |
|---|---|
| Content-Security-Policy | `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; require-trusted-types-for 'script'; upgrade-insecure-requests` |
| X-Content-Type-Options | `nosniff` |
| Referrer-Policy | `no-referrer` |
| Permissions-Policy | `camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()` |
| Cross-Origin-Opener-Policy / -Resource-Policy / -Embedder-Policy | `same-origin` / `same-origin` / `require-corp` |
| Cache-Control | `no-store` for every API and page that shows security data; long-lived, hashed names only for static assets |
| X-Frame-Options | `DENY` (belt and braces with `frame-ancestors`) |

No `unsafe-inline`, no `unsafe-eval`, no CDN, no external font, no analytics.

**Session and cookies.** One session cookie named `__Host-dwarpal`: `Secure; HttpOnly; SameSite=Strict; Path=/`.
Idle timeout 15 minutes, absolute lifetime 8 hours, new identifier at login and at step-up (no fixation), server
side session store, logout destroys it, concurrent session limit per person with a visible list. The session is
bound to the client's TLS channel parameters where the platform allows and to a device key like Dwarpal's other
sessions where it does not.

**CSRF.** Every write needs (a) the session cookie, (b) a per-session anti-forgery token in a custom header,
(c) an `Origin` header equal to the console's own origin, and (d) `Content-Type: application/json`. CORS is not
enabled at all.

**Authentication.** Through Dwarpal's identity provider: password (PBKDF2, existing) plus a second factor
(simulated WebAuthn, existing). Login throttling per account and per source with exponential delay and a visible
lockout, identical answer for a wrong user and a wrong password, no account listing. **Step-up**: signing a
verdict, installing a playbook or policy, approving privilege, isolating a device or changing a role needs a
second-factor proof no older than five minutes.

**Authorisation.** Server side on every route and every object, by role and by ownership (an analyst cannot read
a case about themselves; the SOC API enforces it again). The page hides what a role cannot use, but hiding is
never the control.

**Output and input.** All text from the SOC API (alert text, notes, host names, user agents) is untrusted. The
front end inserts text with `textContent` or `setAttribute` of allow-listed attributes only; there is no
`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `new Function`, `setTimeout(string)` or
inline event handler anywhere, and a source test fails the build if one appears. The server limits body size,
rejects unknown JSON fields, validates every identifier against the existing `Validate` rules, and returns the
same short error shapes the SOC API uses, never a stack trace or a path.

**Static files.** Served only from a fixed in-jar allow-list by exact name (no directory listing, no path
resolution from user input), correct `Content-Type`, `nosniff`.

**Audit of the console.** Login, failed login, step-up, logout, every write, and every read of a sensitive object
are written to the audit chain with the person, the console session id (hashed), the object and the outcome.
Audit failure is itself surfaced (as in the SOC API).

**Secrets.** Nothing secret in URLs, local storage, or the page. The only browser state is the session cookie and
a non-sensitive UI preference (theme, column choice) in `localStorage`, wrapped in try/catch.

**Availability.** Per-person and per-source rate limits, bounded request sizes and concurrency, a request timeout,
a bounded event stream (one per session, keep-alive, server-side cap) and a bounded number of sessions.

## 4. Control map (what an auditor would look at)

| Control | Where it lives | Standard reference |
|---|---|---|
| Unique identification of every analyst | IdP login, certificate subject, audit by name | NIST AC-2, IA-2; SOC 2 CC6.1; ASVS V2 |
| Multi-factor and step-up | IdP second factor, five-minute freshness for privileged writes | IA-2(1), IA-11; ASVS V2.8 |
| Least privilege and separation of duties | Roles, no-own-case, leads-only reports, two-person install | AC-5, AC-6; CC6.3 |
| Session management | `__Host-` cookie, idle and absolute timeouts, destroy on logout | AC-12, SC-23; ASVS V3 |
| Protect transmitted data | TLS 1.3, mutual TLS to the SOC API | SC-8, SC-13; ASVS V9 |
| Audit generation and review | Every write and sensitive read audited, chain verified in the page | AU-2, AU-3, AU-6, AU-9, AU-10; CC7.2; SP 800-92 |
| Tamper-evident logs | Keyed chain with anchored head (layers 1 to 5) | AU-9(3), AU-10; ASVS V7 |
| Input validation and output encoding | Strict parsers, `textContent`, CSP with Trusted Types | SI-10; ASVS V5 |
| Error handling that does not leak | Short public errors, details only in the audit | SI-11; ASVS V7.4 |
| Configuration baseline | Fixed headers, fixed allow-list, no debug routes, a test for each | CM-6, CM-7; ASVS V14 |
| Change approval | Two-person signed playbooks and policy bundles | CM-3, CM-5; CC8.1 |
| Incident handling | Queue, case, evidence, containment with acknowledgement, review | SP 800-61; IR-4, IR-5 |
| Supply chain | No front-end packages, SBOM, pinned Maven build | SA-12, SR-3; SLSA |

## 5. What "done" means for a part

A part is done when (1) its tests pass, (2) every line of section 3 that it touches has a test, (3) its own red
team found and fixed what it found, with a regression test for each (the layer's standing rule), (4) its
threat-model rows (STRIDE, with the ASVS or Top 10 item) are written, and (5) it states in its notes what it
does differently from a commercial product.
