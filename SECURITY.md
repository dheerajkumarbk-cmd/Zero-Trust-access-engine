# Security Policy

Dwarpal is an access-control component, so its own security is part of its function.

## Reporting a vulnerability

Please open a private security advisory on GitHub (Security tab -> "Report a vulnerability")
rather than a public issue.

## Built-in safeguards

| Area | Safeguard |
|---|---|
| Policy files | Safe YAML only (no object construction, CVE-2022-1471), no aliases, no duplicate keys, size/depth/node limits, strict schema, lint gate |
| Inputs | Identifier allow-list blocks log injection (CWE-117); all domain objects validated at construction |
| Failure | Fail-closed: engine errors and unavailable signals never become ALLOW |
| Disclosure | Requesters see a generic message; full explanations go to analysts only |
| Trust | Device posture and login proofs count only when signed (Ed25519) by a key of the right purpose, owner and age |
| Accountability | HMAC-SHA256 chained audit trail; no audit, no access |
| Administration | Policy changes need two administrators' signatures; rollback refused |
| Learning | Behaviour baselines learn only from full ALLOWs; bounded, flood-resistant stores |
| Sessions | Hashed 256-bit tokens; every use signed with the client's session key and single-use; device-agent binding and key-bound MFA at login; continuous evaluation; idle, lifetime and classification-based re-authentication limits; instant revocation |
| Privileged access | No standing admin; just-in-time elevation needs eligibility, fresh single-use WebAuthn, a reason and a different person's signed approval; break-glass is sealed, paged, time-boxed and reviewed; rate limits count only authenticated actions |
| Enforcement points | Mutual TLS 1.3 between components, clients pinned to the exact server certificate; each enforcement point scoped to its own resources; sessions open only on verified, single-use, key-bound MFA; single decisions only for web browsing; per-request deadlines against slow clients; any failure is a deny |
| Edge hygiene | Client-supplied `Dwarpal-*` headers stripped; strict paths and HTTP heads (no smuggling, no method override); host names canonicalised, internal addresses never reached; DLP with validated detectors, values never logged |
| Pipeline | Local pre-commit hook; CI secret scan, 531 tests incl. abuse cases and property tests, coverage gate, SpotBugs/FindSecBugs, CodeQL, dependency review, SBOM; actions pinned to SHAs; JDK 25 enforced; reproducible builds |
