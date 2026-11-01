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
| Pipeline | Secret scan, unit + abuse-case tests, coverage gate, SpotBugs/FindSecBugs, CodeQL, dependency review, SBOM |
