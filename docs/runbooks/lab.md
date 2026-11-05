# Runbook: starting and using the lab

Everything here is free: the JDK and Maven the project already needs. Nothing leaves your machine; the lab
listens on the loopback address only.

## Start

```
bin\lab.cmd                  (Windows)
bin/lab.sh                   (macOS, Linux)
```

The first start builds `target/dwarpal-lab.jar` (the profile `lab-jar`: one jar with the one dependency inside)
and makes the lab's certificates under `lab/pki`. Later starts reuse both. Options, all optional:

| Option | Default | Meaning |
|---|---|---|
| `--dir` | `lab` | The lab directory: certificates, secrets, connector files, audit anchor |
| `--seed` | `7` | The simulated organisation; the same seed gives the same people and the same attacks |
| `--users` | `60` | People in the organisation (6 to 10,000) |
| `--speed` | `60` | Simulated seconds per real second (60 = a simulated minute each second; the whole 8-day script takes about 3 hours) |
| `--warmup-days` | `3` | Simulated days run at once at start, so the baselines exist before the first live minute |
| `--port` | `8443` | The SOC API port (`0` picks a free one) |

## What you get today

* The whole SOC running on the simulated organisation, with the SOC API over mutual TLS.
* A scenario clock that streams events through the real collectors.

The browser console, the attack buttons and the guide arrive with the other Layer 6 parts; this runbook is
extended when they land.

## Things to know

* **The lab starts again from day zero each time.** Its certificates, secrets and seed are kept; the simulated
  organisation, its alerts and cases are not. Persisting them would need every SOC component to rebuild itself from
  the audit trail, which is scheduled after the submission. To keep a run, use the replay export (part J).
* **Certificates are valid for 30 days and are renewed after 20.** Delete `lab/pki` to start over.
* **Secrets:** `lab/pki/pki.pass` and the `.p12` files are readable by your account only. Do not copy them.
* Stop with Ctrl+C.

## Difference from a company deployment

A company runs the SIEM, SOAR and the console as separate services with a database, single sign-on, hardware key
storage and monitoring. The lab runs them in one process with in-memory state so one person can run it at home
and study every part.
