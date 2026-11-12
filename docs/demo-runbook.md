# Demo runbook (live SOC demo, about 10 minutes)

Short and plain. Use account names only. Never show or read out a password or PIN: they are in
`lab\console\people.txt`, which stays closed on screen. The identity-and-access story has its own script in
[demo-walkthrough.md](demo-walkthrough.md); this file is the SOC story (stories A1 and A6) plus the safety net.

## 1. Pre-flight checklist (off stage, 10 minutes before)

- [ ] **PostgreSQL is running.** The Windows service is `postgresql-x64-18`.
      Check: `Get-Service postgresql-x64-18` (Status must say Running).
- [ ] **`db\local.properties` exists.** It is created from `db\local.properties.example` and is never committed.
      Do not open it on screen.
- [ ] **The jar exists.** `target\dwarpal-lab.jar` (built by `bin\lab.cmd`, profile `lab-jar`).
- [ ] **Start the lab** from the repo folder (the same command every time):
      `java -jar target\dwarpal-lab.jar --dir lab --port 8443`
      Or `bin\lab.cmd`, which builds the jar if missing and then runs the same thing. Defaults are `--dir lab`,
      `--port 8443`, `--db on`, `--passkey device`, `--trail on` (see `docs/runbooks/lab.md`). Wait for the line
      `Console: https://localhost:8443/`. Stop with Ctrl+C.
- [ ] **Trust the lab's certificate authority once.** The lab makes its own CA. Import `lab\pki\ca.pem` as a trusted
      authority for your Windows user (Trusted Root Certification Authorities), then restart the browser.
      Without it the browser shows a warning: click Advanced, then Continue to localhost. Remove the CA after the demo.
- [ ] **Windows Hello is registered** on the **Profile** page for dana, spector, cleo, ana and ben (Profile, Passkey,
      "Register your device passkey"). Hana and Uma have no passkey and need none.
- [ ] **One private browser window per account**, so the sessions do not mix. Press F5 in every window after a restart.
- [ ] Passwords on paper, not on screen. If the 7-day rotation has passed, only Profile opens until both are changed.

## 2. The 10-minute script (stories A1 and A6)

Stages follow the slides: Launch, Inject, Decide, Detect, Triage, Respond, Verify. Pause, speed and fast-forward in the
Scenario lab are for SOC leads, so **cleo** (lead and analyst) drives the clock. Case details, Hunt and Entity ask for the
device passkey once per window. Signing a verdict asks for it every time.

| Step | Min | Account | Page (nav label) | What to do | What it proves |
|---|---|---|---|---|---|
| 1 Launch | 0:00 | ana | Scenario lab (More) | Say what the lab is: a simulated company of 60 people with real collectors, engine and SOC. Open card "A1 Credential stuffing from abroad" and read "What the attacker does". | The lab is a real pipeline fed by a script, not a slide. |
| 2 Inject | 0:45 | ana | Scenario lab | Press **Launch A1**. | A leaked password is tried from Russia on an unknown computer. Events enter through the real collectors. |
| 3 Decide | 1:15 | ana | Scenario lab, "What the lab has produced so far" | Read the table: Engine decision **DENY**, the policy, the chance of attack, the signals. | The access engine refused the login on the spot and shows its numbers. |
| 4 Detect | 2:15 | ana | Alert queue (SOC) | Filter by the person. Show that nothing urgent is there. | A blocked login is not an incident. The engine blocks, the SOC hunts what got through. |
| 5 Verify (A1) | 3:00 | ana | Audit explorer (SOC) | Unlock with Windows Hello. Find the DENY record and open it: new address, new country, unknown computer. | Every decision is recorded with the reason, so anyone can check it by hand. |
| 6 Launch | 4:00 | ana | Scenario lab | Open card "A6 Stolen laptop used from the owner's network". Press **Launch A6**. | The hard case: the thief has the owner's laptop and key, and the login looks right. |
| 7 Inject | 4:30 | cleo | Scenario lab, Controls | Choose 30 min in the list and press **Fast-forward**. | The laptop's signed sensor events arrive (encoded PowerShell, USB drive, finance files read). |
| 8 Decide | 5:00 | cleo | Scenario lab, results | Show Engine decision **ALLOW**. | The engine's known blind spot, said openly. Only the device's own telemetry shows the theft. |
| 9 Detect | 5:30 | ana | Alert queue | Find P1 `stolen-laptop-collection` and P2 `encoded-powershell`. Show "the SOC may act on this". | The alert rests on signed sensor evidence, so it may trigger an action. |
| 10 Triage | 6:15 | ana | Cases, then the case | Unlock with Windows Hello. Read "Why this rank". Follow the timeline: PowerShell, USB, finance files. Open one evidence link. | Every claim links to an audit record. Then open **ATT&CK** (SOC) and show the three techniques lit. |
| 11 Respond | 7:30 | ana | Case, "Decide:" | Press **True positive**, then **Sign and submit** (Windows Hello). If the person is privileged, a second analyst (ben) signs the same verdict. | A verdict is signed by a named analyst's key. The playbook isolates the laptop and watches the person. |
| 12 Respond | 8:30 | ana | Response (SOC) | Show the isolation as pending, then acknowledged by the sensor. | Isolation counts only when the device confirms it with its own signature. |
| 13 Verify | 9:00 | cleo | Audit explorer, then Scans | Press **Verify the whole chain** (expect "The chain is intact"). Then run the scans on **Scans**. | Nothing was changed or removed. Every step above is in the chain. |
| 14 Close | 9:40 | any | slide or terminal | Show the numbers sheet below. | Evidence: tests, coverage, static analysis. |

Do not sign the same verdict twice on purpose unless asked: the second sign is refused (a verdict is single use), which is
the correct answer to give if a question comes.

## 3. Fallback if the lab dies

1. Check the lab window. If it is gone, start it again with the same command:
   `java -jar target\dwarpal-lab.jar --dir lab --port 8443`
   Wait for `Console: https://localhost:8443/`, then press F5 in every browser window.
2. A second lab on the same `--dir` refuses to start while the first still runs. If the port is busy, wait or use the
   port `--port 8444` and open that address (the CA is the same, so no new warning).
3. **Kept across a restart:** certificates, secrets, seed, the directory database (people, roles, grants, approvals),
   the console audit trail on disk, and installed policy and playbook bundles.
   **Starts again from day zero:** the simulated organisation, its alerts, cases, risk and launched scenarios.
   So after a restart, launch A1 and A6 again from the Scenario lab. The warm-up replays three simulated days at start.
4. If the database is down, start the service (`Start-Service postgresql-x64-18`, or the Services app) and start the lab
   again. `--db off` is a last resort: the people come from the people file and the directory features (Access, Administration) are not backed by the database.
5. **Crash log:** `lab\logs\crash-<time>-<pid>.log` (the `logs` folder inside the `--dir` folder). It is written on any
   uncaught error and at every normal JVM shutdown (Ctrl+C, window closed), with a thread dump and heap and thread counts.
   A hard kill from outside (Task Manager "End task", a parent process killing its tree) runs no Java code, so then
   no file appears: that absence itself says the lab was killed from outside.

**Measured restart time** (12 Nov 2026, this machine, the current lab jar, `--db off`, `--trail on`, other jobs running):

| Start | Time to HTTPS 200 (`curl -sk`) |
|---|---|
| First start on a fresh folder (makes the CA and certificates) | 18.7 s |
| Second start on the same folder, after the first had stopped | 7.4 s |

The real demo uses the database, so this is an approximation: the database adds a connection and the checks of the
people tables, a little on top. The second figure is the one that matters for a restart on stage: about 10 seconds, plus
the time to log in again. Say "about 10 to 20 seconds" if asked. Re-measure with the database on before the demo if time allows.

## 4. Numbers sheet

Counts below were taken on 2026-11-12 at 20:15 IST on branch `dbms-iga` (Part A files included, not yet committed).
Run each command from the repo folder. Gate numbers must come from a fresh gate run (`target` from that run).

| Number | Value | Command |
|---|---|---|
| Main Java files (= top-level classes, interfaces, enums, records) | 364 | `find src/main/java -name '*.java' \| wc -l` (and `grep -rhE '^(public \|final \|abstract \|sealed )*(class\|interface\|enum\|record) ' src/main/java \| wc -l`, also 364) |
| Test classes (`*Test.java`) | 189 | `find src/test/java -name '*Test.java' \| wc -l` (216 files in all, with helpers) |
| Lines of main Java | 52,693 | `find src/main/java -name '*.java' -print0 \| xargs -0 cat \| wc -l` |
| Lines of test Java | 40,248 | `find src/test/java -name '*.java' -print0 \| xargs -0 cat \| wc -l` |
| Console JavaScript files | 40 | `find src/main/resources/console -name '*.js' \| wc -l` |
| Commits on this branch | 101 | `git rev-list --count HEAD` |
| Total tests / failures / skipped | with database 1,555 / 0 / 0; without database 1,555 / 0 / 85 (2026-11-12) | The `Tests run:` summary line of `mvn -o verify spotbugs:check`, or PowerShell: `foreach($f in Get-ChildItem target\surefire-reports\TEST-*.xml){$s=([xml](Get-Content $f)).testsuite;$t+=[int]$s.tests;$x+=[int]$s.failures+[int]$s.errors;$k+=[int]$s.skipped};"$t tests, $x failed, $k skipped"` |
| Line and branch coverage, with database | 95.6% lines, 86.8% branches | `awk -F, 'NR>1{lm+=$8;lc+=$9;bm+=$6;bc+=$7}END{printf "lines %.1f%% branches %.1f%%\n",100*lc/(lm+lc),100*bc/(bm+bc)}' target/site/jacoco/jacoco.csv` after a gate run with the database up |
| Line and branch coverage, without database | 91.2% lines, 83.9% branches | Same command after a gate run with the database stopped (about 83 tests skip) |
| SpotBugs + FindSecBugs findings | 0 (both gates) | `grep -c '<BugInstance' target/spotbugsXml.xml` (0 is the target) |

Gates of 2026-11-12 (Part A included): `mvn -o verify spotbugs:check` with the database, then again with no database configured (`DWARPAL_DB_CONFIG` pointing to a missing file, `DWARPAL_DB*` unset), `target/jacoco.exec` deleted before each. Both BUILD SUCCESS. Gate minimum 80%.
