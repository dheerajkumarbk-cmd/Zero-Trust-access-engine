# Directory, IAM and vault work: links between stages

Tick a box only when the code and its test exist. Build order: Stage 0 setup, 1 directory database, 2 audit trail,
3 joiners and leavers, Step A (second administrator and elevation), 4 monitoring, 5 real passkeys, 6 vault and emergency
passwords, 7 docs and full gate.

**Single-tester setup of a design meant for two people.** One test person operates every account, including both
administrators (dana and spector). The code still treats them as different people: an approval must come from a different
account than the requester, and one account can never approve its own request. See section 14 of the requirements file.

## Done in Step A (second administrator and elevation)

- [x] **Second administrator:** `spector` (Administration, role ADMIN) is a demo person with his own password and PIN in
      the lab's owner-only `people.txt`, and a row in the directory. Test: `DemoPeopleTest`, `DirectoryPeopleTest`.
- [x] **An administrator's own requests go to the other administrator:** the old "request more access" is refused for
      administrators; "Request a privileged change" (create an administrator account, give or take away the administrator
      role, change one's own access) is decided only by a different administrator. Tests: `PrivilegedAccessTest`,
      `PrivilegedChangeTest`.
- [x] **Nobody approves their own request, and an approval comes from a different account:** enforced in the database
      layer, not only on the page. Tests: `PrivilegedAccessTest`, `PrivilegedChangeTest`, `AccessProcessTest`.
- [x] **Elevation (PIN, passkey, reason, 10 real minutes, visible countdown):** guards the decisions of the access process.
      Tests: `ElevationEndToEndTest` (needed, given, expires after 10 real minutes, ended by the person, belongs to one
      session), `AccessSectionTest`.
- [x] **Every elevated action is audited** with the elevation id, who, what, target, before and after, reason and real
      time. Tests: `ElevationEndToEndTest`, `AccessSectionTest`, `PrivilegedChangeTest`.
- [x] **An audit record cannot be edited or deleted** by anyone, administrators included. Test: `AuditImmutableTest`.
- [x] **One passkey step-up function:** `PasskeyStepUp`. The unlock routes and the elevation call it. Test:
      `ElevationEndToEndTest.anotherWayOfProvingThePasskey...`.
- [x] **S1 -> S3 grants:** every grant is one row in the directory database, so a leaver's removal reads the rows and does
      not recalculate from the role. Built in Stage 3; test: `AccessProcessTest`.

## Still to build

- [x] **S3 -> S6 hook (joiner):** the joiner flow calls one clear hook that creates the new person's switched-off backup
      credential. Until Stage 6 the hook does nothing and says so.
      Built in Stage 3: `CredentialLifecycle.personCreated(personId)`, called by `AccessApi.saveJoiner` after the person
      is saved, and (Step A) after an approved "create an administrator account". Built in Stage 6: `ConsoleMain` passes
      the `Vault`, which makes the new person's switched-off emergency password (and at every start for people who have none).
      Evidence: `AccessSectionTest.hrAsksTheAdministratorTicksAndSavesAndEveryGrantIsAudited` (the hook hears the new id),
      `VaultTest.aNewPersonGetsASwitchedOffEmergencyPasswordAndALeaverLosesIt`, and the manual check of the real wiring
      (Stage 7, below): a joiner saved by the administrator shows in the vault, switched off.
- [x] **S3 -> S6 hook (leaver):** the leaver flow calls one clear hook that deletes that person's backup credential.
      Built in Stage 3: `CredentialLifecycle.personRemoved(personId)`, called by `AccessApi.submitLeaver` after the
      removal committed and the person's sessions were ended. Built in Stage 6: the `Vault` deletes their emergency password
      (and an administrator's own entry). Tests: `VaultTest.aNewPersonGetsASwitchedOffEmergencyPasswordAndALeaverLosesIt`,
      `AccessSectionTest.aLeaverIsRemovedAndTheConsoleIsToldToEndTheirSessionsAndShutTheDoor` (the hook hears the id), and the
      manual check of the real wiring (Stage 7, below): after the leaver route the person is gone from the vault.
- [ ] **S3 -> S6 first sign-in of a joiner: NOT BUILT, and not verified as a flow.** It was not part of the stages as asked,
      so it was left as it was: a joiner gets first secrets only at the lab's NEXT START (`DirectoryPeople.sync` with
      `DemoPeople.issue`, written to the owner-only people file like the demo people). Until then the joiner exists in the
      directory and has a switched-off emergency password, but cannot sign in. A new administrator account made by the
      privileged change is in the same position. What is proven is today's behaviour:
      `DirectoryPeopleJoinersTest.anActiveJoinerWithAConsoleRoleIsGivenFirstSecretsOnceAndEnrolled` and
      `firstSecretsAreWrittenToThePeopleFileAndReadBackAtTheNextStart`. A real first-sign-in flow is for the user to decide.
- [x] **S2 -> S6 record type:** vault events use the separate audit record type added in Stage 2 (analysts cannot read it).
      Built in Stage 2: any record whose type starts `VAULT_` goes into the saved console trail (`ConsoleTrail`). Analysts
      get "not found" for it and never see it listed; a lead sees only its `action` and `target` fields (plus the
      record's own actor and time). Built in Stage 6: every vault call writes a `VAULT_` record with `action`, `target`, the
      reason and the elevation id, never a secret. Tests: `ConsoleTrailAuditTest.vaultEventsAreHiddenFromAnalystsAndLimitedForLeads`,
      `VaultEndToEndTest.theLeadSeesWhoWhenAndOnWhomAndNeverTheSecretOrTheReasonAndAnAnalystSeesNothing`, `MonitorEndToEndTest`.
- [x] **S4 monitoring:** each administrator sees the other administrator's actions on the monitoring page; Cleo sees the
      limited vault log (who, when, on whom, never the secret). The records an administrator needs are already written
      by Stage 3 and Step A (`ACCESS_*`, `ELEVATION_*`, with before and after).
      Built in Stage 4: the Monitoring page (`MonitorModule`, id `monitor`): "Administrators" shows the other administrator's
      actions (administrators only), "Vault log" shows who, when, on whom and the kind of action (leads only; an administrator who is
      not a lead gets "not found"). Read only: it has no write route. Test: `MonitorEndToEndTest`. Stage 6 only has to write
      `VAULT_` records with `action` and `target`.
- [x] **S5 -> step-up function:** the lab now uses a real device passkey (WebAuthn: Windows Hello, a phone or a security
      key) by swapping the implementation behind `PasskeyStepUp` (`WebAuthnStepUp`); the callers (the unlock routes and the
      elevation) did not change. Each person, Spector included, registers their own on the Profile page (password and PIN
      first, then the device). The console checks everything with the JDK only: the challenge (fresh, once, per person), the
      origin, the relying party (`localhost`), presence and verification flags, the signature (ES256 or RS256) and the counter.
      The private key never leaves the device; the console keeps only the public key in the owner-only `console/passkeys.txt`.
      `--passkey typed` keeps the old typed passkey for a machine with no device passkey. Tests: `WebAuthnEndToEndTest`
      (software authenticator with real CBOR and signatures), `CborTest`, and a browser run with Edge's virtual authenticator.
- [x] **S5 -> S6 gate:** the administrator's passkey gates the vault and the elevation, never ordinary sign-in
      (the sign-in itself still asks only for password and security-key PIN).
      Evidence: `VaultEndToEndTest.theListNeedsAnElevationAndShowsNoPasswordAndEveryActionNeedsAReason` and
      `ElevationEndToEndTest.aWrongPinOrPasskeyOrNoReasonGivesNoElevationAndTheAnswerDoesNotSayWhich` (the passkey is asked for
      the vault and the elevation); manual check (Stage 7, below): a person who has a passkey signs in again with password and
      PIN only.
- [x] **S6 elevation for the vault and emergency passwords:** an emergency password activation and a vault reveal need an
      elevation (PIN, passkey, reason). The OTHER administrator is only NOTIFIED (no approval, because an emergency cannot
      wait), and so is Cleo.
      Built in Stage 6: the vault (`VaultModule`, hidden: a plain "not found" for everybody but the administrators, in no menu
      or list, Guide or Glossary: test `VaultNotMentionedTest`). Every call needs an open elevation; every call about a person
      also needs a fresh password and PIN, the passkey again and a reason. The emergency password is sealed with AES-256-GCM
      (`VaultStore`, key in its own folder), is switched off until an administrator switches it on, and then opens only the
      recovery page, once; the person sets a new password and PIN and it is replaced. Notices (`NoticeBoard`, the Notices
      button) go to the other administrator and the leads on every vault action, and to the person when it is switched on or used.
      Tests: `VaultEndToEndTest.aRevealIsOnTheTrailWithoutTheSecretAndTheOtherAdministratorAndTheLeadAreTold`,
      `anEmergencyPasswordDoesNothingUntilSwitchedOnThenWorksOnceInTheRecoveryAndIsReplaced`, `NoticeBoardTest`; manual check
      (Stage 7, below): the other administrator and the lead were told, and nobody was asked.
- [x] **S6 cross-administrator recovery:** if one administrator is locked out, the other runs the emergency recovery for
      them, with Cleo notified. This replaces the earlier "keep backup codes on paper" workaround.
      Test: `VaultEndToEndTest.aLockedOutAdministratorGetsBackInThroughTheOtherOneAndTheLeadIsTold`. (The manual check below
      did the same recovery for an analyst; the administrator case is covered by the test only.)
- [x] **S5 -> S6 emergency password:** the person's own passkey stays required when an emergency password is used.
      The recovery changes only the password and PIN and never touches the passkey record. Evidence: the manual check
      (Stage 7, below): after the recovery the person signs in with the new secrets, the audit explorer still asks for their
      passkey, and their old passkey opens it. No automated test asserts this one yet.

## Rules to test (all stages)

- A leaver ends with zero accounts. A sensitive grant is never made without every approval it needs. A rejected request
  creates nothing. Every grant, approval and removal is an audit record. A non-admin gets "not found" for the vault (Stage 6).
- Nobody approves their own request; an approval comes from a different account; the last administrator is never removed.

## Known limits

- HR holds no passkey, so HR's joiner and leaver requests keep the fresh password and PIN, not an elevation.
- Policy, playbook, PAM and lab-reset changes in Administration still ask for the password and PIN (and the passkey)
  on every action; moving them under elevation is a separate decision.

## Database rules (all stages)

- Only the one small data-access layer talks to PostgreSQL. Every query is a PreparedStatement, standard SQL only.
- The lab signs in as `dwarpal_app` (rows only). `dwarpal_migrator` builds tables and runs the tests.
- Passwords come from an environment variable or the untracked `db/local.properties`. Never from source, logs, commits or
  screenshots.
- Tests use `dwarpal_test`, never `dwarpal`.

## Final gate and checks (Stage 7)

### Manual checks I ran (real pages, real wiring, a throwaway lab on a throwaway PostgreSQL cluster built with `docs/setup.md`)

A lab started with `--db on --passkey typed` on a brand-new cluster (own data folder and port, scram-sha-256, localhost only),
after the shipped `db/setup` script, the migrations and the lab jar. A browser script (Edge, headless) drove the pages and the
routes. 22 checks, all passed (no page errors):

* The analyst has no Vault in the menu and gets a plain "not found" (404) for it; the administrator has Vault and Monitoring.
* HR has no SOC pages, vault or monitoring; HR's Administration page offers only "Why was I denied?".
* **Joiner -> vault:** HR raised two joiners, the administrator saved them under an elevation, and both appeared in the vault
  with their emergency password switched off; the vault list showed no password.
* **Leaver -> vault:** HR removed one of them; the page said the account is switched off, sessions ended and every grant removed,
  and the person was gone from the vault list while the other stayed.
* **Emergency password:** switched on by the administrator (shown, not printed); a wrong one opened nothing; the right one opened
  the recovery; the person set new secrets; the same emergency password then failed (single use).
* **Passkey still required:** after the recovery the person signed in with password and PIN only, the audit explorer asked for
  their passkey, and their old passkey opened it.
* **Told, not asked:** the other administrator and the lead each had a notice; no notice held a secret.
* **Monitoring:** the lead's vault log showed who, when and on whom with no reason or secret; the other administrator saw Dana's
  actions; an analyst could not read the monitoring page.
* **Setup from scratch:** `initdb` with scram-sha-256, `listen_addresses = localhost`, the shipped setup script (checks printed:
  localhost, scram-sha-256, all rules scram-sha-256), migrations to version 3 for both databases, the app login can read and
  write rows and gets "permission denied" when it tries to create a table, and the lab started and moved the seven people in.
  One difference from the shipped script: its two interactive `\password` lines need a keyboard, so the run answered them with
  two `ALTER ROLE ... PASSWORD` lines. Every other line ran as shipped.

### Full gate

`mvn -o verify spotbugs:check` (compile with warnings as errors, every test, the coverage gate, SpotBugs with FindSecBugs),
run three times on the same tree with nothing else changed (the lab jar was built between runs 1 and 2; no Java source changed
after the last commit):

| Run | Command | Time | Result |
|---|---|---|---|
| 1 | `verify spotbugs:check` | 09:47 to 10:01 | 1,394 tests, 0 failures, 0 errors, 0 skipped; coverage met; SpotBugs 0 bugs, 0 errors |
| 2 | `verify` | 10:17 to 10:32 | 1,394 tests, 0 failures, 0 errors, 0 skipped; coverage met |
| 3 | `verify spotbugs:check` | 10:32 to 10:48 | 1,394 tests, 0 failures, 0 errors, 0 skipped; coverage met; SpotBugs 0 bugs, 0 errors |

* The same 1,394 tests passed every time, so no flaky test showed up in three runs. That includes the console end-to-end
  tests that timed out once under load earlier (they ran here while four idle throwaway labs were also running).
* Nothing was skipped: the database tests ran against `dwarpal_test` and Node.js was present for `ConsoleScriptsParseTest`.
* Coverage (JaCoCo, run 3): lines 95.7 percent, branches 86.7 percent, instructions 96.4 percent; the gate is 80 percent.

### Secret scan

A script searched for the real secret values on this machine (the database passwords from `db/local.properties` and every
password and PIN in every `people.txt` found under the lab folders, 378 values in all) in every tracked or untracked file of
the working tree and in every line of every commit on every branch (`git log --all -p`). It printed counts only, never a value.

| Check | Result |
|---|---|
| Working tree files containing a real secret | 0 |
| History lines containing a real secret | 0 |
| History lines with a private-key or access-token pattern (the pre-commit hook's patterns) | 0 |
| Forbidden file names in any commit (`.pem`, `.key`, `.p12`, `.env`, `people.txt`, `credentials.txt`, `passkeys.txt`, `local.properties`, `vault.dat`, `vault-key/`, `target/`, `.jar`) | 0 |
| Password-looking string literals in main code, docs, `db`, `bin` | 0 |

Test sources do contain fixed test-only passwords and passkeys for the throwaway test fixtures; they are not the lab's secrets.

### Items I could not verify

* The first sign-in of a joiner (above): not built, so there is nothing to verify beyond today's behaviour.
* Windows Hello on the real device: not exercised by me. The software authenticator (tests) and Edge's virtual authenticator
  (browser) were.
* The cross-administrator recovery was proven by `VaultEndToEndTest`, not by hand in a browser.
* The "passkey stays required after an emergency password" link has a manual check but no automated test.
