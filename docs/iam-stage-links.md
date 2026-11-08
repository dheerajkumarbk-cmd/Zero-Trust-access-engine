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

- [ ] **S3 -> S6 hook (joiner):** the joiner flow calls one clear hook that creates the new person's switched-off backup
      credential. Until Stage 6 the hook does nothing and says so.
      Built in Stage 3: `CredentialLifecycle.personCreated(personId)`, called by `AccessApi.saveJoiner` after the person
      is saved, and (Step A) after an approved "create an administrator account". `ConsoleMain` passes
      `CredentialLifecycle.NONE`; Stage 6 passes the real one and ticks this box.
- [ ] **S3 -> S6 hook (leaver):** the leaver flow calls one clear hook that deletes that person's backup credential.
      Built in Stage 3: `CredentialLifecycle.personRemoved(personId)`, called by `AccessApi.submitLeaver` after the
      removal committed and the person's sessions were ended. Same swap in Stage 6.
- [ ] **S3 -> S6 first sign-in of a joiner:** until Stage 6 a joiner gets first secrets at the lab's next start
      (`DirectoryPeople.sync` with `DemoPeople.issue`, written to the owner-only people file like the demo people). Stage 6
      replaces this with the switched-off backup credential and a first-sign-in flow. A new administrator account made by
      the privileged change is in the same position.
- [ ] **S2 -> S6 record type:** vault events use the separate audit record type added in Stage 2 (analysts cannot read it).
      Built in Stage 2: any record whose type starts `VAULT_` goes into the saved console trail (`ConsoleTrail`). Analysts
      get "not found" for it and never see it listed; a lead sees only its `action` and `target` fields (plus the
      record's own actor and time). Stage 6 must put the secret nowhere in the payload, and write `action` and `target`.
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
- [ ] **S6 elevation for the vault and emergency passwords:** an emergency password activation and a vault reveal need an
      elevation (PIN, passkey, reason). The OTHER administrator is only NOTIFIED (no approval, because an emergency cannot
      wait), and so is Cleo.
- [ ] **S6 cross-administrator recovery:** if one administrator is locked out, the other runs the emergency recovery for
      them, with Cleo notified. This replaces the earlier "keep backup codes on paper" workaround.
- [ ] **S5 -> S6 emergency password:** the person's own passkey stays required when an emergency password is used.

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
