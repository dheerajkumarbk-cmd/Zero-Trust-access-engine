# Directory, IAM and vault work: links between stages

Tick a box only when the code and its test exist. Build order: Stage 0 setup, 1 directory database, 2 audit trail,
3 joiners and leavers, 4 monitoring, 5 real passkeys, 6 vault and emergency passwords, 7 docs and full gate.

- [ ] **S3 -> S6 hook (joiner):** the joiner flow calls one clear hook that creates the new person's switched-off backup
      credential. Until Stage 6 the hook does nothing and says so.
      Built in Stage 3: `CredentialLifecycle.personCreated(personId)`, called by `AccessApi.saveJoiner` after the person
      is saved. `ConsoleMain` passes `CredentialLifecycle.NONE`; Stage 6 passes the real one and ticks this box.
- [ ] **S3 -> S6 hook (leaver):** the leaver flow calls one clear hook that deletes that person's backup credential.
      Built in Stage 3: `CredentialLifecycle.personRemoved(personId)`, called by `AccessApi.submitLeaver` after the
      removal committed and the person's sessions were ended. Same swap in Stage 6.
- [ ] **S3 -> S6 first sign-in of a joiner:** until Stage 6 a joiner gets first secrets at the lab's next start
      (`DirectoryPeople.sync` with `DemoPeople.issue`, written to the owner-only people file like the demo people). Stage 6
      replaces this with the switched-off backup credential and a first-sign-in flow.
- [ ] **S2 -> S6 record type:** vault events use the separate audit record type added in Stage 2 (analysts cannot read it).
      Built in Stage 2: any record whose type starts `VAULT_` goes into the saved console trail (`ConsoleTrail`). Analysts
      get "not found" for it and never see it listed; a lead sees only its `action` and `target` fields (plus the
      record's own actor and time). Stage 6 must put the secret nowhere in the payload, and write `action` and `target`.
- [ ] **S5 -> S6 gate:** the admin's passkey gates the vault only, never ordinary sign-in.
- [ ] **S6 reminder to the user:** the admin's own sign-in cannot be recovered from the vault. Keep Dana's backup codes
      on paper, offline.
- [ ] **S1 -> S3 grants:** every grant is one row in the directory database, so a leaver's removal reads the rows and does
      not recalculate from the role.
- [ ] **S5 -> S6 emergency password:** the person's own passkey stays required when an emergency password is used.

## Database rules (all stages)

- Only the one small data-access layer talks to PostgreSQL. Every query is a PreparedStatement, standard SQL only.
- The lab signs in as `dwarpal_app` (rows only). `dwarpal_migrator` builds tables and runs the tests.
- Passwords come from an environment variable or the untracked `db/local.properties`. Never from source, logs, commits or
  screenshots.
- Tests use `dwarpal_test`, never `dwarpal`.
