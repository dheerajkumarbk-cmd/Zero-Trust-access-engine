# Directory, IAM and vault work: links between stages

Tick a box only when the code and its test exist. Build order: Stage 0 setup, 1 directory database, 2 audit trail,
3 joiners and leavers, 4 monitoring, 5 real passkeys, 6 vault and emergency passwords, 7 docs and full gate.

- [ ] **S3 -> S6 hook (joiner):** the joiner flow calls one clear hook that creates the new person's switched-off backup
      credential. Until Stage 6 the hook does nothing and says so.
- [ ] **S3 -> S6 hook (leaver):** the leaver flow calls one clear hook that deletes that person's backup credential.
- [ ] **S2 -> S6 record type:** vault events use the separate audit record type added in Stage 2 (analysts cannot read it).
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
