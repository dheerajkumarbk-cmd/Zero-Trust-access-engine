# Build report: the `iga` database (identity, access governance and audit)

Written 12 Nov 2026. Plain language on purpose. Everything below was run on PostgreSQL 18, database `dwarpal_dbms`, schema `iga`. Spec: `DBMS_BUILD_PROPOSAL.md`.

## 1. Where things stand

All five phases are built and committed. The last full test run, on a database rebuilt from the committed scripts only, is **pass=19 fail=0 skip=0** (file `docs/dbms/test-results-final.txt`).

| Commit | What it holds |
|---|---|
| `c8e6646` | Phase 0: existing-schema report, setup script, `run.sh`, README |
| `731f898` | Phase 1: tables, keys, checks, ER diagram (Mermaid text) |
| `07ba4b9` | Phase 2: procedures, triggers, audit hash chain, first tests |
| `ebbbbbe` | Phase 3: seed, views, indexes, EXPLAIN captures, demo queries, transaction demos. It also carries the roles and row-level-security files, which were ready and tested |
| `ef7b482` | Phase 4: backup, restore, dropped-table recovery |
| `0ecb6b1` | Phase 5: segregation-of-duties trigger, `access_request`, `privileged_session` |

To rebuild from nothing: `db/iga/run.sh --build` (about 60 seconds, mostly the 500,000-event seed), then `db/iga/run.sh --test`.

## 2. What was built, why, and the evidence

### Phase 0 and 1: tables
**Built:** 16 tables: department, person, system, account, role, entitlement, role_entitlement, role_assignment, sod_rule, dept_birthright_role, lifecycle_event, security_event, audit_log, review_campaign, review_item, plus (phase 5) access_request and privileged_session. Keys, foreign keys, CHECK and UNIQUE constraints, and a partial unique index so an account holds a live role only once.
**Why:** a grant is its own table (`role_assignment`) because it has its own facts (who granted it, from when, until when, revoked when).
**Evidence:** tests 1, 2, 15 pass. ER diagram is `docs/dbms/iga_er.md`.

### Phase 2: procedures, triggers, audit chain
**Built:** `joiner`, `mover`, `leaver` procedures (each one transaction, all or nothing). Triggers: no grant to a terminated person, a leaver disables accounts, `audit_log` cannot be updated, deleted or truncated. Each audited table change writes one audit row whose hash covers the previous row's hash, so the rows form a chain. `verify_audit_chain()` returns the first bad row number, or NULL if the chain is intact.
**Evidence:** tests 3, 7, 8, 9, 10, 13, 16, 17, 18 pass. Test 10 changes one audit row and the verifier finds it.

### Phase 3: seed, views, indexes, queries
**Seed** (`08_seed.sql`, fixed values, no randomness that changes between runs): 8 departments, 200 people, 6 systems, 30 roles, 120 entitlements, 520 accounts, 900 role assignments, 6 SoD rules, **500,000 security events** (May to Oct 2026). Whole rebuild including the seed: about 56 to 67 seconds.
**Planted faults, counted by views and asserted by test 19:** 6 orphan accounts, 4 leavers with live access, 3 segregation violations, 12 dormant accounts, 3 service accounts whose owner left (plus 2 overdue privileged grants). All exact.
**Views:** the 7 views of spec section 8 and the materialised view `mv_access_summary`.
**Partitions:** `security_event` is split by month (May to Dec 2026) plus a DEFAULT partition. Test 11 shows a one-month query reads one partition only (`docs/dbms/explain-pruning.txt`: July query, only `security_event_2026_07` in the plan, 1271 buffers, about 23 ms).
**Indexes** (`06_indexes.sql`, the six of spec section 7). Plans before and after, each run twice (first, second), in `docs/dbms/explain-before.txt` and `explain-after.txt`. The machine was busy, so timings are noisy; the plan shape is what matters.

| Query | Before | After | Plan change |
|---|---|---|---|
| Last 50 events of one account | 120 ms, 70 ms | 0.53 ms, 0.13 ms | parallel seq scan of 6 partitions plus sort, to index scans, no sort |
| One-day time range | 8.9 ms, 3.5 ms | 1.5 ms, 1.1 ms | index-only scan on the primary key, to BRIN bitmap scan |
| JSONB search (`details @>`) | 96 ms, 135 ms | 0.97 ms, 0.58 ms | seq scan, to GIN bitmap scans |
| Live grants of an account | 0.18 ms, 0.03 ms | 0.06 ms, 0.02 ms | already an index scan: the older partial unique index `uq_assignment_live` covers it. The new index is the spec's, and is partly redundant |
| Dormant accounts | 0.06 ms, 0.04 ms | 0.05 ms, 0.02 ms | seq scan to partial index, but the table has only 520 rows, so no real gain |
| Email lookup (`lower(email)`) | 0.09 ms, 0.07 ms | 0.05 ms, 0.02 ms | seq scan to expression index (200 rows, tiny gain) |

Index sizes on `security_event`: BRIN 192 kB in total, B-tree 36 MB (primary key plus the composite), GIN 28 MB, table data about 59 MB. The last three rows are honest: on small tables an index cannot help much.
**Showcase queries** (`09_demo_queries.sql`, output `demo-queries-output.txt`): recursive management chain (6 levels for person 150), window `rank()` of failed logins per day, and `GROUP BY ... HAVING` giving exactly **8** brute-force candidates (15 failures in one 5-minute window each).
**Transaction demos** (`db/iga/demos`, outputs `demo-*.txt`): atomicity (`joiner` with a bad role leaves nothing), isolation (READ COMMITTED lets a 4th holder in; SERIALIZABLE gives `40001`), deadlock (`40P01`, one session aborted), durability (WAL position advances and is flushed at COMMIT). All four were run again on 12 Nov at 20:04 and gave the same key results (`40001`, `40P01`, `P0002`); the saved files are from the first real runs, not edited.

### Phase 4: roles, row-level security, backup
**Roles** (`07_roles.sql`): `iga_app` (runs the three procedures only, no table access), `iga_reviewer` (reads views; can update only `decision` and `decided_at` on its own review items, enforced by a row-level-security policy), `iga_auditor` (read everything including `audit_log`), `iga_admin` (schema changes; cannot update or delete audit rows). RLS is forced on `review_item`.
**Evidence:** test 12 passes (a reviewer sees only their own items). `roles-demo-output.txt`: 36 checks, all pass, including `iga_app` getting `42501 permission denied` on `DELETE FROM iga.audit_log`.
**Backup and restore** (`demos/backup_restore.sh`, output `backup-restore-output.txt`): `pg_dump -Fc` of schema `iga` (11.6 MB, kept outside the repository, 345 entries); restored with `pg_restore` into the separate database `dwarpal_dbms_restore`. All 17 table row counts match (500,000 events, 1,898 audit rows). `verify_audit_chain()` on the restored copy returned NULL (chain intact). Then `DROP TABLE iga.lifecycle_event` was run there, the table was recovered alone from the dump (10 dump entries: table, data, key, checks, foreign keys), 15 rows came back, all counts matched again, chain still intact. Note: `pg_dump` needed `--enable-row-security` because RLS is forced on `review_item`.

### Phase 5: stretch tables
`trg_sod_check` (a grant is refused if the account already holds a live role that a `sod_rule` pairs with it; a per-account advisory lock stops two sessions passing the check together). `access_request` (a CHECK forbids deciding your own request). `privileged_session` (an EXCLUDE constraint with `tstzrange` forbids two overlapping open sessions for one account; needs the `btree_gist` extension, already installed). `leaver` now ends open privileged sessions. Tests 4, 5, 6 pass.

## 3. Final test output (`10_tests.sql`, run on a freshly rebuilt database)

```
PASS 1  to  PASS 19   (19 lines, all PASS; see docs/dbms/test-results-final.txt)
SUMMARY pass=19 fail=0 skip=0
```
The test script runs in one transaction that is rolled back, so the database is unchanged afterwards.

## 4. What is left, unverified, or different from the plan

- **Durability restart step:** the full demo needs the PostgreSQL service restarted. The scripts never do that. The owner runs `durability.sh step1`, restarts the service as administrator, then `step3` (must show the marker row), then `cleanup`. See `db/iga/demos/README.md`.
- **Second proposal file** `dbms-project-proposal.md` was not found (searched C:\Users\Admin to depth 5 and D:), so no differences between the two proposals could be listed.
- **No PNG of the ER diagram:** only Mermaid text; no renderer is installed. Paste `iga_er.md` into any Mermaid viewer.
- **No live link to Dwarpal's `directory_person`:** the optional import was not built. The `iga` data is self-contained.
- **Point-in-time recovery** is explained below, not performed (the server has `archive_mode = off`, which PITR needs).
- **Planted SoD violations bypass the trigger on purpose:** the seed adds the 3 violating grants before the 6 rules exist, so `v_sod_violations` has something to show. The trigger blocks new violations only.
- `access_request` and `privileged_session` have no audit trigger and no procedures yet; they are tables with constraints.
- Phase 3 commit also contains the phase 4 roles files (they were tested together); phase 4 commit adds the backup parts.
- Timings are from a busy machine; do not quote single numbers as benchmarks.
- Demo outputs for atomicity, isolation, deadlock, durability were captured on `dwarpal_dbms_restore`, not on `dwarpal_dbms`.

## 5. Study notes: the 12 questions of spec section 15

1. **Why is `role_assignment` its own table?** One account can hold many roles and one role is held by many accounts (many-to-many). The grant also has its own facts: granted_by, valid_from, valid_to, revoked_at. A column on `account` could hold only one role and has nowhere for those facts.
2. **A dependency that broke 3NF in the flat table.** In the flat "one row per person, account, role" sheet, `person -> dept_id -> department name` is a chain: the department name depends on the person only through the department (a transitive dependency), so it repeats on every row and can disagree. Fix: separate `department` table, `person` holds only `dept_id`. Same idea for `role_id -> system_id`.
3. **Primary key, unique, foreign key.** Primary key: the one identity of a row (`account_id`), never NULL, never repeats. Unique: another rule that must not repeat, e.g. (system, username) in `account`. Foreign key: a value that must exist in another table, e.g. `account.person_id` must be a real person.
4. **`leaver` fails halfway.** It runs as one transaction. If any step raises an error (revoke grants, disable accounts, end privileged sessions, write the lifecycle row), PostgreSQL rolls back everything done so far; the person stays as before, no half-revoked state. Audit rows written in that transaction roll back too, so the chain has no gap.
5. **ACID in `mover`.** Atomic: old birthright roles removed and new ones added, or nothing. Consistent: constraints and triggers (no grant to a terminated person, SoD) hold at commit. Isolated: another session never sees the half-moved person. Durable: after COMMIT the change is in the write-ahead log on disk and survives a crash.
6. **READ COMMITTED vs SERIALIZABLE.** Demo: the rule "at most 3 holders", checked then inserted by two sessions together. Under READ COMMITTED both saw 2 holders and both inserted: 4 holders, rule broken. Under SERIALIZABLE the second one failed with `40001 could not serialize access`; the application retries; 3 holders.
7. **Partial index on live assignments.** Only the live grants (`revoked_at IS NULL`) are asked about daily; revoked history grows forever. A partial index holds only live rows, so it is smaller and faster to keep up to date. Honest note: here an earlier partial unique index already covers this query, so the plan did not change.
8. **BRIN for time, B-tree for account.** Events are appended in time order, so each block of the table covers a narrow time span; BRIN stores just min and max per block range: 192 kB against tens of MB. Account ids are scattered through the table, so only a B-tree can jump straight to one account's rows (and, with `occurred_at DESC` in the key, return the newest 50 without sorting).
9. **How a changed audit row is detected; what it does not protect against.** Each row's hash covers its own content and the previous row's hash. Change one row and its stored hash no longer matches, or the next row's `prev_hash` no longer matches; `verify_audit_chain()` returns the first bad number (test 10). It does not stop someone with full database rights who recomputes the whole chain after the edit, or deletes the newest rows (no later row points back to them), unless the latest hash is also stored somewhere else (printed, a different system).
10. **Why the trigger enforces SoD, not the application.** Every path to the table passes the trigger: the procedures, a script, a manual SQL session, a second application. Application code covers only itself and can be skipped or buggy. A per-account lock makes it safe under concurrency.
11. **View vs materialised view.** Plain views (`v_orphan_accounts`, `v_leaver_residual_access`, ...) are queries run each time, so always current; the leaver view must always be empty, so it must never be stale. `mv_access_summary` stores counts per department and system: expensive to compute, fine to be a little old, refreshed on demand with `REFRESH MATERIALIZED VIEW`.
12. **Recover to yesterday 3 pm.** PostgreSQL writes every change to the write-ahead log (WAL) first. Needs: a base backup (`pg_basebackup`) taken before that time, plus continuous WAL archiving (`archive_mode = on`, `archive_command`). To recover: restore the base backup, set `restore_command` and `recovery_target_time = 'yesterday 15:00'`, create `recovery.signal`, start the server; it replays WAL up to that time, then you promote it. Here archiving is off, so only the `pg_dump` snapshot is available: this build can return to the dump time, not to 3 pm.

```
 change ----> WAL buffer ---fsync at COMMIT---> WAL files (durable)
                                 |                   |
                          checkpoint writes     archive_command copies
                          dirty pages to        full WAL segments aside
                          data files                  |
 recovery = base backup  +  replay archived WAL  up to the chosen time (PITR)
```
A checkpoint is a point where all earlier changes are already in the data files, so crash recovery starts replay from the last checkpoint instead of from the beginning.
