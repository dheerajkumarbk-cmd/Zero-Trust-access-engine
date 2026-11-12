# Transaction demonstrations (spec section 4)

All demos create their own fixture rows (names start with `DEMO`), clean up after themselves and can be re-run.
Pass the database name as the argument (or `DB=...`); the default is `dwarpal_dbms`. They use `db/iga/run.sh`
(no password on the command line), so build `01..04` first. Audit rows are append-only by design and stay.

| Demo | Run | What it proves | Expected result |
|---|---|---|---|
| Atomicity | `db/iga/run.sh --db dwarpal_dbms db/iga/demos/atomicity.sql -v ON_ERROR_STOP=0` | `joiner` is all-or-nothing; ROLLBACK and SAVEPOINT undo whole steps | `ERROR P0002 role no_such_role does not exist`; all leftover counts 0; after the SAVEPOINT example only DEMO-ATOM-2 exists |
| Isolation | `db/iga/demos/isolation.sh [DB]` | Check-then-insert (max 3 holders) is unsafe under READ COMMITTED, safe under SERIALIZABLE | READ COMMITTED: 4 holders (rule broken). SERIALIZABLE: second session gets `40001 could not serialize access`, 3 holders |
| Deadlock | `db/iga/demos/deadlock.sh [DB]` | Opposite lock order deadlocks; PostgreSQL detects it and aborts one session | `deadlock_timeout` 1s; one session gets `40P01 deadlock detected` and rolls back; the other commits its `mover`. Which one is aborted can vary |
| Durability | `db/iga/demos/durability.sh safe [DB]` (safe part only) | Commit advances and flushes the WAL (LSN) | fsync/synchronous_commit on; LSN advances by a few hundred bytes or more (other sessions share the WAL); flushed LSN equals current LSN after COMMIT |

Durability full demo (owner, by hand): `durability.sh step1`; restart the PostgreSQL service as administrator
(`net stop postgresql-x64-18`, `net start postgresql-x64-18`, never run by the scripts); `durability.sh step3`
must show the marker row; `durability.sh cleanup`.

Captured outputs are in `docs/dbms/demo-*.txt`.
