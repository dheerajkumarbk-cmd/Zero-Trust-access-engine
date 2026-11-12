# Setup guide: the directory database and the lab

This guide takes a clean Windows machine to a running lab at `https://localhost:8443`. Everything is free. Nothing in it
asks you to write a real password, PIN, key or backup code into a file that is tracked by git, a log or a screenshot.

Lab project: this is a college project built to study how a zero-trust decision point, a SOC and an identity-and-access
process fit together. It has not been audited and is not production-ready (see [iam-architecture.md](iam-architecture.md),
"Known limitations").

## 1. What you need

| Need | Version used | Notes |
|---|---|---|
| JDK | 25 (Eclipse Temurin 25.0.5) | The build refuses an older JDK with a clear message. |
| Maven | 3.9 or newer | Builds and tests. Works offline once the dependencies are in the local repository. |
| PostgreSQL | 18.6 (14 or newer should work; 18 is what was tested) | The directory database. Free, from postgresql.org. |
| A browser | Edge or Chrome | For the console. A device passkey needs Windows Hello, a phone or a security key. |
| Node.js | optional | Only the test `ConsoleScriptsParseTest` uses it (it parses every console script). Without Node the test is skipped and says so. |

The PostgreSQL JDBC driver is a Maven dependency and needs no separate install; see [dependencies.md](dependencies.md).

## 2. Install PostgreSQL and set it up for this machine only

1. Install PostgreSQL from the official installer. Keep the port `5432`. The installer asks you to choose a password
   for the database superuser `postgres`: choose one and keep it somewhere private. It is used once, in step 3, and the
   lab never uses it.
2. Make the server listen on this computer only, and store passwords as `scram-sha-256`. In the data folder
   (for example `D:\Program Files\PostgreSQL\18\data`):
   * `postgresql.conf`: `listen_addresses = 'localhost'` and `password_encryption = 'scram-sha-256'`.
   * `pg_hba.conf`: the `host` lines for `127.0.0.1/32` and `::1/128` use `scram-sha-256` (not `trust`, not `md5`).
3. Restart the PostgreSQL service so the changes apply.

The lab refuses to talk to a database that is not on `localhost`, `127.0.0.1` or `[::1]`, and the database address takes
no options, so these two settings and the lab agree.

## 3. Create the two roles and the two databases (once)

Run the setup script as the PostgreSQL administrator, from `psql`:

```
"<PostgreSQL folder>\bin\psql.exe" -U postgres -h localhost
\i 'C:/path/to/l5-try/db/setup/00-create-roles-and-databases.sql'
```

The script asks you to type two NEW passwords, one after the other, each twice to confirm (nothing is echoed and nothing is
saved by the script). Choose two different passwords and keep them in a password manager or on paper.

It creates:

| Name | What it is |
|---|---|
| `dwarpal_migrator` | Owns the two databases and their tables. Used to build or change the tables, and by the tests. Not a superuser. |
| `dwarpal_app` | What the running lab signs in as. Can read and write rows. Cannot create, change or drop tables. Not a superuser. |
| `dwarpal` | The lab's real data (people, roles, access items, requests, grants, approvals). |
| `dwarpal_test` | Test data only. The tests wipe it on every run. |

At the end the script prints a few checks (`listen_addresses`, `password_encryption`, `pg_hba.conf` rules) that are safe to
show. Check that they match step 2.

## 4. Tell the lab the two passwords (never in git)

Either copy the example file and type the two passwords after the `=` signs:

```
copy db\local.properties.example db\local.properties
```

`db/local.properties` is listed in `.gitignore` and is never committed. Or set environment variables, which win over the
file:

| Variable | Meaning |
|---|---|
| `DWARPAL_DB_APP_PASSWORD` | the password of `dwarpal_app` |
| `DWARPAL_DB_MIGRATOR_PASSWORD` | the password of `dwarpal_migrator` |
| `DWARPAL_DB_URL` (optional) | the lab database address, default `jdbc:postgresql://localhost:5432/dwarpal` |
| `DWARPAL_DB_TEST_URL` (optional) | the test database address, default `jdbc:postgresql://localhost:5432/dwarpal_test` |
| `DWARPAL_DB_CONFIG` (optional) | another path for the properties file |

A password is never printed: every class that holds one prints "redacted". If a password is missing, the lab says which
setting is empty and where to fill it in.

## 5. Build the lab and create the tables

```
mvn -q -Plab-jar -DskipTests -Djacoco.skip=true package
java -cp target\dwarpal-lab.jar dev.dwarpal.directory.MigrateMain
java -cp target\dwarpal-lab.jar dev.dwarpal.directory.MigrateMain --test
```

The first command builds one runnable jar (`target/dwarpal-lab.jar`) that contains the JDBC driver. The second builds the
tables of the lab database as `dwarpal_migrator`; the third does the same for the test database. A table change is a numbered
script under `src/main/resources/db/migrations` (three exist today); running the migration again does nothing. The lab
itself signs in as `dwarpal_app` and checks that the tables are at the version it expects.

## 6. Start the lab

```
bin\lab.cmd
```

(`bin/lab.sh` on macOS or Linux.) The lab builds the jar if it is missing, makes its certificates under `lab/pki` on the first
start, moves the demo people into the directory database, and prints the address and where the first secrets are.
It stays up until you press Ctrl+C. Loopback only: nothing is reachable from another computer.

Options (all optional; the full list is in [runbooks/lab.md](runbooks/lab.md)):

| Option | Default | Meaning |
|---|---|---|
| `--dir` | `lab` | The lab folder. Never point two running labs at the same folder; the second refuses to start. |
| `--port` | `8443` | The console's port. |
| `--db` | `on` | `on` uses the directory database; `test` uses `dwarpal_test` (throwaway labs and tests); `off` runs without a database, with the people file only. |
| `--passkey` | `device` | `device` uses real WebAuthn device passkeys; `typed` keeps the old typed passkey, as a fallback for a machine with no device passkey. |
| `--trail` | `on` | `on` saves the console's audit trail to disk and refuses to start on a trail that was changed; `off` keeps it in memory (throwaway labs only). |

## 7. Trust the lab's certificate once, then sign in

* Import `lab\pki\ca.pem` as a trusted certificate authority for your own Windows user, so the browser opens
  `https://localhost:8443` without a warning. Do this only for the lab and remove it when you delete the lab.
* **First credentials:** each person's first password and security-key PIN are made by the lab, kept in
  `lab\console\people.txt` (a file only your Windows account can read), and shown in the launcher's window at each start for
  everyone who has not yet chosen their own. Read them there or in that file. They are not copied into any document, and
  the file's copy is replaced by a marker once the person has chosen their own. Do not paste them into chats, commits or
  screenshots.
* Sign in with user, password and PIN. A password and a PIN last 7 days (`--rotate-days`); after that only the Profile page
  opens until both are changed.
* **Passkeys:** analysts, leads and administrators register their own device passkey on the **Profile** page (password and PIN
  first, then Windows Hello, a phone or a security key). Each person does their own, Spector included. HR and ordinary users
  have none and need none.

## 8. Files the lab keeps under its folder

| File or folder | What it holds |
|---|---|
| `pki/` | The lab's certificate authority and certificates. Owner-only. |
| `console/people.txt` | First passwords and PINs of the demo people and of approved joiners, until changed. Owner-only. |
| `console/credentials.txt` | Salted one-way hashes of passwords, PINs and typed passkeys. |
| `console/passkeys.txt` | The PUBLIC key of each device passkey. The private key never leaves the device. |
| `console/trail/` | The saved audit trail, with keys of its own, checked at every start. |
| `console/notices.txt` | Short notices ("an emergency password was switched on for you"). They never hold a secret. |
| `console/vault/` | The vault's data, sealed with AES-256-GCM. |
| `console/vault-key/` | The key that opens the vault. **Keep it apart from `console/vault/` and never delete it:** a vault that has data but no key will not open and the lab refuses to start on it. |

Back up `console/vault-key/` to somewhere other than the folder that holds `console/vault/`. None of these files belongs in git.

## 9. Run the tests

```
mvn -o verify spotbugs:check
```

This compiles with warnings as errors, runs every test (about 1,400, about 13 minutes), checks that coverage is at least
80 percent, and runs SpotBugs with FindSecBugs, which must report zero findings.

* The tests that need PostgreSQL use `dwarpal_test` and wipe it. They are **skipped** (not failed) when the database
  passwords are not configured, so a run on a machine without the database proves less. Look at the "skipped" count in the
  summary.
* Add `-DskipTests` only for builds; the gate is the full command above.

## 10. Troubleshooting

| You see | Do this |
|---|---|
| "the database password for ... is not set" | Fill in `db/local.properties` or set the environment variables (step 4). |
| The lab stops on start and names the database | PostgreSQL is not running, or the tables are not migrated (step 5). |
| "the vault has data but its key file is missing" | Put the `console/vault-key/` folder back. A new key cannot open old data, by design. |
| "a second lab on this folder" | Another lab uses the same `--dir`. Stop it or choose another folder. |
| The page is blank after a restart | Reload with F5: the browser kept the old scripts. |
