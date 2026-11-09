# Identity and access: how it is built

This describes the identity-and-access part of the Dwarpal lab as it exists in the code, stage by stage. It follows the
IAM process notes (administration, authentication, authorization, audit, privileged access) and the requirements in
`admin-vault-and-iam-requirements.md`. For setup see [setup.md](setup.md); for what proves each requirement see
[requirements-coverage.md](requirements-coverage.md); for the stage-by-stage checklist see
[iam-stage-links.md](iam-stage-links.md).

Lab project: it has not been audited and is not production-ready. Read "Known limitations" at the end.

## 1. Single-tester setup of a design meant for two people

The design assumes two administrators who are two different people, **Dana** and **Spector**. In this lab one tester
operates every account, both administrators included, to try the whole thing. The code does not know that: it treats the two
accounts as two people. An approval has to come from a different account than the requester, and one account can never
approve its own request. In a real organisation these are two people, and the approval is a real check by a second person.
A demonstration with one tester shows the rules working, but it is not two-person control in the real sense.

## 2. The pieces

```
 browser console (plain ES modules, strict CSP)
        |  HTTPS, loopback only
 ConsoleServer  -- sessions, roles, CSRF, step-up, passkey gates, rate limits, audit of every request
   |        |            |            |             |            |
 Access   Admin       Monitor      Vault        Notices     SOC pages (ana, ben, cleo)
 module   module      module       module       board       through the SOC API
   |        |                         |
 AccessApi --- CredentialLifecycle ---+   (a person appears -> a switched-off emergency password; a person leaves -> it is deleted)
   |
 dev.dwarpal.directory  (the only package that touches JDBC; every query is a PreparedStatement)
   |
 PostgreSQL: dwarpal (lab) and dwarpal_test (tests), signed in as dwarpal_app (rows only) or dwarpal_migrator (tables)
```

### 2.1 The directory database and the data-access layer

* **PostgreSQL** holds the directory: people and their console roles (`directory_person`, `directory_person_role`) and the
  access process (`access_item`, `access_role_template`, `access_request`, `access_request_item`, `access_grant`,
  `access_approval`). Tables are made by numbered scripts under `src/main/resources/db/migrations` (three today).
* **One small data-access layer** (`dev.dwarpal.directory`): `PostgresDirectory` and `PostgresAccess` behind the interfaces
  `Directory` and `Access`. Only this package imports JDBC, every query is a `PreparedStatement` built from a literal, there is
  no SQL assembled from strings, and the SQL is standard SQL (`DirectorySourceTest`, `DirectoryInjectionTest`).
* **Two database logins.** The running lab is `dwarpal_app`: it can read and write rows and cannot create, change or drop a
  table or delete a person (`PostgresDirectoryTest.theLabUserCanReadAndWriteRowsButNotChangeTablesOrDeletePeople`).
  `dwarpal_migrator` builds the tables and runs the tests. Passwords come from environment variables or the untracked
  `db/local.properties`, never from source.
* **The Directory page** (administrators): lists everyone with counts and the database version. It is read only and never
  shows an address, a user name or a password (`AdminDirectoryTest`).

### 2.2 Joiner, access request and leaver

| Flow | Who starts it | Who decides | What happens |
|---|---|---|---|
| **Joiner** | **Hana (HR)** raises it with a fresh password and PIN: name, department, business role, reason | An **administrator** | Nothing exists until the administrator saves. The role's default access shows as **pre-ticked checkboxes**; the administrator ticks or unticks and saves under an elevation. Only the ticked items are granted, one `access_grant` row per item. The person is created in the directory, and the vault makes their switched-off emergency password. A refused joiner needs a reason and creates nothing. |
| **Access request** | Any signed-in person except an administrator: "Request more access" | Automatic or by people | **Simple** items (email, wiki, VPN, CRM, the plain console) are granted at once if the directory shows the person is **active**. **Hard** items (finance, production database, the analyst and lead consoles) need the **administrator and a lead**. Nobody approves their own request, and a refusal needs a reason. |
| **Leaver** | **Hana (HR)** with a fresh password and PIN | Nobody (removal needs no approval) | At once. In one database transaction every grant recorded for the person is removed **from the grant records, not recalculated from the role**, console roles are removed and open requests are cancelled; then their sessions end and they cannot sign in again, and the vault deletes their emergency password and, for an administrator, their own entry. HR cannot remove an administrator by this route. |

Granting a console role (`console`, `console-analyst`, `console-lead`) takes effect at once and ends the person's old session.

### 2.3 Privileged changes between the two administrators

An administrator's own "Request more access" would have gone to nobody, so it is refused for administrators. Instead an
administrator uses **"Request a privileged change"**, which goes only to the OTHER administrator:

* create an administrator account,
* give or take away the administrator role,
* change their own access (never a console role).

The lead is not asked. The asker cannot decide their own request; a refusal needs a reason; and the **last active
administrator can never be removed**, checked both when the request is raised and when it is approved
(`PrivilegedAccessTest`, `PrivilegedChangeTest`).

### 2.4 The audit trail

* Every console action and every access, elevation and vault action is an audit record: who, what, the target, before and
  after values where something changed, the reason, the elevation id and the real time. Secrets are never written.
* The lab's own chain (HMAC-chained) is joined by a **saved console trail** under `console/trail`, checked at every start.
  A record changed or removed by hand is found and the console **refuses to start** on it (`ConsoleTrailTest`,
  `AuditImmutableTest`).
* **No administrator, or anyone, can edit or delete a record.** There is no route and no method that does it
  (`AuditImmutableTest.theConsoleHasNoCallThatEditsOrDeletesARecordForAnyRoleOrMethod`).
* Vault records have their own type (`VAULT_...`). Analysts cannot read them. A lead sees only the action and the target,
  plus the record's own actor and time, never the reason or any secret.

### 2.5 Privileged elevation (a small PAM)

Privileged actions need an **elevation**: the security PIN, the passkey and a written reason (5 to 200 characters).

* It lasts **10 real minutes** (the lab's fast scenario clock is not involved), shows a countdown in the footer, can be ended
  at once with "End now", and closes by itself. It belongs to one session; a second sign-in of the same person is not elevated.
* Only administrators and leads can be elevated.
* The start, the end (by the person, by time running out or by the session ending) and a failed attempt are records
  (`ELEVATION_STARTED`, `ELEVATION_ENDED`, `ELEVATION_FAILED`). A wrong PIN or passkey and a missing reason give the same
  answer, which does not say which was wrong.
* It guards: an administrator's or a lead's decision on an access grant, an administrator's joiner decisions, the privileged
  changes, and every vault call. HR holds no passkey, so HR's requests keep the fresh password and PIN instead.

### 2.6 Real passkeys

* A person registers their own **device passkey** (Windows Hello, a phone or a security key) on the Profile page, after proving
  password and PIN. Dana, Spector, Cleo and the analysts each do their own.
* The console checks everything with the JDK only: a fresh single-use challenge made for that person (2 minutes), the origin
  (`https://localhost:8443`), the relying party (`localhost`), the user-present and user-verified flags, the signature
  (ES256 or RS256) and that the signature counter never goes backwards (a counter that stays at zero is fine). The private
  key never leaves the device; the console keeps only the public key.
* Everything that needs the passkey calls one function, `PasskeyStepUp`. Real passkeys replaced the typed one by swapping its
  implementation (`WebAuthnStepUp`); no caller changed.
* `--passkey typed` keeps the old typed passkey for a machine with no device passkey, and for tests.
* The passkey gates the vault and the privileged actions. It never gates ordinary sign-in, which asks for password and PIN only.

### 2.7 The vault and emergency passwords

* **What it keeps:** (1) one **emergency password** per person, analysts, leads and everyone else included, made when the
  person is made, random (`XXXX-XXXX-XXXX-XXXX`), and **switched off**; (2) an administrator's **own** password and PIN, readable
  only by that administrator.
* **Ordinary passwords are never stored readable.** They stay as salted one-way hashes. The emergency password is a separate
  credential, so the "severe situation" recovery needs no readable copy of anyone's real password.
* **At rest** the vault is sealed with AES-256-GCM under a key kept in a separate folder (`console/vault-key`). A changed byte,
  a wrong key or a missing key stops the console from starting (`VaultTest`).
* **Hidden:** to anyone who is not an administrator the vault does not exist: no menu entry, no Guide or Glossary entry, and a
  plain "not found" for every address, the same as a page that is not there. (An administrator sees the Vault in their own menu.)
* **Every vault call** needs an open elevation (otherwise "423 elevation required"), a reason, and a second-factor proof no
  older than 5 minutes, and it asks for the passkey again each time. The record is written **first**; if the audit trail cannot
  take it nothing is shown or changed.
* **An administrator can never act on themselves** in the vault (the other administrator does that for them).
* **Using it:** an administrator switches a person's emergency password on, tells them in person, and the person opens the
  sign-in page's recovery with it. It works once, only for that person, and only for the recovery: the person must set a new
  password and PIN, every session of theirs ends, and the emergency password is replaced by a new switched-off one. The
  person's passkey is not touched. An administrator may also choose the password themselves (10 to 64 characters); it is kept
  as typed and stays readable in the vault until it is used.
* **Display:** a revealed secret shows for 60 seconds, hides itself, and is never stored in the page.
* **Who is told:** the OTHER administrator and the leads (Cleo) get a notice on every vault action; the person gets one when
  their emergency password is switched on and when it is used. Nobody has to approve, because an emergency cannot wait.
  Notices (`NoticeBoard`) never hold a secret.
* **If an administrator is locked out,** the other administrator runs this same recovery for them, with Cleo notified. There
  is no paper workaround.

### 2.8 Monitoring

The Monitoring page is read only and has no way to change a record.

* **Administrators:** each administrator sees what the OTHER administrator did (access decisions, elevations, sign-ins,
  changes; not plain page views). Vault records of the other administrator appear as the action and the target only.
* **Leads (Cleo):** the limited vault log: who, when, on whom, and the kind of action. Never the secret or the reason.

## 3. Roles and accounts

The demo people (their first passwords and PINs are in `lab\console\people.txt`, not here):

| Person | Role in the lab | Can see and do |
|---|---|---|
| **Dana** | Administrator | Administration: policy and playbook proposals with the two-person install, what-if replay, privileged access (PAM), sessions and devices, reset to day zero, the **Directory** tab, the **Access requests** tab (joiner queue, ticking and saving access, hard-item approvals, privileged changes). The **Vault** (tabs "Emergency passwords" and "My own entry"). **Monitoring** (tab "Administrators": the other administrator's actions). Notices. Profile. Not an analyst: no SOC queue, cases or audit explorer, by design (separation of duties). Needs a passkey; elevation for privileged actions. |
| **Spector** | Administrator (the second one) | Exactly what Dana can, with his own password, PIN and passkey. Dana's requests for a privileged change go to him, and his to her. |
| **Cleo** | SOC lead (also an analyst) | Everything an analyst has, plus reports and exports, the **hard-item approvals** for access (with an administrator), and the **Monitoring** tab "Vault log" (who, when, on whom). Is told of every vault action. Can be elevated. |
| **Ana**, **Ben** | Analysts | The SOC: alert queue, cases and verdicts, hunt, entity risk, response, audit explorer (not vault records), scans, the Guide and the scenario lab. Request more access. Need a passkey. |
| **Hana** | HR | Access, "People requests": raises joiner and leaver requests (each with a fresh password and PIN). Also "my access" and "request more access" like any person. Sees nothing of the SOC, administration, vault or monitoring, and cannot see an administrator in her list or remove one. Has no passkey and needs none. |
| **Uma** | Ordinary user | Home (her account, what it can open, what needs doing, recent activity on her own account), Access ("my access" and "request more access"), "Why was I denied?", Profile (password, PIN, backup codes, sessions). Sees nothing confidential, so has no passkey and should not. |

The SOC service itself knows only `ana`, `ben` and `cleo` (see limitations).

## 4. Known limitations and honest notes

* **Lab project.** Not audited and not production-ready. One process, loopback only, free tools only. A company would run
  the SIEM, SOAR and console as separate services with single sign-on and hardware key storage.
* **LDAP is not implemented.** The directory is PostgreSQL behind one data-access layer. LDAP could later be offered as a read
  interface over the same data; it was not built. MongoDB and H2 were considered and not used.
* **The SOC service knows only `ana`, `ben` and `cleo`.** A new analyst created through the joiner flow can sign in to the
  console, but cannot act as a SOC analyst, because the SOC side has no record of them.
* **A new joiner gets first secrets at the next lab start.** There is no first-sign-in flow: an approved joiner exists in the
  directory and has a switched-off emergency password at once, but their first password and PIN are made and written to
  `people.txt` the next time the lab starts. The same holds for an administrator account made by a privileged change.
* **Monitoring is narrower than "everything a team member does".** Administrators see the other administrator's actions and
  leads see the vault log. Analysts' dashboard actions are in the audit explorer for analysts and leads, which administrators
  cannot open (separation of duties).
* **Policy, playbook, PAM and lab-reset changes** in Administration still ask for the password, PIN and passkey on every
  action; they are not under elevation. HR requests keep the fresh password and PIN, since HR has no passkey.
* **Passkeys:** checked with a software authenticator in the tests and with Edge's virtual authenticator in a browser. The
  attestation statement is not evaluated, so any authenticator is accepted; this is a lab, not a hardware-attestation policy.
  Registering and using Windows Hello on the real device is for the person to try.
* **The vault key sits on the same machine** as the vault, in a different folder. Someone who controls your Windows account can
  read both. Keep a copy of `console/vault-key` elsewhere.
* **Notices are polled every 30 seconds**, not pushed.
* **The SOC world restarts from day zero** each time the lab starts; the directory, the vault, notices, passkeys,
  credentials and the saved audit trail are kept.
* **Database tests are skipped** when the database passwords are not configured; Node.js is needed for the script-parse test.
* **User names are case-sensitive** at sign-in.
