# Demo walkthrough (about 10 minutes)

One tester plays every account. Say so at the start: **"The design is for two administrators who are two people. Today I
operate both, and the code still treats them as two different accounts."** Use account names only; never read out or show a
password or PIN. Keep `lab\console\people.txt` closed on screen.

## Before you start (5 minutes, off stage)

* The lab is running at `https://localhost:8443` (`bin\lab.cmd`), the database is up, and the lab's certificate authority is
  trusted. Press F5 in every browser window after a restart.
* Dana, Spector, Cleo and Ana have each registered their device passkey on the Profile page (once). Hana and Uma have none.
* Use one private window per account so the sessions do not mix. Have the first passwords on paper, not on screen.
* For a second run, use a different joiner id than the first (a person that exists is never overwritten).

## The run

| Min | Account and screen | What to do | What it proves | What to say |
|---|---|---|---|---|
| 0:00 | **Hana (HR)**, Access > People requests | Raise a joiner: id `priya`, name, department Engineering, business role Software engineer, a reason. The shell asks for password and PIN. | HR can only ask. HR sees no SOC, no administration, no vault. | "HR starts the process. Nothing exists yet, and HR cannot approve it." |
| 1:00 | **Dana (administrator)**, Administration > Access requests | Open the request. The role's access is **pre-ticked**. Untick one simple item, tick the production database. Save: the elevation dialog asks for **PIN, passkey and a reason**. | Checkbox access; only ticked items are granted, one record per item; **elevation**, with the 10-minute countdown in the footer. | "Privileged work needs a PIN, my passkey and a written reason. It lasts ten real minutes and I can end it now." |
| 2:30 | Same screen | Show: simple items granted at once, the production database waiting. Click "End now". | Simple vs hard approval; elevation ends on demand. | "Simple access is automatic once HR shows the person active. Sensitive access needs the administrator and a lead." |
| 3:00 | **Cleo (lead)**, Access > Approvals | Approve the waiting item (elevation). Dana's ticking and saving already counted as the administrator's approval; Cleo's is the second. | Hard approval needs the administrator **and** a lead; nobody approves their own request. | "Neither of us alone can grant it." |
| 4:00 | **Dana**, "Request a privileged change" | Ask to give a person the administrator role. Try to decide it as Dana. | The request goes to the **other** administrator; the asker cannot decide it. | "An administrator can no longer send a request to nobody. It goes to Spector." |
| 4:45 | **Spector (second administrator)** | Approve it (elevation). | Approval from a different account. The last administrator can never be removed. | "One tester, two accounts, but the code enforces a second person." |
| 5:30 | **Dana**, Vault > Emergency passwords | Elevate. Show that everyone's emergency password is **off**. Switch **Ana's** on (reason). The password shows for 60 seconds, then hides. Point at "the other administrator does that for you" beside Dana's own row. | Hidden vault, sealed storage, a reason and the passkey for every action. An administrator cannot act on themselves. | "Nobody sees this page unless they are an administrator. Every action is recorded first and never contains the secret." |
| 6:30 | **Ana**, sign-in page > recovery | Use the emergency password, then set a new password and PIN. Try it again. | It works once, for her only; every session of hers ended; it is replaced by a new switched-off one. | "It is a break-glass credential. It opens one thing and is used up." |
| 7:30 | **Spector**, Notices; **Cleo**, Monitoring > Vault log; **Spector**, Monitoring > Administrators | Spector reads the notices; Cleo shows who, when, on whom; Spector shows Dana's actions. | The other administrator and the lead are **notified, not asked**. Cleo never sees the secret or the reason. Administrators watch each other. | "Nobody has to approve an emergency, but everybody who should know does. The log cannot be edited by anyone." |
| 8:30 | **Hana**, Leaver | Remove `priya` (or any joiner you made). Show the Directory tab as Dana. | A leaver loses **everything at once**, from the grant records; sessions end; the emergency password is deleted. | "Removing access is more urgent than granting it." |
| 9:15 | **Uma** | Sign in: Home only, no passkey. | An ordinary user has a useful page and nothing confidential. | "She has nothing confidential, so she has no passkey." |
| 9:45 | Terminal or slide | Show the test count and "no administrator can edit an audit record". | Evidence. | "Every claim here has a named test." See [requirements-coverage.md](requirements-coverage.md). |

## If something goes wrong

* A blank page after a restart: F5.
* "elevation required": open the elevation again; it lasts ten real minutes.
* A passkey prompt that does nothing: the person has not registered a device on the Profile page yet.
* A new joiner cannot sign in: expected. Their first secrets are made when the lab next starts (see
  [iam-architecture.md](iam-architecture.md), "Known limitations"). Do not promise a first sign-in for a new joiner.
