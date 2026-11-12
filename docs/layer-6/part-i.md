# Layer 6 part I: admin and user views

*Built by the lab session on branch `layer6/lab` (merged with `layer6/integration` for the wiring). Not pushed. Data is the
simulated organisation.*

## 1. What it is

A console module, id `admin` (`dev.dwarpal.console.admin.AdminModule`, pages under
`src/main/resources/console/modules/admin/`). It adds no new security logic: every change goes through the components
that already enforce the rules (`PolicyInstaller`, `PlaybookInstaller`, `PrivilegedAccessManager`, `WhatIf`), with the
administrator's own signature, and every refusal is theirs. `AdminServices` is the seam; `LabAdminServices` implements
it over the running lab (`LabSession`), the tests over a small composition of the same real components.

| Page | Role | What it does |
|---|---|---|
| Why was I denied? | USER | The person's own latest decisions in the engine's own words (`Decision.userMessage()`), a reference, what to do next. Nothing else |
| Policy | ADMIN | Active policy in plain words (every condition rendered by `describe()`), change number, history of changes from the audit chain |
| Playbooks | ADMIN | Active playbooks, per rule, in plain words |
| Proposals | ADMIN | Propose a policy or playbook (linted on entry), what-if on recent requests, sign, install, withdraw |
| Privileged access | ADMIN | Open elevation requests, grants, break-glass uses awaiting review; request, approve, revoke, review |
| Sessions and devices | ADMIN | Latest decision per person and device, device posture, isolation state, what the SOC revoked |

Privileged writes (sign, install, request, approve, revoke, review) are registered with `needsStepUp` true and checked
again in the handler. Installation is two steps on purpose: signing (each administrator, with their own key, over the
exact text and sequence) and install (the installer checks two distinct valid approvers, the sequence, the linter, and
writes the audit record before the change takes effect). The module keeps only open paperwork: at most 10 proposals,
one hour each.

**What the lab does not have.** No gateway runs in the lab, so there are no gateway sessions. The sessions page shows the
latest decision per person and device from the audit chain and the SOC's revocations, and says so on the page.

## 2. Routes (`/console/api/admin/`)

`whoami`, `me/decisions`, `me/decisions/{ref}` (USER); `policy`, `playbooks`, `proposals`, `sessions`, `devices`,
`decisions/{ref}`, `pam` (ADMIN, read); `policy/propose`, `playbooks/propose`, `proposals/{id}/whatif|withdraw` (ADMIN);
`proposals/{id}/approve|install`, `pam/request`, `pam/approve/{id}`, `pam/revoke/{id}`, `pam/review/{id}` (ADMIN, step-up).
Strict JSON, unknown fields refused, identifier-only path parameters, one short error sentence.

## 3. Threat model: STRIDE with ASVS / Top 10

| # | Threat | Control | Test | Reference |
|---|---|---|---|---|
| S1 | A person signs as another administrator | the signing key is looked up by the logged-in person's id; a person without a key (any other id) gets 403 | `AdminModuleTest.aPersonWithoutASigningKey...` | ASVS V2, V4; A01 |
| S2 | A stale session approves or installs | host step-up plus a second check in every privileged handler | `privilegedWritesAlsoRefuseAStaleSecondFactor...` | ASVS V2.8 |
| T1 | One administrator approves twice, or alone | the installer counts distinct signers; the test signs twice and installs: refused | `aPolicyNeedsTwoDifferentAdministrators...` | CM-5, SOC 2 CC8.1 |
| T2 | An old sequence replayed, or an approved file edited | approvals sign the exact text and sequence (a proposal cannot be edited, only withdrawn); the installer refuses rollback | `anOldSequenceIsRefusedByTheInstaller...` | ASVS V13 |
| T3 | A hostile policy or playbook file (tags, aliases, nesting, duplicate keys, control characters, unknown rules, destructive default, secret) | the real safe loaders and linters; a refused file is shown with findings but never kept; its text is not echoed back | `LabAdminModuleTest.hostileFiles...`, `AdminModuleTest` | ASVS V5; A03, A08 |
| T4 | Elevation without a second person | PAM refuses own approval, ineligible people and roles, short reasons, long windows | `anElevationNeedsADifferentApprover...`, `...Ineligible...` | AC-5, AC-6 |
| R1 | Who changed what | every install, grant and revoke is an audit record written by the component under the administrator's id; the history page reads them | `LabAdminModuleTest.anInstalledPolicy...` | AU-2, AU-10 |
| I1 | "Why was I denied" teaches an attacker | only the engine's requester message, the reference, time, resource, action and generic next steps: no policy, score, signal, address, device or threshold | `theRequestersPageUsesTheEnginesOwnWords...` | ASVS V7.4, V8; A04 |
| I2 | Reading another person's decision by guessing a reference | a reference that is not yours answers exactly like one that does not exist (same status and body) | `anotherPersonsReferenceLooksExactlyLike...` | ASVS V4.2; API1 |
| I3 | Stored XSS through policy descriptions or justifications | text goes in only with `textContent`; JSON stays valid whatever the text holds; the source test covers the admin pages | `textFromTheFileComesBackAsData...`, `FrontEndRulesTest` | ASVS V5.3 |
| D1 | Proposal flood | at most 10 open, 64 KiB each, one hour; PAM's own rate limits | `proposalsAreBoundedAndLapse` | ASVS V11 |
| D2 | What-if too large | at most 20,000 recent requests, the replay's own 200,000 cap | `whatIfReplays...` | |
| E1 | An analyst or ordinary person reaches admin data | role in registration and in every handler | `handlersRefuseTheWrongRoleEvenWithoutTheHostsCheck` | ASVS V4.1 |

## 4. Red-team pass

| Probe | First result | Now |
|---|---|---|
| Refused proposal file echoed back to the browser in the answer | **Leak of the submitted text** (found by the hostile-file test: an object tag came back in the response) | A refused file's text is not returned |
| Same administrator signs twice then installs | Held (installer: "1 distinct") | Regression test |
| Person with ADMIN role but no signing key approves | Held (403) | Regression test |
| Stale second factor on approve, install, request | Held (403) | Regression test |
| Install the same proposal twice; install an older sequence after a newer one | Held (404; "rollback") | Regression tests |
| Someone else's decision reference, a made-up one, and `../..` | Held (identical 404; 400) | Regression tests |
| Decision details page as an ordinary person | Held (403) | Regression test |
| Elevation: own approval, ineligible role, stranger, 1-character reason, 600 minutes | Held (PAM refuses each) | Regression tests |
| 11th proposal; proposal after the hour | Held (429; lapses) | Regression test |
| Object tag, alias, 5,000-deep nesting, duplicate keys, control character in policy and playbook files | Held; no stack trace | Regression test |
| Word "factor" in the requester's page | Test too strict, not a leak: the generic advice says "second factor" | Test now looks for risk, score, policy names |

## 5. Requests to the integration session

1. The host constructs `new AdminModule(new LabAdminServices(session))`, with the same `LabSession` as the lab module.
2. The console person ids `ada` and `ray` are the lab's two administrators (they own the signing keys); other ADMIN
   persons can read but cannot sign (stated on screen by the 403).
3. After a reset, open proposals refer to the old installer and fail when signed or installed; they lapse in an hour.
4. Roles: handlers treat ADMIN as including LEAD and ANALYST; USER stands apart.

## 6. Differences from a commercial product

| Commercial (privileged-access and change-management suites, IAM governance) | Here |
|---|---|
| Approval workflows with tickets, delegation and e-mail | Two signatures on the exact text, in the console, one hour to complete |
| Policy simulation in a staging tenant | What-if replay of recent requests (data-minimised, without signed evidence), with gains in restricted access listed first |
| Session management of real gateways | None in the lab; decisions per person and device from the audit chain |
| Break-glass vaults with hardware tokens | Sealed key per account in the lab; review by a different person |
| Self-service portal explaining denials in detail | Deliberately only the engine's generic message and a reference |
