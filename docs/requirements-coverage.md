# Requirements coverage

Every requirement of `admin-vault-and-iam-requirements.md` (sections 2 to 9, the proposals of section 11 as built, and
section 14), where it is implemented, and what proves it. Status: **Met**, **Met with a note**, **Partly met**, **Not built**.
Test names are the Java test methods under `src/test/java/dev/dwarpal/` (`PrivilegedAccessTest` means the one in the package
`directory`; the one in `pam` belongs to the Layer 3 PAM); "manual" means a check I ran by hand and wrote
down (see the list at the end). Nothing here is marked Met without a test or a manual check behind it.

## Section 2 to 9: what the user asked for

| # | Requirement | Status | Where | Proof |
|---|---|---|---|---|
| A1 | A hidden area where the administrator keeps their own password and security PIN | Met | `VaultModule` routes `own`, `own/save`, `own/reveal`; `Vault.saveOwn` | `VaultEndToEndTest.anAdministratorKeepsTheirOwnPasswordAndPinAndOnlyTheyCanReadThem` |
| A2 | No mention anywhere that it exists (menu, Guide, Glossary, other users) | Met with a note | Hidden module: `ConsoleServer.hiddenModule` answers a plain "not found"; no Guide or Glossary text | `VaultNotMentionedTest.onlyTheVaultsOwnPagesAndTheLeadsLogUseTheWord`, `VaultEndToEndTest.everybodyButAnAdministratorGetsAPlainNotFoundAndNeverSeesItInAList`. Note: an administrator sees "Vault" in their own menu, because they must reach it. Notices to the other administrator, the leads and the person say what happened (an emergency password), never "vault". |
| A3 | Only the Administrator user can use it | Met | Module minimum `ADMIN`; the vault refuses acting on oneself | `VaultEndToEndTest.everybodyBut...`, `VaultTest.aCallWithoutAnElevationOrFromAnotherRoleIsRefusedBeforeAnythingHappens` |
| A4 | It opens only with a passkey | Met | Every vault call needs an open elevation (PIN + passkey + reason) and the passkey again per action (`Gate.EVERY_TIME`) | `VaultEndToEndTest.theListNeedsAnElevation...`, `ElevationEndToEndTest.aWrongPinOrPasskeyOrNoReasonGivesNoElevation...`, `ConsolePasskeyWindowTest.aResponseActionAsksForThePasskeyEveryTime...`, manual (browser run in Stage 5 and 6 with Edge's virtual authenticator; not repeated in Stage 7) |
| B1 | A page where the administrator sees what team members do in their dashboard, everything | Partly met | `MonitorModule`: "Administrators" (the other administrator's actions) and "Vault log" (leads) | `MonitorEndToEndTest` (3). **Gap:** an administrator does not see analysts' dashboard actions. Those are in the audit explorer, which administrators cannot open (separation of duties). Section 14.5 asks only for the administrators and the vault log. Decision for the user. |
| C1 | A dedicated backup (emergency) password for every user, analysts and leads included | Met | `Vault.ensure` at every start for everyone who can sign in; `personCreated` for each new person | `VaultTest.aNewPersonGetsASwitchedOffEmergencyPasswordAndALeaverLosesIt`, `VaultEndToEndTest.theListNeedsAnElevation...`, manual |
| C2 | In a severe situation the administrator can change a user's password | Met by design | Not by reading or setting someone's real password: the administrator switches the emergency password on, the person uses it once on the recovery page and sets a new password and PIN themselves (section 11, item 1, so no readable copy of a real password exists) | `VaultEndToEndTest.anEmergencyPasswordDoesNothingUntilSwitchedOnThenWorksOnceInTheRecoveryAndIsReplaced` |
| C3 | If the administrator picks a password they remember, it stays visible in the section after the passkey | Met | `Vault.setTyped` (10 to 64 characters, kept as typed, readable until used) | `VaultTest.aChosenPasswordIsKeptAsTypedWithinLimits`, `VaultEndToEndTest.switchingItOffStopsItAndAnAdministratorMayChooseTheirOwnWhichStaysReadableUntilUsed` |
| C4 | Every time the section is opened: passkey and a 10-minute timer | Met with a note | Elevation: PIN + passkey + reason, 10 real minutes, footer countdown, "End now"; revealed secrets hide after 60 seconds | `ElevationEndToEndTest.theElevationClosesByItselfAfterTenRealMinutesAndTheCloseIsRecorded`, `VaultEndToEndTest.theListNeedsAnElevation...`. Note: the timer is read as "the view stays authorised for 10 minutes" (section 14.3), not "wait 10 minutes first". |
| C5 | Opening one user's credentials also needs the security PIN | Met | Vault POST routes are step-up routes (password + PIN no older than 5 minutes) plus the elevation's PIN | `ConsoleAccessTest.theHostChecksRoleCsrfAndStepUpBeforeAModuleRuns`, `ElevationEndToEndTest`, manual (browser run in Stage 6; not repeated in Stage 7) |
| D1 | The administrator approves joiners and assigns the role | Met | Administration > Access requests; `AccessApi.saveJoiner` | `AccessSectionTest.hrAsksTheAdministratorTicksAndSavesAndEveryGrantIsAudited`, `AccessProcessTest.onlyHrRaisesJoinersAndLeaversAndOnlyTheAdministratorSaves` |
| D2 | Approval is simple or hard | Met | `AccessItem.Sensitivity`: SIMPLE is automatic when the directory shows the person active; HARD needs the administrator and a lead | `AccessSectionTest.anOrdinaryPersonAsksForMoreAndSimpleItemsAreAutomaticWhileHardOnesWaitForBothApprovers`, `AccessProcessTest.aSensitiveItemIsNeverGrantedWithoutTheAdministratorAndALeadAndNobodyApprovesTheirOwn` |
| D3 | Requests for joiners and for leavers | Met | HR "People requests" | `AccessLeaverEndToEndTest` (3), `AccessSectionTest` |
| D4 | A leaver loses all access, removed completely | Met | Removal reads the grant records; console roles removed; open requests cancelled; sessions ended | `AccessProcessTest.aLeaverEndsWithZeroAccessEveryGrantRemovedFromTheRecordsAndEveryRemovalAudited`, `aLeaverWithNoGrantRecordsStillLosesTheirConsoleRoles`, `AccessLeaverEndToEndTest.aLeaverIsLockedOutAtOnceTheirSessionEndsAndTheyCannotSignInAgain` |
| D5 | Each role shows access as checkboxes; only ticked items are granted after saving | Met | `access_role_template` pre-ticks; `access_grant` one row per item | `AccessProcessTest.onlyWhatIsTickedIsGrantedOneRecordPerItemAndSensitiveItemsWaitForALead`, `theCatalogueAndTheRoleDefaultsAreThere` |
| D6 | A separate section in the admin dashboard | Met | Administration > "Access requests" tab | `AccessSectionTest.everyRouteRefusesTheRolesThatAreNotItsOwn` |
| E1 | An HR user type with the access HR needs | Met | Role `HR`, user `hana`; no SOC, administration, vault or monitoring | `DemoPeopleTest.rolesAreAnalystLeadAdminUserAndHr`, `DirectoryPeopleTest.theHrRoleIsItsOwnThingNotAnAnalystNorAnAdministrator`, `LabConsoleDirectoryEndToEndTest.thePeopleAreMovedIntoTheDirectoryAndHanaIsContainedToHerOwnRole` |
| E2 | HR's requests go directly to the administrator | Met | A joiner request is seen only by the administrator | `AccessLeaverEndToEndTest.aJoinerAsksThroughTheConsoleAndStaysUnseenByEveryoneButTheAdministrator` |
| F1 | A real database as the directory | Met | PostgreSQL 18.6, driver 42.7.14, `dev.dwarpal.directory` | `PostgresDirectoryTest` (9), `MigratorTest` (7), `DirectorySourceTest` (7), `DirectoryInjectionTest` (4) |
| F2 | Look into LDAP | Looked into, not built | See [iam-architecture.md](iam-architecture.md), "Known limitations" | None (nothing built). LDAP could later be a read interface over the same data. |
| F3 | The admin dashboard can open a link to the database/directory itself | Met | Administration > "Directory" tab: everyone with counts and the database version, read only, no address, user name or password | `AdminDirectoryTest` (4) |
| G1 | Uma's page shows something useful | Met | Home: her account, what it can open, what needs doing, recent activity on her own account; Access; "Why was I denied?" | `ConsoleProfileTest.aPersonSeesOnlyTheirOwnAccountActivity`, `ConsoleAccessTest.theModuleListShowsOnlyWhatARoleMaySee` |
| G2 | Uma has no passkey | Met | `needsPasskey` is false for a role that opens nothing confidential | `ConsoleProfileTest.aRoleThatOpensNothingConfidentialHasNoPasskey` |

## Section 11: proposals, and what the build does with each

| # | Proposal | Status | Proof |
|---|---|---|---|
| 1 | No readable real passwords; a separate emergency credential, encrypted | Met | `VaultTest.whatIsSavedComesBackAfterARestartAndTheFileIsSealed`, `ConsoleProfileTest.secretsSurviveARestartAndAreNeverKeptInTheClear` |
| 2 | Check-out / check-in: after use the password is changed and the credential rotated | Met | `VaultEndToEndTest.anEmergencyPasswordDoesNothingUntilSwitchedOnThenWorksOnce...` (single use, replaced by a new switched-off one) |
| 3 | The vault is encrypted with a key stored separately | Met | `VaultTest.aChangedByteAWrongKeyOrAMissingKeyStopsTheVault`, `VaultEndToEndTest.theVaultFileHoldsNoReadableSecretAndTheNoticesNoSecretEither` |
| 4 | Passkey, then PIN, then a credential that auto-hides | Met | The page hides a revealed secret after 60 s (`vault/index.js`, `SHOWN_SECONDS`); checked in a browser run in Stage 6, not repeated in Stage 7 |
| 5 | Administrator recovery: a second administrator | Met | `VaultEndToEndTest.aLockedOutAdministratorGetsBackInThroughTheOtherOneAndTheLeadIsTold` |
| 6 | Hide the vault from the interface, never from the audit trail | Met | `VaultNotMentionedTest`, `VaultEndToEndTest.everybodyBut...`; every call writes a `VAULT_` record first (`VaultTest.ifTheAuditTrailCannotTakeTheRecordNothingIsShownOrChanged`) |
| 7 | A separate tamper-evident log of vault actions; who reads it | Met | `VaultEndToEndTest.theLeadSeesWhoWhenAndOnWhomAndNeverTheSecretOrTheReasonAndAnAnalystSeesNothing`, `ConsoleTrailTest`; `VAULT_` records are in the saved trail and leads see who, when, on whom |
| 8 | Reuse the audit data for the team activity page; append-only | Partly met | `MonitorModule` over the saved trail; append-only by `AuditImmutableTest`. Same gap as B1: not an all-staff feed. |
| 9 | Role templates with pre-ticked checkboxes; one grant record per item | Met | `AccessProcessTest.onlyWhatIsTicked...` |
| 10 | Leaver removal uses the grant records; end sessions at once; revoke the backup credential | Met | `AccessProcessTest.aLeaverEndsWithZeroAccess...`, `AccessLeaverEndToEndTest`, `VaultTest.aNewPersonGets...AndALeaverLosesIt`, manual |
| 11 | Simple vs hard approval | Met | See D2 |
| 12 | Separation of duties: HR cannot approve its own requests; an administrator cannot approve their own; HR cannot see the vault, monitoring or others' credentials | Met | `AccessProcessTest.theAdministratorAndALeadCannotApproveTheirOwnRequests`, `AccessSectionTest.everyRouteRefusesTheRolesThatAreNotItsOwn`, `VaultEndToEndTest.everybodyBut...`, `MonitorEndToEndTest.otherPeopleDoNotGetThePage...` |
| 13 | A relational database rather than MongoDB | Met | PostgreSQL |
| 14 | Content for Uma's page | Met | See G1 |

## Section 14: second administrator and privileged access

| # | Requirement | Status | Proof |
|---|---|---|---|
| 14.1 | Dana and Spector, each with their own password, PIN and passkey; no shared account; Spector's first secrets are made by the lab and kept in `people.txt` | Met | `DemoPeopleTest.rolesAreAnalystLeadAdminUserAndHr`, `DirectoryPeopleTest`, `WebAuthnEndToEndTest.aPersonRegistersTheirDevice...`; secret scan below |
| 14.1 | Single-tester setup: the code still treats the two accounts as two people | Met | `PrivilegedChangeTest.theRulesTreatTwoAccountsOperatedByOnePersonAsTwoPeople` |
| 14.2 | "Request a privileged change" goes to the OTHER administrator; the old button is gone | Met | `PrivilegedChangeTest.anAdministratorsOwnRequestForMoreAccessIsNoLongerSentToNobody`, `theRequestWaitsForTheOtherAdministratorWhoCanDecideItAndTheAskerCannot` |
| 14.2 | Creating an administrator, giving or taking the administrator role, an administrator's own access: the other administrator approves, not the lead | Met | `PrivilegedChangeTest.aNewAdministratorAccountIsCreatedOnlyWhenTheOtherAdministratorApproves`, `PrivilegedAccessTest.onlyADifferentAdministratorMayDecideAndNeverTheOneWhoAsked` |
| 14.2 | The last active administrator can never be removed; an administrator's own request carries no console role | Met | `PrivilegedAccessTest.theLastAdministratorCanNeverBeRemoved`, `PrivilegedChangeTest.theLastAdministratorGuardAlsoHoldsAtApprovalTime`, `anAdministratorsOwnAccessChangesOnlyWhenTheOtherApprovesAndNeverTakesAConsoleRole` |
| 14.2 | Hard approvals for everybody else: administrator plus lead; nobody approves their own | Met | `AccessProcessTest.aSensitiveItemIsNeverGrantedWithoutTheAdministratorAndALead...` |
| 14.3 | Elevation: PIN, passkey, reason; 10 real minutes; footer countdown; "End now"; closes by itself; one session | Met | `ElevationEndToEndTest` (7); the countdown and "End now" in the footer: manual (browser run in Step A; not repeated in Stage 7) |
| 14.3 | Every elevated action audited with elevation id, who, what, target, before and after, reason, real time; start and end are records | Met | `AccessSectionTest.everyRecordOfAnElevatedActionNamesTheElevationAndItsReason`, `PrivilegedChangeTest.everyStepIsAuditedWithTheElevationBeforeAndAfter`, `ElevationEndToEndTest.theElevationClosesByItself...` |
| 14.3 | The passkey check sits behind one function, `PasskeyStepUp` | Met | `ElevationEndToEndTest.anotherWayOfProvingThePasskeyReplacesTheTypedOneWithoutTouchingTheCallers`, `WebAuthnEndToEndTest.theElevationAsksForTheDevice...` |
| 14.3 | Elevation covers the access process, the privileged changes and (Stage 6) emergency activation and vault reveals; HR keeps fresh password and PIN | Met | `ElevationEndToEndTest`, `AccessSectionTest.hrAsksForAFreshSecondFactorAndTheDecisionsAskForAnElevationInstead`, `VaultEndToEndTest.theListNeedsAnElevation...` |
| 14.4 | Emergency activation and vault reveals notify (not ask) the other administrator, and Cleo | Met | `VaultEndToEndTest.aRevealIsOnTheTrailWithoutTheSecretAndTheOtherAdministratorAndTheLeadAreTold` |
| 14.4 | The person's own passkey stays required when an emergency password is used | Met | Recovery changes only password and PIN and never touches the passkey record; manual (a throwaway lab, see [iam-stage-links.md](iam-stage-links.md), "Final gate and checks") |
| 14.5 | Each administrator sees the other's actions; Cleo sees the limited vault log | Met | `MonitorEndToEndTest` (3) |
| 14.5 | No administrator can edit or delete audit records; a record changed by hand is found at the next start, which refuses | Met | `AuditImmutableTest` (4), `ConsoleTrailTest.anAlteredByteInTheTrailIsRefused` |
| 14.6 | A locked-out administrator is recovered by the other, with Cleo notified | Met | `VaultEndToEndTest.aLockedOutAdministratorGetsBackInThroughTheOtherOneAndTheLeadIsTold` |
| 14.7 | PostgreSQL; prepared statements only; real passkeys; AES-256-GCM vault; emergency passwords off until activated; simple and hard approvals | Met | `DirectorySourceTest.everyPreparedStatementIsBuiltFromALiteralOrAConstant`, `WebAuthnEndToEndTest` (11), `VaultTest`, `VaultEndToEndTest.anEmergencyPasswordDoesNothingUntilSwitchedOn...` |
| 14.8 | Tests listed there (no self-approval, different account, goes to the other administrator, expiry after 10 real minutes, every elevated action audited, audit immutable) | Met | As above |

## Section 13: constraints

| Constraint | Status | Proof |
|---|---|---|
| Never write real passwords or PINs into the repo, the logs or this file | Met | Secret scan of the working tree and the git history: [iam-stage-links.md](iam-stage-links.md), "Final gate and checks" |
| Keep existing tests passing and add tests for new features | Met | Full gate: [iam-stage-links.md](iam-stage-links.md), "Final gate and checks" |
| Commit locally in small steps; nothing pushed | Met | One commit per stage; `origin/main` is unchanged |

## Not met or open

* **B1 / item 8:** monitoring does not show analysts' dashboard actions to administrators (decision for the user).
* **F2:** LDAP is not implemented.
* **First sign-in of a joiner:** an approved joiner gets first secrets at the next lab start. This is item "S3 to S6 first sign-in" in [iam-stage-links.md](iam-stage-links.md), left unticked.
* **New analysts** can sign in but the SOC service does not know them.
* **Real Windows Hello** has not been exercised by me on a physical device; it was exercised with a software authenticator in tests and Edge's virtual authenticator in a browser.

## Manual checks I ran

The results of the by-hand checks (the throwaway-lab runs and the from-scratch setup) are recorded in the "Final gate and checks"
section of [iam-stage-links.md](iam-stage-links.md).
