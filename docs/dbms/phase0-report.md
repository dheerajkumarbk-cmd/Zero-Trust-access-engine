# Phase 0 report: existing Dwarpal tables and the reuse plan

Source: `src/main/resources/db/migrations/V001__directory.sql`, `V002__access.sql`, `V003__privileged.sql` (read only).
Row counts were read from database `dwarpal` as `dwarpal_migrator` with `SELECT count(*)` only, on 12 November 2026. Nothing else was run against `dwarpal`.
Column types are as written in the migrations (VARCHAR(n), TIMESTAMP WITH TIME ZONE). V003 changes are folded in below.

## 1. Existing Dwarpal tables (8, all in schema public)

The database also holds `schema_version` (migration bookkeeping). It is not defined in these three files and is not listed further.

### directory_person (7 rows)
| Column | Type | Null |
|---|---|---|
| person_id | VARCHAR(32) | NOT NULL |
| display_name | VARCHAR(100) | NOT NULL |
| department | VARCHAR(60) | NOT NULL |
| business_role | VARCHAR(60) | NOT NULL |
| status | VARCHAR(10) | NOT NULL |
| source | VARCHAR(10) | NOT NULL |
| created_at, updated_at | TIMESTAMPTZ | NOT NULL |

Keys: PK person_id. CHECK status IN (ACTIVE, DISABLED); CHECK source IN (SEED, HR, ADMIN) (ADMIN added by V003); CHECK char_length(person_id) >= 2; CHECK char_length(trim(display_name)) > 0.
Note: department is plain text, not a table; there is no manager, email, hire date or end date.

### directory_person_role (9 rows)
| Column | Type | Null |
|---|---|---|
| person_id | VARCHAR(32) | NOT NULL |
| console_role | VARCHAR(10) | NOT NULL |

Keys: PK (person_id, console_role); FK person_id -> directory_person; CHECK console_role IN (ANALYST, LEAD, ADMIN, USER, HR).

### access_item (9 rows)
| Column | Type | Null |
|---|---|---|
| item_id | VARCHAR(30) | NOT NULL |
| label | VARCHAR(80) | NOT NULL |
| description | VARCHAR(200) | NOT NULL |
| sensitivity | VARCHAR(6) | NOT NULL |
| console_role | VARCHAR(10) | NULL |

Keys: PK item_id; CHECK sensitivity IN (SIMPLE, HARD); CHECK console_role IS NULL OR IN (ANALYST, LEAD, USER).

### access_role_template (25 rows)
Columns: business_role VARCHAR(60), item_id VARCHAR(30), both NOT NULL.
Keys: PK (business_role, item_id); FK item_id -> access_item.

### access_request (2 rows)
| Column | Type | Null |
|---|---|---|
| request_id | VARCHAR(40) | NOT NULL |
| kind | VARCHAR(16) (widened by V003) | NOT NULL |
| status | VARCHAR(10) | NOT NULL |
| subject_id | VARCHAR(32) | NOT NULL |
| requested_by | VARCHAR(32) | NOT NULL |
| reason | VARCHAR(300) | NOT NULL |
| display_name | VARCHAR(100) | NULL |
| department | VARCHAR(60) | NULL |
| business_role | VARCHAR(60) | NULL |
| decided_by | VARCHAR(32) | NULL |
| decision_reason | VARCHAR(300) | NULL |
| created_at, updated_at | TIMESTAMPTZ | NOT NULL |

Keys: PK request_id. CHECK kind IN (JOINER, LEAVER, ACCESS, CREATE_ADMIN, ADD_ADMIN, REMOVE_ADMIN, OWN_ACCESS); CHECK status IN (PENDING, APPROVED, REJECTED, DONE, CANCELLED); CHECK a JOINER has display_name, department, business_role; CHECK a CREATE_ADMIN has the same three (V003). No FK on subject_id, requested_by or decided_by.

### access_request_item (0 rows)
Columns: request_id VARCHAR(40), item_id VARCHAR(30), both NOT NULL.
Keys: PK (request_id, item_id); FK request_id -> access_request; FK item_id -> access_item.

### access_grant (0 rows)
| Column | Type | Null |
|---|---|---|
| grant_id | VARCHAR(40) | NOT NULL |
| request_id | VARCHAR(40) | NOT NULL |
| person_id | VARCHAR(32) | NOT NULL |
| item_id | VARCHAR(30) | NOT NULL |
| state | VARCHAR(8) | NOT NULL |
| created_at | TIMESTAMPTZ | NOT NULL |
| granted_at, removed_at | TIMESTAMPTZ | NULL |
| removed_reason | VARCHAR(100) | NULL |

Keys: PK grant_id; FK request_id -> access_request; FK person_id -> directory_person; FK item_id -> access_item; CHECK state IN (PENDING, ACTIVE, REJECTED, REMOVED); CHECK state <> ACTIVE OR granted_at IS NOT NULL.

### access_approval (0 rows)
| Column | Type | Null |
|---|---|---|
| grant_id | VARCHAR(40) | NOT NULL |
| approver_role | VARCHAR(5) | NOT NULL |
| approver_id | VARCHAR(32) | NULL |
| decision | VARCHAR(8) | NOT NULL |
| reason | VARCHAR(300) | NULL |
| decided_at | TIMESTAMPTZ | NULL |

Keys: PK (grant_id, approver_role); FK grant_id -> access_grant; CHECK approver_role IN (ADMIN, LEAD); CHECK decision IN (PENDING, APPROVED, REJECTED); CHECK decision = PENDING OR (approver_id and decided_at not null).

## 2. Spec section 3.1 against Dwarpal

| # | Spec table | Status | Closest Dwarpal table and the gap |
|---|---|---|---|
| 1 | department (CORE) | missing | Only a text column `directory_person.department`. No table, no parent. |
| 2 | person (CORE) | partial | `directory_person` holds people, but has no employee_no, email, manager, hire/end date; status is ACTIVE/DISABLED (spec: active/on_leave/terminated); text ids. |
| 3 | account (CORE) | missing | None. `directory_person_role` gives console roles, not per-system accounts. |
| 4 | system (CORE) | missing | None. |
| 5 | role (CORE) | partial | `directory_person_role.console_role` (5 fixed values) and `access_item` overlap loosely; neither is a per-system role with a privileged flag. |
| 6 | entitlement (CORE) | partial | `access_item` is a catalogue of things a person can be given, not (system, action, resource). |
| 7 | role_entitlement (CORE) | partial | `access_role_template` maps business role -> item; similar idea, different entities. |
| 8 | role_assignment (CORE) | partial | `access_grant` (person x item, state, granted/removed times); no valid_to, no account, no granted_by. |
| 9 | sod_rule | missing | None. |
| 10 | access_request | exists, different shape | `access_request` exists with text ids, kind/status vocabularies of its own and no requester/approver FKs or requester <> approver check. |
| 11 | lifecycle_event (CORE) | missing | Joiner/leaver are request kinds in `access_request`; no old/new department history. |
| 12 | review_campaign | missing | None. |
| 13 | review_item | missing | None. |
| 14 | privileged_session | missing | V003 adds privileged requests (CREATE_ADMIN etc.) as request kinds, not sessions with a time range. |
| 15 | security_event (CORE) | missing | None in PostgreSQL. |
| 16 | audit_log (CORE) | missing | None in PostgreSQL. |

## 3. Approved plan

- The `iga` schema is built self-contained in a separate database, `dwarpal_dbms`. It does not touch `dwarpal` or `dwarpal_test`.
- PostgreSQL cannot join or reference another database. Cross-database views and foreign keys need `postgres_fdw` or `dblink`, which would store a password in the server; they are not approved. So nothing from Dwarpal is duplicated live and nothing in `iga` has a foreign key into Dwarpal.
- The only link is an OPTIONAL read-only import script: psql `\copy` out of `dwarpal.directory_person` into a staging table, plus a read-only view in `iga`. It is built last and only if time allows.
- Two helper tables beyond the spec's 16: `sod_rule` (built early, in phase 1, because the seed's six rules and `v_sod_violations` need it) and `dept_birthright_role(dept_id, role_id)` (the roles a joiner or mover gets from the department).

Phase split:

| Phase | Builds |
|---|---|
| 0 | This report |
| 1 | CORE tables (department, person, system, account, role, entitlement, role_entitlement, role_assignment, lifecycle_event, security_event, audit_log) plus sod_rule and dept_birthright_role; `role_assignment.request_id` is a plain nullable column with no FK yet |
| 2 | Functions, procedures, triggers, audit hash chain |
| 3 | Seed data, views, indexes, EXPLAIN captures |
| 4 | Roles, row-level security, backup and restore; review_campaign and review_item |
| 5 (stretch) | access_request (and the FK from role_assignment.request_id), privileged_session, SoD and privileged-approval triggers, approve_request |
