# IGA schema: entity-relationship diagram

All 16 tables of the spec (section 3.1) plus the helper table `dept_birthright_role`. Crow's-foot notation: `||` exactly one, `o|` zero or one, `o{` zero or many, `|{` one or many. Each relationship line is labelled with the foreign-key column.

```mermaid
erDiagram
    department {
        bigint dept_id PK
        text name UK
        bigint parent_dept_id FK
    }
    person {
        bigint person_id PK
        text employee_no UK
        text full_name
        text email UK
        bigint dept_id FK
        bigint manager_id FK
        text status
        date hire_date
        date end_date
    }
    system {
        bigint system_id PK
        text name UK
        smallint criticality
        bigint owner_person_id FK
    }
    account {
        bigint account_id PK
        bigint person_id FK
        bigint system_id FK
        text username "UK with system_id"
        text account_type
        bigint owner_person_id FK
        text status
        timestamptz last_login_at
    }
    role {
        bigint role_id PK
        bigint system_id FK
        text name "UK with system_id"
        boolean is_privileged
    }
    entitlement {
        bigint entitlement_id PK
        bigint system_id FK
        text action "UK with system_id, resource"
        text resource
    }
    role_entitlement {
        bigint role_id PK, FK
        bigint entitlement_id PK, FK
    }
    role_assignment {
        bigint assignment_id PK
        bigint account_id FK
        bigint role_id FK
        bigint granted_by FK
        bigint request_id FK
        timestamptz valid_from
        timestamptz valid_to
        timestamptz revoked_at "live: account_id, role_id unique where null"
    }
    sod_rule {
        bigint role_a PK, FK
        bigint role_b PK, FK
        text description
    }
    dept_birthright_role {
        bigint dept_id PK, FK
        bigint role_id PK, FK
    }
    access_request {
        bigint request_id PK
        bigint requester_id FK
        bigint account_id FK
        bigint role_id FK
        text justification
        text status
        bigint decided_by FK
        timestamptz decided_at
    }
    lifecycle_event {
        bigint event_id PK
        bigint person_id FK
        text event_type
        bigint old_dept_id FK
        bigint new_dept_id FK
        timestamptz effective_at
        timestamptz processed_at
    }
    review_campaign {
        bigint campaign_id PK
        text name
        date starts_on
        date ends_on
    }
    review_item {
        bigint item_id PK
        bigint campaign_id FK
        bigint assignment_id FK
        bigint reviewer_id FK
        text decision
        timestamptz decided_at
    }
    privileged_session {
        bigint session_id PK
        bigint account_id FK
        bigint role_id FK
        bigint approved_by FK
        text reason
        tstzrange during "EXCLUDE overlap per account, role"
    }
    security_event {
        bigint event_id PK
        timestamptz occurred_at PK "partition key"
        bigint account_id FK
        text event_type
        inet source_ip
        text outcome
        jsonb details
    }
    audit_log {
        bigint seq PK
        timestamptz occurred_at
        text actor
        text action
        text table_name
        text row_pk
        jsonb old_row
        jsonb new_row
        bytea prev_hash
        bytea row_hash
    }

    department ||--o{ person : "dept_id"
    department |o--o{ department : "parent_dept_id"
    person |o--o{ person : "manager_id"
    person |o--o{ system : "owner_person_id"
    person |o--o{ account : "person_id (human)"
    person |o--o{ account : "owner_person_id (service, agent)"
    system ||--o{ account : "system_id"
    system ||--o{ role : "system_id"
    system ||--o{ entitlement : "system_id"
    role ||--o{ role_entitlement : "role_id"
    entitlement ||--o{ role_entitlement : "entitlement_id"
    account ||--o{ role_assignment : "account_id"
    role ||--o{ role_assignment : "role_id"
    person |o--o{ role_assignment : "granted_by"
    access_request |o--o{ role_assignment : "request_id"
    role ||--o{ sod_rule : "role_a"
    role ||--o{ sod_rule : "role_b"
    department ||--o{ dept_birthright_role : "dept_id"
    role ||--o{ dept_birthright_role : "role_id"
    person ||--o{ access_request : "requester_id"
    person |o--o{ access_request : "decided_by"
    account ||--o{ access_request : "account_id"
    role ||--o{ access_request : "role_id"
    person ||--o{ lifecycle_event : "person_id"
    department |o--o{ lifecycle_event : "old_dept_id"
    department |o--o{ lifecycle_event : "new_dept_id"
    review_campaign ||--o{ review_item : "campaign_id"
    role_assignment ||--o{ review_item : "assignment_id"
    person ||--o{ review_item : "reviewer_id"
    account |o--o{ security_event : "account_id"
    account ||--o{ privileged_session : "account_id"
    role ||--o{ privileged_session : "role_id"
    person ||--o{ privileged_session : "approved_by"
```

## Reading the diagram against spec 3.2

| Spec relationship | In the diagram |
|---|---|
| Department 1:N Person; Person 1:N Person (manager); Department 1:N Department (parent) | `department -> person`, `person -> person` (manager_id), `department -> department` (parent_dept_id) |
| Person 1:N Account; System 1:N Account, Role, Entitlement | `person -> account` (person_id for human accounts, owner_person_id for service and agent accounts); `system -> account / role / entitlement` |
| Role M:N Entitlement | via `role_entitlement` (composite primary key resolves the many-to-many) |
| Account M:N Role | via `role_assignment`, which carries its own attributes (granted_by, valid_from, valid_to, revoked_at) |
| Role M:N Role (conflict) | via `sod_rule` (role_a, role_b), with CHECK role_a < role_b so each pair is stored once |
| Campaign 1:N Review item; Review item N:1 Role assignment | `review_campaign -> review_item`, `role_assignment -> review_item` |
| Account 1:N Security event; Account 1:N Privileged session | `account -> security_event` (optional, account_id nullable), `account -> privileged_session` |

Notes: a human account must have `person_id`; a service or AI-agent account must have `owner_person_id` (CHECK `ck_account_owner`), so both foreign keys are optional in the table and exactly one is required by type. `lifecycle_event` keeps both department ids optional because a joiner has no old department and a leaver has no new one. `security_event` is range-partitioned monthly on `occurred_at`, so its primary key includes the partition key. `audit_log` references nothing by design: it stores row images as JSONB so history survives any later change to the audited tables.

## Build phases

| Phase | Tables |
|---|---|
| 1 (built first) | CORE: `department`, `person`, `system`, `account`, `role`, `entitlement`, `role_entitlement`, `role_assignment`, `lifecycle_event`, `security_event`, `audit_log`; plus `sod_rule` and `dept_birthright_role` |
| 4 | `review_campaign`, `review_item` |
| 5 (stretch) | `access_request` (adds the foreign key `role_assignment.request_id`), `privileged_session` |

Until phase 5, `role_assignment.request_id` is a plain nullable column with no foreign key, and `access_request`, `review_campaign`, `review_item` and `privileged_session` are drawn here as the design target.

## PNG

A PNG could not be made without a download: neither `mmdc` (Mermaid CLI) nor Graphviz `dot` is installed here. GitHub and https://mermaid.live render the Mermaid block above directly.
