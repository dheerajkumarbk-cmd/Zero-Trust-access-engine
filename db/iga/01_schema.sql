-- 01_schema.sql : IGA schema, phase 1 tables (CORE + sod_rule + dept_birthright_role).
-- Drops and rebuilds the whole iga schema, so the full build is re-runnable. All-or-nothing.
-- Named CHECK/UNIQUE constraints are added in 02_constraints.sql.
\set ON_ERROR_STOP on

BEGIN;

DROP SCHEMA IF EXISTS iga CASCADE;
CREATE SCHEMA iga;
SET search_path = iga, public;

-- ---------------------------------------------------------------- identity directory
CREATE TABLE department (
    dept_id        bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name           text   NOT NULL,
    parent_dept_id bigint NULL,
    CONSTRAINT fk_department_parent_dept_id FOREIGN KEY (parent_dept_id) REFERENCES department (dept_id)
);
COMMENT ON TABLE department IS 'Organisational units; parent_dept_id makes the hierarchy a recursive relationship.';

CREATE TABLE person (
    person_id   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    employee_no text   NOT NULL,
    full_name   text   NOT NULL,
    email       text   NOT NULL,
    dept_id     bigint NOT NULL,
    manager_id  bigint NULL,
    status      text   NOT NULL DEFAULT 'active',
    hire_date   date   NOT NULL,
    end_date    date   NULL,
    CONSTRAINT fk_person_dept_id    FOREIGN KEY (dept_id)    REFERENCES department (dept_id),
    CONSTRAINT fk_person_manager_id FOREIGN KEY (manager_id) REFERENCES person (person_id)
);
COMMENT ON TABLE person IS 'Every human in the directory; never deleted, only terminated, so history keeps its referents.';

CREATE TABLE system (
    system_id       bigint   GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name            text     NOT NULL,
    criticality     smallint NOT NULL,
    owner_person_id bigint   NULL,
    CONSTRAINT fk_system_owner_person_id FOREIGN KEY (owner_person_id) REFERENCES person (person_id)
);
COMMENT ON TABLE system IS 'Applications protected by the platform, with a criticality from 1 to 4 and a business owner.';

CREATE TABLE account (
    account_id      bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    person_id       bigint      NULL,
    system_id       bigint      NOT NULL,
    username        text        NOT NULL,
    account_type    text        NOT NULL,
    owner_person_id bigint      NULL,
    status          text        NOT NULL DEFAULT 'active',
    last_login_at   timestamptz NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT fk_account_person_id       FOREIGN KEY (person_id)       REFERENCES person (person_id),
    CONSTRAINT fk_account_system_id       FOREIGN KEY (system_id)       REFERENCES system (system_id),
    CONSTRAINT fk_account_owner_person_id FOREIGN KEY (owner_person_id) REFERENCES person (person_id)
);
COMMENT ON TABLE account IS 'A login on one system: human (belongs to a person) or service/ai_agent (has an accountable owner).';

-- ---------------------------------------------------------------- access governance
CREATE TABLE role (
    role_id       bigint  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    system_id     bigint  NOT NULL,
    name          text    NOT NULL,
    is_privileged boolean NOT NULL DEFAULT false,
    CONSTRAINT fk_role_system_id FOREIGN KEY (system_id) REFERENCES system (system_id)
);
COMMENT ON TABLE role IS 'A named bundle of entitlements on one system; is_privileged marks roles needing approval and session control.';

CREATE TABLE entitlement (
    entitlement_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    system_id      bigint NOT NULL,
    action         text   NOT NULL,
    resource       text   NOT NULL,
    CONSTRAINT fk_entitlement_system_id FOREIGN KEY (system_id) REFERENCES system (system_id)
);
COMMENT ON TABLE entitlement IS 'One permission (action on resource) offered by a system.';

CREATE TABLE role_entitlement (
    role_id        bigint NOT NULL,
    entitlement_id bigint NOT NULL,
    PRIMARY KEY (role_id, entitlement_id),
    CONSTRAINT fk_role_entitlement_role_id        FOREIGN KEY (role_id)        REFERENCES role (role_id),
    CONSTRAINT fk_role_entitlement_entitlement_id FOREIGN KEY (entitlement_id) REFERENCES entitlement (entitlement_id)
);
COMMENT ON TABLE role_entitlement IS 'Resolves the many-to-many relationship between role and entitlement.';

CREATE TABLE role_assignment (
    assignment_id bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id    bigint      NOT NULL,
    role_id       bigint      NOT NULL,
    granted_by    bigint      NULL,
    request_id    bigint      NULL,  -- FK to access_request is added in phase 5
    valid_from    timestamptz NOT NULL DEFAULT now(),
    valid_to      timestamptz NULL,
    revoked_at    timestamptz NULL,
    CONSTRAINT fk_role_assignment_account_id FOREIGN KEY (account_id) REFERENCES account (account_id),
    CONSTRAINT fk_role_assignment_role_id    FOREIGN KEY (role_id)    REFERENCES role (role_id),
    CONSTRAINT fk_role_assignment_granted_by FOREIGN KEY (granted_by) REFERENCES person (person_id)
);
COMMENT ON TABLE role_assignment IS 'Account-to-role grant with its own attributes (who granted, from when, until when, revoked when).';

CREATE TABLE sod_rule (
    role_a      bigint NOT NULL,
    role_b      bigint NOT NULL,
    description text   NULL,
    PRIMARY KEY (role_a, role_b),
    CONSTRAINT fk_sod_rule_role_a FOREIGN KEY (role_a) REFERENCES role (role_id),
    CONSTRAINT fk_sod_rule_role_b FOREIGN KEY (role_b) REFERENCES role (role_id)
);
COMMENT ON TABLE sod_rule IS 'Segregation of duties: pairs of roles (role_a < role_b) that one account must never hold together.';

CREATE TABLE dept_birthright_role (
    dept_id bigint NOT NULL,
    role_id bigint NOT NULL,
    PRIMARY KEY (dept_id, role_id),
    CONSTRAINT fk_dept_birthright_role_dept_id FOREIGN KEY (dept_id) REFERENCES department (dept_id),
    CONSTRAINT fk_dept_birthright_role_role_id FOREIGN KEY (role_id) REFERENCES role (role_id)
);
COMMENT ON TABLE dept_birthright_role IS 'Roles every member of a department receives automatically on joiner and mover.';

CREATE TABLE lifecycle_event (
    event_id     bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    person_id    bigint      NOT NULL,
    event_type   text        NOT NULL,
    old_dept_id  bigint      NULL,
    new_dept_id  bigint      NULL,
    effective_at timestamptz NOT NULL DEFAULT now(),
    processed_at timestamptz NULL,
    CONSTRAINT fk_lifecycle_event_person_id   FOREIGN KEY (person_id)   REFERENCES person (person_id),
    CONSTRAINT fk_lifecycle_event_old_dept_id FOREIGN KEY (old_dept_id) REFERENCES department (dept_id),
    CONSTRAINT fk_lifecycle_event_new_dept_id FOREIGN KEY (new_dept_id) REFERENCES department (dept_id)
);
COMMENT ON TABLE lifecycle_event IS 'History of every joiner, mover and leaver and when it was processed.';

-- ---------------------------------------------------------------- security events (range partitioned by month, UTC)
CREATE TABLE security_event (
    event_id    bigint      GENERATED BY DEFAULT AS IDENTITY,
    occurred_at timestamptz NOT NULL,
    account_id  bigint      NULL,
    event_type  text        NOT NULL,
    source_ip   inet        NULL,
    outcome     text        NOT NULL,
    details     jsonb       NOT NULL DEFAULT '{}',
    PRIMARY KEY (event_id, occurred_at),
    CONSTRAINT fk_security_event_account_id FOREIGN KEY (account_id) REFERENCES account (account_id)
) PARTITION BY RANGE (occurred_at);
COMMENT ON TABLE security_event IS 'Authentication and access events, range-partitioned by month on occurred_at (UTC bounds).';

CREATE TABLE security_event_2026_05 PARTITION OF security_event FOR VALUES FROM ('2026-05-01 00:00:00+00') TO ('2026-06-01 00:00:00+00');
CREATE TABLE security_event_2026_06 PARTITION OF security_event FOR VALUES FROM ('2026-06-01 00:00:00+00') TO ('2026-07-01 00:00:00+00');
CREATE TABLE security_event_2026_07 PARTITION OF security_event FOR VALUES FROM ('2026-07-01 00:00:00+00') TO ('2026-08-01 00:00:00+00');
CREATE TABLE security_event_2026_08 PARTITION OF security_event FOR VALUES FROM ('2026-08-01 00:00:00+00') TO ('2026-09-01 00:00:00+00');
CREATE TABLE security_event_2026_09 PARTITION OF security_event FOR VALUES FROM ('2026-09-01 00:00:00+00') TO ('2026-10-01 00:00:00+00');
CREATE TABLE security_event_2026_10 PARTITION OF security_event FOR VALUES FROM ('2026-10-01 00:00:00+00') TO ('2026-11-01 00:00:00+00');
CREATE TABLE security_event_2026_11 PARTITION OF security_event FOR VALUES FROM ('2026-11-01 00:00:00+00') TO ('2026-12-01 00:00:00+00');
CREATE TABLE security_event_2026_12 PARTITION OF security_event FOR VALUES FROM ('2026-12-01 00:00:00+00') TO ('2027-01-01 00:00:00+00');
CREATE TABLE security_event_default PARTITION OF security_event DEFAULT;

COMMENT ON TABLE security_event_2026_05 IS 'security_event partition, May 2026 (UTC).';
COMMENT ON TABLE security_event_2026_06 IS 'security_event partition, June 2026 (UTC).';
COMMENT ON TABLE security_event_2026_07 IS 'security_event partition, July 2026 (UTC).';
COMMENT ON TABLE security_event_2026_08 IS 'security_event partition, August 2026 (UTC).';
COMMENT ON TABLE security_event_2026_09 IS 'security_event partition, September 2026 (UTC).';
COMMENT ON TABLE security_event_2026_10 IS 'security_event partition, October 2026 (UTC).';
COMMENT ON TABLE security_event_2026_11 IS 'security_event partition, November 2026 (UTC).';
COMMENT ON TABLE security_event_2026_12 IS 'security_event partition, December 2026 (UTC).';
COMMENT ON TABLE security_event_default IS 'security_event catch-all partition for rows outside the monthly ranges.';

-- ---------------------------------------------------------------- tamper-evident audit log
CREATE TABLE audit_log (
    seq         bigint      PRIMARY KEY,   -- assigned by iga.audit_write, deliberately not an identity column
    occurred_at timestamptz NOT NULL,
    actor       text        NOT NULL,
    action      text        NOT NULL,
    table_name  text        NOT NULL,
    row_pk      text        NOT NULL,
    old_row     jsonb       NULL,
    new_row     jsonb       NULL,
    prev_hash   bytea       NOT NULL,
    row_hash    bytea       NOT NULL
);
COMMENT ON TABLE audit_log IS 'Append-only, SHA-256 hash-chained record of changes to person, account and role_assignment.';

-- =============================================================================================
-- phase 4: access review (periodic recertification of role assignments)
-- A campaign is a review period. Each review_item asks one reviewer to decide, for one assignment,
-- whether the access is still needed ('keep') or not ('revoke'). Row-level security on review_item
-- (so a reviewer sees only their own items) is set up in 07_roles.sql.
-- =============================================================================================
CREATE TABLE review_campaign (
    campaign_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name        text   NOT NULL,
    starts_on   date   NOT NULL,
    ends_on     date   NOT NULL,
    CONSTRAINT uq_review_campaign_name UNIQUE (name),
    CONSTRAINT ck_review_campaign_dates CHECK (ends_on >= starts_on)
);
COMMENT ON TABLE review_campaign IS 'One access-review period (e.g. "2026 Q4 recertification"); owns many review_items.';

CREATE TABLE review_item (
    item_id       bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    campaign_id   bigint      NOT NULL,
    assignment_id bigint      NOT NULL,
    reviewer_id   bigint      NOT NULL,
    decision      text        NULL,
    decided_at    timestamptz NULL,
    CONSTRAINT fk_review_item_campaign_id   FOREIGN KEY (campaign_id)   REFERENCES review_campaign (campaign_id),
    CONSTRAINT fk_review_item_assignment_id FOREIGN KEY (assignment_id) REFERENCES role_assignment (assignment_id),
    CONSTRAINT fk_review_item_reviewer_id   FOREIGN KEY (reviewer_id)   REFERENCES person (person_id),
    CONSTRAINT uq_review_item_campaign_assignment UNIQUE (campaign_id, assignment_id),
    CONSTRAINT ck_review_item_decision CHECK (decision IN ('keep', 'revoke'))
);
COMMENT ON TABLE review_item IS 'One reviewer decision on one role assignment within a campaign; decision is NULL until the reviewer decides.';


-- ---------------------------------------------------------------- phase 5 tables (spec section 3.1, stretch)
-- btree_gist lets an exclusion constraint combine equality on a bigint with overlap on a range.
CREATE EXTENSION IF NOT EXISTS btree_gist SCHEMA public;

CREATE TABLE access_request (
    request_id    bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    requester_id  bigint      NOT NULL,
    account_id    bigint      NOT NULL,
    role_id       bigint      NOT NULL,
    justification text        NOT NULL,
    status        text        NOT NULL DEFAULT 'pending',
    decided_by    bigint      NULL,
    decided_at    timestamptz NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT fk_access_request_requester_id FOREIGN KEY (requester_id) REFERENCES person (person_id),
    CONSTRAINT fk_access_request_account_id   FOREIGN KEY (account_id)   REFERENCES account (account_id),
    CONSTRAINT fk_access_request_role_id      FOREIGN KEY (role_id)      REFERENCES role (role_id),
    CONSTRAINT fk_access_request_decided_by   FOREIGN KEY (decided_by)   REFERENCES person (person_id),
    CONSTRAINT ck_access_request_status CHECK (status IN ('pending', 'approved', 'rejected', 'withdrawn')),
    -- nobody decides their own request
    CONSTRAINT ck_access_request_no_self_approval CHECK (decided_by IS NULL OR decided_by <> requester_id),
    -- a decided request names who decided and when; a pending one names neither
    CONSTRAINT ck_access_request_decision CHECK (
        (status IN ('pending', 'withdrawn') AND decided_by IS NULL AND decided_at IS NULL)
     OR (status IN ('approved', 'rejected') AND decided_by IS NOT NULL AND decided_at IS NOT NULL))
);
COMMENT ON TABLE access_request IS 'A request for a role on an account; the decider must be a different person (CHECK).';
ALTER TABLE role_assignment ADD CONSTRAINT fk_role_assignment_request_id
    FOREIGN KEY (request_id) REFERENCES access_request (request_id);

CREATE TABLE privileged_session (
    session_id  bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id  bigint      NOT NULL,
    role_id     bigint      NOT NULL,
    approved_by bigint      NOT NULL,
    reason      text        NOT NULL,
    during      tstzrange   NOT NULL,
    ended_at    timestamptz NULL,
    CONSTRAINT fk_privileged_session_account_id  FOREIGN KEY (account_id)  REFERENCES account (account_id),
    CONSTRAINT fk_privileged_session_role_id     FOREIGN KEY (role_id)     REFERENCES role (role_id),
    CONSTRAINT fk_privileged_session_approved_by FOREIGN KEY (approved_by) REFERENCES person (person_id),
    CONSTRAINT ck_privileged_session_range CHECK (NOT isempty(during) AND lower(during) IS NOT NULL AND upper(during) IS NOT NULL),
    -- one account cannot have two overlapping privileged sessions (ended sessions no longer count)
    CONSTRAINT ex_privileged_session_no_overlap EXCLUDE USING gist (account_id WITH =, during WITH &&) WHERE (ended_at IS NULL)
);
COMMENT ON TABLE privileged_session IS 'Time-boxed elevated access for one account; an EXCLUDE constraint forbids overlapping open sessions.';
COMMIT;
