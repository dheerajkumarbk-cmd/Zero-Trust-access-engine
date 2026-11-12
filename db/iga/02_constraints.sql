-- 02_constraints.sql : named CHECK / UNIQUE constraints and the live-assignment partial unique index.
-- Run after 01_schema.sql (which drops and recreates the schema, so this file is re-runnable after 01).
\set ON_ERROR_STOP on

BEGIN;
SET search_path = iga, public;

-- department
ALTER TABLE department ADD CONSTRAINT uq_department_name UNIQUE (name);

-- person
ALTER TABLE person ADD CONSTRAINT uq_person_employee_no UNIQUE (employee_no);
ALTER TABLE person ADD CONSTRAINT uq_person_email UNIQUE (email);
ALTER TABLE person ADD CONSTRAINT ck_person_status CHECK (status IN ('active', 'on_leave', 'terminated'));
ALTER TABLE person ADD CONSTRAINT ck_person_dates CHECK (end_date IS NULL OR end_date >= hire_date);
ALTER TABLE person ADD CONSTRAINT ck_person_terminated_end CHECK (status <> 'terminated' OR end_date IS NOT NULL);

-- system
ALTER TABLE system ADD CONSTRAINT uq_system_name UNIQUE (name);
ALTER TABLE system ADD CONSTRAINT ck_system_criticality CHECK (criticality BETWEEN 1 AND 4);

-- account
ALTER TABLE account ADD CONSTRAINT uq_account_system_username UNIQUE (system_id, username);
ALTER TABLE account ADD CONSTRAINT ck_account_type CHECK (account_type IN ('human', 'service', 'ai_agent'));
ALTER TABLE account ADD CONSTRAINT ck_account_status CHECK (status IN ('active', 'disabled'));
ALTER TABLE account ADD CONSTRAINT ck_account_owner CHECK (
    (account_type = 'human' AND person_id IS NOT NULL)
    OR (account_type IN ('service', 'ai_agent') AND owner_person_id IS NOT NULL)
);

-- role / entitlement
ALTER TABLE role ADD CONSTRAINT uq_role_system_name UNIQUE (system_id, name);
ALTER TABLE entitlement ADD CONSTRAINT uq_entitlement UNIQUE (system_id, action, resource);

-- role_assignment: validity window, and at most one live (not revoked) grant per account and role
ALTER TABLE role_assignment ADD CONSTRAINT ck_assignment_validity CHECK (valid_to IS NULL OR valid_to > valid_from);
CREATE UNIQUE INDEX uq_assignment_live ON role_assignment (account_id, role_id) WHERE revoked_at IS NULL;

-- sod_rule: store each pair once, smaller role id first
ALTER TABLE sod_rule ADD CONSTRAINT ck_sod_order CHECK (role_a < role_b);

-- lifecycle_event
ALTER TABLE lifecycle_event ADD CONSTRAINT ck_lifecycle_type CHECK (event_type IN ('joiner', 'mover', 'leaver'));

-- security_event (propagates to all partitions)
ALTER TABLE security_event ADD CONSTRAINT ck_event_outcome CHECK (outcome IN ('success', 'failure'));

-- audit_log
ALTER TABLE audit_log ADD CONSTRAINT ck_audit_action CHECK (action IN ('INSERT', 'UPDATE', 'DELETE'));
ALTER TABLE audit_log ADD CONSTRAINT ck_audit_hash_len CHECK (octet_length(row_hash) = 32 AND octet_length(prev_hash) = 32);

COMMIT;
