-- V002: the access process. A catalogue of things a person can be given, a default set per business role, requests
-- (a joiner, a leaver, or somebody asking for more), one grant record per item, and the approvals a sensitive grant
-- needs. Standard SQL only. Nothing is ever deleted: a removed grant is marked REMOVED, a refused one REJECTED, so the
-- history of who had what, and why it ended, stays whole.

CREATE TABLE access_item (
    item_id      VARCHAR(30)  NOT NULL,
    label        VARCHAR(80)  NOT NULL,
    description  VARCHAR(200) NOT NULL,
    sensitivity  VARCHAR(6)   NOT NULL,
    console_role VARCHAR(10),
    CONSTRAINT pk_access_item PRIMARY KEY (item_id),
    CONSTRAINT ck_item_sensitivity CHECK (sensitivity IN ('SIMPLE', 'HARD')),
    CONSTRAINT ck_item_console_role CHECK (console_role IS NULL OR console_role IN ('ANALYST', 'LEAD', 'USER'))
);

CREATE TABLE access_role_template (
    business_role VARCHAR(60) NOT NULL,
    item_id       VARCHAR(30) NOT NULL,
    CONSTRAINT pk_access_role_template PRIMARY KEY (business_role, item_id),
    CONSTRAINT fk_template_item FOREIGN KEY (item_id) REFERENCES access_item (item_id)
);

CREATE TABLE access_request (
    request_id      VARCHAR(40)  NOT NULL,
    kind            VARCHAR(8)   NOT NULL,
    status          VARCHAR(10)  NOT NULL,
    subject_id      VARCHAR(32)  NOT NULL,
    requested_by    VARCHAR(32)  NOT NULL,
    reason          VARCHAR(300) NOT NULL,
    display_name    VARCHAR(100),
    department      VARCHAR(60),
    business_role   VARCHAR(60),
    decided_by      VARCHAR(32),
    decision_reason VARCHAR(300),
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_access_request PRIMARY KEY (request_id),
    CONSTRAINT ck_request_kind CHECK (kind IN ('JOINER', 'LEAVER', 'ACCESS')),
    CONSTRAINT ck_request_status CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'DONE', 'CANCELLED')),
    CONSTRAINT ck_request_joiner CHECK (kind <> 'JOINER'
        OR (display_name IS NOT NULL AND department IS NOT NULL AND business_role IS NOT NULL))
);

CREATE TABLE access_request_item (
    request_id VARCHAR(40) NOT NULL,
    item_id    VARCHAR(30) NOT NULL,
    CONSTRAINT pk_access_request_item PRIMARY KEY (request_id, item_id),
    CONSTRAINT fk_request_item_request FOREIGN KEY (request_id) REFERENCES access_request (request_id),
    CONSTRAINT fk_request_item_item FOREIGN KEY (item_id) REFERENCES access_item (item_id)
);

CREATE TABLE access_grant (
    grant_id       VARCHAR(40)  NOT NULL,
    request_id     VARCHAR(40)  NOT NULL,
    person_id      VARCHAR(32)  NOT NULL,
    item_id        VARCHAR(30)  NOT NULL,
    state          VARCHAR(8)   NOT NULL,
    created_at     TIMESTAMP WITH TIME ZONE NOT NULL,
    granted_at     TIMESTAMP WITH TIME ZONE,
    removed_at     TIMESTAMP WITH TIME ZONE,
    removed_reason VARCHAR(100),
    CONSTRAINT pk_access_grant PRIMARY KEY (grant_id),
    CONSTRAINT fk_grant_request FOREIGN KEY (request_id) REFERENCES access_request (request_id),
    CONSTRAINT fk_grant_person FOREIGN KEY (person_id) REFERENCES directory_person (person_id),
    CONSTRAINT fk_grant_item FOREIGN KEY (item_id) REFERENCES access_item (item_id),
    CONSTRAINT ck_grant_state CHECK (state IN ('PENDING', 'ACTIVE', 'REJECTED', 'REMOVED')),
    CONSTRAINT ck_grant_active CHECK (state <> 'ACTIVE' OR granted_at IS NOT NULL)
);

CREATE TABLE access_approval (
    grant_id      VARCHAR(40) NOT NULL,
    approver_role VARCHAR(5)  NOT NULL,
    approver_id   VARCHAR(32),
    decision      VARCHAR(8)  NOT NULL,
    reason        VARCHAR(300),
    decided_at    TIMESTAMP WITH TIME ZONE,
    CONSTRAINT pk_access_approval PRIMARY KEY (grant_id, approver_role),
    CONSTRAINT fk_approval_grant FOREIGN KEY (grant_id) REFERENCES access_grant (grant_id),
    CONSTRAINT ck_approval_role CHECK (approver_role IN ('ADMIN', 'LEAD')),
    CONSTRAINT ck_approval_decision CHECK (decision IN ('PENDING', 'APPROVED', 'REJECTED')),
    CONSTRAINT ck_approval_decided CHECK (decision = 'PENDING' OR (approver_id IS NOT NULL AND decided_at IS NOT NULL))
);

-- What can be given. SIMPLE is approved automatically once the directory shows the person is active; HARD needs the
-- administrator and a lead. The three console items are what the console's own roles are made of.
INSERT INTO access_item (item_id, label, description, sensitivity, console_role) VALUES
    ('email', 'Company email', 'A mailbox and calendar.', 'SIMPLE', NULL),
    ('wiki', 'Internal wiki', 'Read and edit the internal wiki.', 'SIMPLE', NULL),
    ('vpn', 'VPN', 'Remote access to the office network.', 'SIMPLE', NULL),
    ('crm', 'Customer records (CRM)', 'Read customer records.', 'SIMPLE', NULL),
    ('finance', 'Finance system', 'Payments, ledgers and payroll.', 'HARD', NULL),
    ('prod-db', 'Production database', 'Direct access to live data.', 'HARD', NULL),
    ('console', 'Dwarpal console', 'Sign in and see your own page.', 'SIMPLE', 'USER'),
    ('console-analyst', 'SOC analyst console', 'Work the alert queue, cases, hunt and entities.', 'HARD', 'ANALYST'),
    ('console-lead', 'SOC lead console', 'Everything an analyst has, plus reports and approvals.', 'HARD', 'LEAD');

-- The default set for each business role: pre-ticked for the administrator, who can still tick or untick.
INSERT INTO access_role_template (business_role, item_id) VALUES
    ('Security analyst', 'email'), ('Security analyst', 'wiki'), ('Security analyst', 'vpn'),
    ('Security analyst', 'console'), ('Security analyst', 'console-analyst'),
    ('SOC lead', 'email'), ('SOC lead', 'wiki'), ('SOC lead', 'vpn'),
    ('SOC lead', 'console'), ('SOC lead', 'console-lead'),
    ('Finance officer', 'email'), ('Finance officer', 'wiki'), ('Finance officer', 'console'),
    ('Finance officer', 'finance'),
    ('HR officer', 'email'), ('HR officer', 'wiki'), ('HR officer', 'console'),
    ('Software engineer', 'email'), ('Software engineer', 'wiki'), ('Software engineer', 'vpn'),
    ('Software engineer', 'console'),
    ('Support agent', 'email'), ('Support agent', 'wiki'), ('Support agent', 'crm'), ('Support agent', 'console');

-- The running lab signs in as dwarpal_app: rows only. It may not change the catalogue or a template, and it may not
-- delete a request, a grant or an approval: history stays.
GRANT SELECT ON access_item TO dwarpal_app;
GRANT SELECT ON access_role_template TO dwarpal_app;
GRANT SELECT, INSERT, UPDATE ON access_request TO dwarpal_app;
GRANT SELECT, INSERT ON access_request_item TO dwarpal_app;
GRANT SELECT, INSERT, UPDATE ON access_grant TO dwarpal_app;
GRANT SELECT, INSERT, UPDATE ON access_approval TO dwarpal_app;
