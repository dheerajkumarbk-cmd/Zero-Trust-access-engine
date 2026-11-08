-- V001: the directory of people. One row per person, and one row per console role that person holds.
-- Standard SQL only. A leaver is marked DISABLED and never deleted, so their history stays whole: the lab user
-- is not even allowed to delete a person.

CREATE TABLE directory_person (
    person_id     VARCHAR(32)  NOT NULL,
    display_name  VARCHAR(100) NOT NULL,
    department    VARCHAR(60)  NOT NULL,
    business_role VARCHAR(60)  NOT NULL,
    status        VARCHAR(10)  NOT NULL,
    source        VARCHAR(10)  NOT NULL,
    created_at    TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at    TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_directory_person PRIMARY KEY (person_id),
    CONSTRAINT ck_person_status CHECK (status IN ('ACTIVE', 'DISABLED')),
    CONSTRAINT ck_person_source CHECK (source IN ('SEED', 'HR')),
    CONSTRAINT ck_person_id_length CHECK (CHAR_LENGTH(person_id) >= 2),
    CONSTRAINT ck_person_name CHECK (CHAR_LENGTH(TRIM(display_name)) > 0)
);

CREATE TABLE directory_person_role (
    person_id    VARCHAR(32) NOT NULL,
    console_role VARCHAR(10) NOT NULL,
    CONSTRAINT pk_directory_person_role PRIMARY KEY (person_id, console_role),
    CONSTRAINT fk_person_role_person FOREIGN KEY (person_id) REFERENCES directory_person (person_id),
    CONSTRAINT ck_console_role CHECK (console_role IN ('ANALYST', 'LEAD', 'ADMIN', 'USER', 'HR'))
);

-- The running lab signs in as dwarpal_app: rows only, never tables.
GRANT SELECT, INSERT, UPDATE ON directory_person TO dwarpal_app;
GRANT SELECT, INSERT, DELETE ON directory_person_role TO dwarpal_app;
