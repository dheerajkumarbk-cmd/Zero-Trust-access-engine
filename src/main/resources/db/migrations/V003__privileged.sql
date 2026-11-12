-- V003: privileged changes. An administrator asks for a change that only a DIFFERENT administrator may decide: to create
-- an administrator account, to give or take away the administrator role, or to change their own access. They reuse the
-- request table, so the history of who asked, who decided and why stays in one place. Standard SQL only.

ALTER TABLE access_request DROP CONSTRAINT ck_request_kind;
ALTER TABLE access_request ALTER COLUMN kind SET DATA TYPE VARCHAR(16);
ALTER TABLE access_request ADD CONSTRAINT ck_request_kind CHECK (kind IN ('JOINER', 'LEAVER', 'ACCESS', 'CREATE_ADMIN', 'ADD_ADMIN', 'REMOVE_ADMIN', 'OWN_ACCESS'));
ALTER TABLE access_request ADD CONSTRAINT ck_request_admin_create CHECK (kind <> 'CREATE_ADMIN' OR (display_name IS NOT NULL AND department IS NOT NULL AND business_role IS NOT NULL));

-- A person made by an approved administrator request is not an HR joiner and not a seed person.
ALTER TABLE directory_person DROP CONSTRAINT ck_person_source;
ALTER TABLE directory_person ADD CONSTRAINT ck_person_source CHECK (source IN ('SEED', 'HR', 'ADMIN'));
