ALTER TABLE users
    ADD CONSTRAINT users_id_organization_unique UNIQUE (id, organization_id);

ALTER TABLE groups
    ADD CONSTRAINT groups_id_organization_unique UNIQUE (id, organization_id);

ALTER TABLE oidc_clients
    ADD CONSTRAINT oidc_clients_id_organization_unique UNIQUE (id, organization_id);

ALTER TABLE auth_sessions
    ADD CONSTRAINT auth_sessions_id_organization_unique UNIQUE (id, organization_id),
    ADD CONSTRAINT auth_sessions_id_user_organization_unique UNIQUE (id, user_id, organization_id);

ALTER TABLE memberships
    DROP CONSTRAINT IF EXISTS memberships_user_id_fkey,
    DROP CONSTRAINT IF EXISTS memberships_group_id_fkey,
    ADD CONSTRAINT memberships_user_organization_fk
        FOREIGN KEY (user_id, organization_id)
        REFERENCES users(id, organization_id)
        ON DELETE CASCADE,
    ADD CONSTRAINT memberships_group_organization_fk
        FOREIGN KEY (group_id, organization_id)
        REFERENCES groups(id, organization_id)
        ON DELETE CASCADE;

ALTER TABLE auth_sessions
    DROP CONSTRAINT IF EXISTS auth_sessions_user_id_fkey,
    ADD CONSTRAINT auth_sessions_user_organization_fk
        FOREIGN KEY (user_id, organization_id)
        REFERENCES users(id, organization_id)
        ON DELETE CASCADE;

ALTER TABLE consent_grants
    DROP CONSTRAINT IF EXISTS consent_grants_user_id_fkey,
    DROP CONSTRAINT IF EXISTS consent_grants_client_id_fkey,
    ADD CONSTRAINT consent_grants_user_organization_fk
        FOREIGN KEY (user_id, organization_id)
        REFERENCES users(id, organization_id)
        ON DELETE CASCADE,
    ADD CONSTRAINT consent_grants_client_organization_fk
        FOREIGN KEY (client_id, organization_id)
        REFERENCES oidc_clients(id, organization_id)
        ON DELETE CASCADE;

ALTER TABLE authorization_codes
    DROP CONSTRAINT IF EXISTS authorization_codes_user_id_fkey,
    DROP CONSTRAINT IF EXISTS authorization_codes_session_id_fkey,
    DROP CONSTRAINT IF EXISTS authorization_codes_client_id_fkey,
    ADD CONSTRAINT authorization_codes_user_organization_fk
        FOREIGN KEY (user_id, organization_id)
        REFERENCES users(id, organization_id)
        ON DELETE CASCADE,
    ADD CONSTRAINT authorization_codes_session_user_organization_fk
        FOREIGN KEY (session_id, user_id, organization_id)
        REFERENCES auth_sessions(id, user_id, organization_id)
        ON DELETE CASCADE,
    ADD CONSTRAINT authorization_codes_client_organization_fk
        FOREIGN KEY (client_id, organization_id)
        REFERENCES oidc_clients(id, organization_id)
        ON DELETE CASCADE;

ALTER TABLE access_tokens
    DROP CONSTRAINT IF EXISTS access_tokens_user_id_fkey,
    DROP CONSTRAINT IF EXISTS access_tokens_client_id_fkey,
    ADD CONSTRAINT access_tokens_user_organization_fk
        FOREIGN KEY (user_id, organization_id)
        REFERENCES users(id, organization_id)
        ON DELETE CASCADE,
    ADD CONSTRAINT access_tokens_client_organization_fk
        FOREIGN KEY (client_id, organization_id)
        REFERENCES oidc_clients(id, organization_id)
        ON DELETE CASCADE;

ALTER TABLE refresh_tokens
    DROP CONSTRAINT IF EXISTS refresh_tokens_user_id_fkey,
    DROP CONSTRAINT IF EXISTS refresh_tokens_client_id_fkey,
    ADD CONSTRAINT refresh_tokens_user_organization_fk
        FOREIGN KEY (user_id, organization_id)
        REFERENCES users(id, organization_id)
        ON DELETE CASCADE,
    ADD CONSTRAINT refresh_tokens_client_organization_fk
        FOREIGN KEY (client_id, organization_id)
        REFERENCES oidc_clients(id, organization_id)
        ON DELETE CASCADE;

ALTER TABLE mfa_credentials
    DROP CONSTRAINT IF EXISTS mfa_credentials_user_id_fkey,
    ADD CONSTRAINT mfa_credentials_user_organization_fk
        FOREIGN KEY (user_id, organization_id)
        REFERENCES users(id, organization_id)
        ON DELETE CASCADE;

ALTER TABLE account_tokens
    DROP CONSTRAINT IF EXISTS account_tokens_user_id_fkey,
    DROP CONSTRAINT IF EXISTS account_tokens_created_by_user_id_fkey,
    ADD CONSTRAINT account_tokens_user_organization_fk
        FOREIGN KEY (user_id, organization_id)
        REFERENCES users(id, organization_id)
        ON DELETE CASCADE,
    ADD CONSTRAINT account_tokens_created_by_user_organization_fk
        FOREIGN KEY (created_by_user_id, organization_id)
        REFERENCES users(id, organization_id)
        ON DELETE SET NULL (created_by_user_id);
