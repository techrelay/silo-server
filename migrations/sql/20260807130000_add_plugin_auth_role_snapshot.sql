-- +goose Up
ALTER TABLE plugin_auth_identities
    ADD COLUMN IF NOT EXISTS managed_role_snapshot JSONB;

-- +goose Down
ALTER TABLE plugin_auth_identities
    DROP COLUMN IF EXISTS managed_role_snapshot;
