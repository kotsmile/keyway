-- +goose Up
-- keyway's own Store: the one backend where keyway holds a payload at all.
--
-- It exists so keyway is usable with no cloud account, which is what makes a
-- one-command quickstart possible. Everything here is scoped by `store`,
-- because a deployment may declare more than one `type: keyway` Store — a
-- sandbox beside a real one — and they must not see each other's secrets.

CREATE TABLE own_secrets (
    store       TEXT        NOT NULL,
    name        TEXT        NOT NULL,
    -- Labels and annotations as this Store's own metadata. Other backends
    -- carry these natively; here keyway is the backend, so it stores them.
    labels      JSONB       NOT NULL DEFAULT '{}',
    annotations JSONB       NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (store, name)
);

CREATE TABLE own_versions (
    store      TEXT        NOT NULL,
    name       TEXT        NOT NULL,
    -- Version ids are per secret and monotonic, spelled as text because that
    -- is what the SecretManager trait speaks and what every other backend
    -- reports.
    version    BIGINT      NOT NULL,
    -- The sealed payload. keyway never writes a plaintext here, and there is
    -- no column it could go in.
    ciphertext BYTEA       NOT NULL,
    nonce      BYTEA       NOT NULL,
    -- Which key sealed this version. Per version rather than per Store, so
    -- rotating the active key does not make yesterday's payloads unreadable.
    key_id     TEXT        NOT NULL,
    state      TEXT        NOT NULL DEFAULT 'enabled'
        CHECK (state IN ('enabled', 'disabled', 'destroyed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (store, name, version),
    FOREIGN KEY (store, name) REFERENCES own_secrets (store, name) ON DELETE CASCADE
);

-- "The newest version of this secret" is the hot read: every unqualified
-- access resolves through it.
CREATE INDEX own_versions_latest ON own_versions (store, name, version DESC);

-- Which keys are still needed to open what this deployment holds. A rotation
-- is finished when this returns only the active id, and dropping a key before
-- then is what makes a payload unopenable.
CREATE INDEX own_versions_by_key ON own_versions (key_id);
