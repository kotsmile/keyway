-- +goose Up
-- keyway holds no payloads except in its own Store. What lives here is what a
-- secret manager cannot answer: who owns a secret, who may see it, and who
-- looked.
--
-- Every table keys a secret by (store, name) as text, because the secret lives
-- in somebody else's system and there is no foreign key to point at. The API
-- addresses secrets by uuid; resolving one to a (store, name) is the service's
-- job, not the schema's.

-- Who a secret belongs to.
--
-- At most one row per secret, because two owners is a list to argue about
-- rather than an answer to "who do I ask about this".
CREATE TABLE ownership (
    store      TEXT        NOT NULL,
    secret     TEXT        NOT NULL,
    -- The owner's handle. Always a person: a group cannot own a secret,
    -- because an owner is who you ASK about one.
    owner      TEXT        NOT NULL,
    -- When they became the owner. Set on create, reset by a transfer, so it
    -- reads as "has held this since" rather than "was created then".
    since      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (store, secret)
);

CREATE INDEX ownership_by_owner ON ownership (owner);

-- A grant of sight of one secret to one subject.
CREATE TABLE delegations (
    id           UUID        PRIMARY KEY,
    store        TEXT        NOT NULL,
    secret       TEXT        NOT NULL,
    -- The kind is stored, never inferred from the shape of the name. Under a
    -- generic OIDC issuer a groups claim may yield bare names, so a team
    -- called `sre` and a person called `sre` would otherwise be one row
    -- (ADR-0003).
    subject_kind TEXT        NOT NULL CHECK (subject_kind IN ('user', 'group')),
    subject_id   TEXT        NOT NULL,
    -- What this grant opens. It is carried here rather than capped by the
    -- grantee's role: a delegation is self-describing (ADR-0002).
    level        TEXT        NOT NULL CHECK (level IN ('guest', 'read', 'write')),
    -- Narrows the grant to some entries of a kv secret; empty is the whole
    -- secret. This is what makes it safe to bundle a bot's credentials in one
    -- secret and still hand out one of them.
    keys         TEXT[]      NOT NULL DEFAULT '{}',
    granted_by   TEXT        NOT NULL,
    granted_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- NULL is indefinite, which is the common case, and is why it is nullable
    -- rather than defaulted to some arbitrary date.
    expires_at   TIMESTAMPTZ,
    -- Why it was granted: the sentence the next admin needs in order to decide
    -- whether it is still true.
    note         TEXT        NOT NULL DEFAULT ''
);

-- The question asked on every authorisation check: what is granted to this
-- caller, over this secret.
CREATE INDEX delegations_by_secret ON delegations (store, secret);
CREATE INDEX delegations_by_subject ON delegations (subject_kind, subject_id);

-- One subject may hold at most one grant per secret. A second would make
-- "what does this open" a max() over rows rather than an answer, and the UI
-- could not show a grant list that means anything.
CREATE UNIQUE INDEX delegations_one_per_subject
    ON delegations (store, secret, subject_kind, subject_id);

-- What happened. Append-only: there is no UPDATE or DELETE on this table
-- anywhere in the service.
CREATE TABLE audit (
    id        BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- The handle that acted.
    actor     TEXT        NOT NULL,
    -- The public half of the API token used, when one was. NULL for a browser
    -- session. Recorded so a row can name WHICH credential acted, which is
    -- what the id half of `kw-<id>-<secret>` exists for.
    via_token TEXT,
    action    TEXT        NOT NULL CHECK (action IN (
        'create', 'update', 'reveal', 'delete', 'delegate', 'revoke', 'transfer'
    )),
    store     TEXT        NOT NULL,
    secret    TEXT        NOT NULL,
    -- The backend version this row is about: created by an update, or read by
    -- a reveal. Empty for a delegation change.
    version   TEXT        NOT NULL DEFAULT '',
    -- Which kv entries the action touched. Never the values.
    keys      TEXT[]      NOT NULL DEFAULT '{}',
    -- The grantee, for a delegate or revoke — and the NEW owner, for a
    -- transfer.
    subject   TEXT        NOT NULL DEFAULT '',
    note      TEXT        NOT NULL DEFAULT ''
);

CREATE INDEX audit_by_secret ON audit (store, secret, at DESC);
CREATE INDEX audit_recent ON audit (at DESC);

-- Tokens keyway issued itself.
CREATE TABLE tokens (
    -- The public half of `kw-<id>-<secret>`, in the clear: it is not a secret,
    -- and it is what an audit row names.
    id         TEXT        PRIMARY KEY,
    -- sha256 of the secret half. The plaintext exists once, in the response
    -- that created it; a console that can re-show a token is a console that
    -- can leak every token it ever issued.
    hash       BYTEA       NOT NULL,
    -- The handle this token acts as. It carries no grants of its own.
    subject    TEXT        NOT NULL,
    -- Required, not defaulted: the name is the only thing that answers "can I
    -- delete this one" in six months, and a list of identical defaults answers
    -- nothing.
    name       TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- NULL never expires, deliberately, for the caller this exists for: an
    -- expiry on the credential a reconcile loop presents is an outage
    -- scheduled for a day nobody picked.
    expires_at TIMESTAMPTZ,
    -- Best-effort, for the person deciding whether a token is still needed.
    -- Never an authorisation input.
    last_used  TIMESTAMPTZ
);

CREATE INDEX tokens_by_subject ON tokens (subject);

-- What keyway remembers about a person between sign-ins.
--
-- An API token carries no claim, so without this it could not know which
-- groups its holder is in, and a grant to a team would be invisible to every
-- bot and every CI job (ADR-0004).
CREATE TABLE users (
    handle     TEXT        PRIMARY KEY,
    -- The groups claim as it stood at the last sign-in. Refreshed by every
    -- login, and replaced by a live lookup where a Directory is configured.
    groups     TEXT[]      NOT NULL DEFAULT '{}',
    -- Carried for display only; the handle is what everything keys on.
    email      TEXT        NOT NULL DEFAULT '',
    name       TEXT        NOT NULL DEFAULT '',
    last_login TIMESTAMPTZ NOT NULL DEFAULT now()
);
