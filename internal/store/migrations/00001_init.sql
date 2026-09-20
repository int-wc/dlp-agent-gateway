-- +goose Up
CREATE TABLE IF NOT EXISTS user_statuses (
    actor text PRIMARY KEY,
    status text NOT NULL CHECK (status IN ('normal', 'privileged', 'departing')),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS policies (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    keyword text NOT NULL,
    action text NOT NULL CHECK (action IN ('review', 'block')),
    scope text NOT NULL CHECK (scope IN ('all', 'internal', 'external')),
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audits (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT now(),
    actor text NOT NULL,
    destination text NOT NULL,
    filename text NOT NULL,
    sha256 text NOT NULL DEFAULT '',
    size_bytes bigint NOT NULL DEFAULT 0,
    action text NOT NULL CHECK (action IN ('allow', 'review', 'block')),
    reasons text[] NOT NULL DEFAULT '{}',
    signals text[] NOT NULL DEFAULT '{}',
    model_status text NOT NULL DEFAULT '',
    forwarded boolean NOT NULL DEFAULT false,
    transfer_status text NOT NULL DEFAULT 'not_requested',
    upstream_status integer
);
CREATE INDEX IF NOT EXISTS audits_created_at_idx ON audits (created_at DESC);
CREATE INDEX IF NOT EXISTS audits_actor_created_at_idx ON audits (actor, created_at DESC);
CREATE INDEX IF NOT EXISTS audits_action_created_at_idx ON audits (action, created_at DESC);

CREATE TABLE IF NOT EXISTS exceptions (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    audit_id bigint NOT NULL UNIQUE REFERENCES audits(id),
    actor text NOT NULL,
    destination text NOT NULL,
    sha256 text NOT NULL,
    justification text NOT NULL,
    status text NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz
);
CREATE INDEX IF NOT EXISTS exceptions_lookup_idx
    ON exceptions (actor, destination, sha256, status, expires_at);

CREATE TABLE IF NOT EXISTS feedback (
    audit_id bigint PRIMARY KEY REFERENCES audits(id),
    verdict text NOT NULL CHECK (verdict IN ('true_positive', 'false_positive')),
    note text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS admin_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT now(),
    event text NOT NULL,
    target text NOT NULL
);
CREATE INDEX IF NOT EXISTS admin_events_created_at_idx ON admin_events (created_at DESC);

-- +goose Down
DROP TABLE IF EXISTS admin_events;
DROP TABLE IF EXISTS feedback;
DROP TABLE IF EXISTS exceptions;
DROP TABLE IF EXISTS audits;
DROP TABLE IF EXISTS policies;
DROP TABLE IF EXISTS user_statuses;

