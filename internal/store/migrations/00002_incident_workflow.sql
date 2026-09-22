-- +goose Up
CREATE TABLE IF NOT EXISTS incidents (
    audit_id bigint PRIMARY KEY REFERENCES audits(id) ON DELETE CASCADE,
    status text NOT NULL CHECK (status IN ('new', 'investigating', 'pending_business', 'resolved')),
    assignee text NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS incidents_status_updated_at_idx ON incidents (status, updated_at DESC);

CREATE TABLE IF NOT EXISTS incident_notes (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    audit_id bigint NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    author text NOT NULL,
    body text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS incident_notes_audit_created_at_idx ON incident_notes (audit_id, created_at DESC);

-- +goose Down
DROP TABLE IF EXISTS incident_notes;
DROP TABLE IF EXISTS incidents;
