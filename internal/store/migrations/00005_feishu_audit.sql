-- +goose Up
CREATE TABLE feishu_audit_events (
    unique_id text PRIMARY KEY,
    event_time timestamptz NOT NULL,
    event_name text NOT NULL,
    event_module integer NOT NULL,
    operator_type integer NOT NULL,
    operator_value text NOT NULL DEFAULT '',
    object_type text NOT NULL DEFAULT '',
    object_value text NOT NULL DEFAULT '',
    imported_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX feishu_audit_events_time_idx ON feishu_audit_events (event_time DESC);

CREATE TABLE feishu_sync_state (
    source text PRIMARY KEY,
    last_end timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE feishu_sync_state;
DROP TABLE feishu_audit_events;
