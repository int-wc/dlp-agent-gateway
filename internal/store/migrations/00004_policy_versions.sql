-- +goose Up
ALTER TABLE policies ADD COLUMN version bigint NOT NULL DEFAULT 1 CHECK (version >= 1);

CREATE TABLE policy_revisions (
    policy_id bigint NOT NULL REFERENCES policies(id),
    version bigint NOT NULL CHECK (version >= 1),
    keyword text NOT NULL,
    action text NOT NULL CHECK (action IN ('review', 'block')),
    scope text NOT NULL CHECK (scope IN ('all', 'internal', 'external')),
    mode text NOT NULL CHECK (mode IN ('draft', 'monitor', 'enforce')),
    changed_at timestamptz NOT NULL DEFAULT now(),
    changed_by text NOT NULL,
    change_type text NOT NULL CHECK (change_type IN ('migration', 'created', 'updated', 'rollback')),
    PRIMARY KEY (policy_id, version)
);

INSERT INTO policy_revisions(policy_id,version,keyword,action,scope,mode,changed_at,changed_by,change_type)
SELECT id,1,keyword,action,scope,mode,updated_at,'system','migration' FROM policies;

-- +goose Down
DROP TABLE policy_revisions;
ALTER TABLE policies DROP COLUMN version;
