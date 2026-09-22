-- +goose Up
ALTER TABLE policies ADD COLUMN mode text;
UPDATE policies SET mode = CASE WHEN enabled THEN 'enforce' ELSE 'draft' END;
ALTER TABLE policies ALTER COLUMN mode SET DEFAULT 'enforce';
ALTER TABLE policies ALTER COLUMN mode SET NOT NULL;
ALTER TABLE policies ADD CONSTRAINT policies_mode_check CHECK (mode IN ('draft', 'monitor', 'enforce'));

-- +goose Down
ALTER TABLE policies DROP CONSTRAINT IF EXISTS policies_mode_check;
ALTER TABLE policies DROP COLUMN IF EXISTS mode;
