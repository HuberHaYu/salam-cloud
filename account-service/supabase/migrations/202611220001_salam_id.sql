-- Server-only working state. GitHub remains the encrypted checkpoint repository.
CREATE SCHEMA IF NOT EXISTS salam_private;
REVOKE ALL ON SCHEMA salam_private FROM PUBLIC, anon, authenticated;
CREATE TABLE IF NOT EXISTS salam_private.state (
  key text PRIMARY KEY,
  value jsonb NOT NULL
);
REVOKE ALL ON salam_private.state FROM PUBLIC, anon, authenticated;
ALTER TABLE salam_private.state ENABLE ROW LEVEL SECURITY;
-- No client policy: only the trusted function's database connection can access this state.
CREATE TABLE IF NOT EXISTS salam_private.archive_lease (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  until_at timestamptz NOT NULL DEFAULT '-infinity',
  holder text
);
REVOKE ALL ON salam_private.archive_lease FROM PUBLIC, anon, authenticated;
ALTER TABLE salam_private.archive_lease ENABLE ROW LEVEL SECURITY;
INSERT INTO salam_private.archive_lease(singleton) VALUES(true) ON CONFLICT DO NOTHING;
