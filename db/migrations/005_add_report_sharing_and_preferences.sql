ALTER TABLE analysis_reports ADD COLUMN share_token TEXT;
ALTER TABLE analysis_reports ADD COLUMN share_enabled INTEGER NOT NULL DEFAULT 0;

CREATE UNIQUE INDEX IF NOT EXISTS idx_analysis_reports_share_token
  ON analysis_reports(share_token);

CREATE TABLE IF NOT EXISTS user_preferences (
  user_id INTEGER PRIMARY KEY,
  preferred_landing TEXT NOT NULL DEFAULT '/dashboard',
  default_analysis_sort TEXT NOT NULL DEFAULT 'latest',
  email_updates INTEGER NOT NULL DEFAULT 1,
  dashboard_digest INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
