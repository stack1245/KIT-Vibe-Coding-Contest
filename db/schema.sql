PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS schema_migrations (
  name TEXT PRIMARY KEY,
  applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT,
  display_name TEXT NOT NULL,
  github_id TEXT UNIQUE,
  github_login TEXT,
  github_avatar_url TEXT,
  github_profile_url TEXT,
  github_access_token TEXT,
  github_token_scope TEXT,
  github_token_updated_at TEXT,
  auth_provider TEXT NOT NULL DEFAULT 'local',
  last_login_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS email_verifications (
  email TEXT PRIMARY KEY,
  code_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS analysis_reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  application_type TEXT NOT NULL,
  summary TEXT NOT NULL,
  application_report TEXT NOT NULL,
  result_mode TEXT NOT NULL,
  overall_severity TEXT NOT NULL,
  findings_count INTEGER NOT NULL DEFAULT 0,
  findings_json TEXT NOT NULL,
  source_files_json TEXT NOT NULL,
  share_token TEXT UNIQUE,
  share_enabled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS analysis_jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  status TEXT NOT NULL,
  stage TEXT NOT NULL,
  progress_percent INTEGER NOT NULL DEFAULT 0,
  message TEXT NOT NULL DEFAULT '',
  report_id INTEGER,
  accepted_files_json TEXT NOT NULL DEFAULT '[]',
  rejected_files_json TEXT NOT NULL DEFAULT '[]',
  error_message TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (report_id) REFERENCES analysis_reports(id) ON DELETE SET NULL
);

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

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_github_id ON users(github_id);
CREATE INDEX IF NOT EXISTS idx_analysis_reports_user_id_created_at
  ON analysis_reports(user_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_analysis_reports_share_token
  ON analysis_reports(share_token);
CREATE INDEX IF NOT EXISTS idx_analysis_jobs_user_id_created_at
  ON analysis_jobs(user_id, created_at DESC);
