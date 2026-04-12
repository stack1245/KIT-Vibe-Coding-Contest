CREATE TABLE IF NOT EXISTS report_quiz_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  report_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  finding_key TEXT NOT NULL,
  finding_title TEXT NOT NULL,
  session_token TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'ready',
  quiz_json TEXT NOT NULL,
  flag_value TEXT NOT NULL,
  generated_at TEXT NOT NULL,
  solved_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (report_id) REFERENCES analysis_reports(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE (report_id, finding_key)
);

CREATE INDEX IF NOT EXISTS idx_report_quiz_sessions_report_id
  ON report_quiz_sessions(report_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_report_quiz_sessions_user_id
  ON report_quiz_sessions(user_id, created_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS idx_report_quiz_sessions_session_token
  ON report_quiz_sessions(session_token);
