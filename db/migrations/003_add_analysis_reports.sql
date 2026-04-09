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
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_analysis_reports_user_id_created_at
  ON analysis_reports(user_id, created_at DESC);
