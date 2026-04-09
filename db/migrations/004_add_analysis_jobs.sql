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

CREATE INDEX IF NOT EXISTS idx_analysis_jobs_user_id_created_at
  ON analysis_jobs(user_id, created_at DESC);
