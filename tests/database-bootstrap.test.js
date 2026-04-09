import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import { afterEach, describe, expect, it } from 'vitest';
import { initializeDatabase } from '../lib/server/database-bootstrap';

const tempDirectories = [];

function createTempDir() {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'phase-db-test-'));
  tempDirectories.push(tempDir);
  return tempDir;
}

afterEach(() => {
  while (tempDirectories.length > 0) {
    const tempDir = tempDirectories.pop();
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

describe('initializeDatabase', () => {
  it('creates the latest schema from the snapshot and records migrations on a fresh database', () => {
    const tempDir = createTempDir();
    const databaseFilePath = path.join(tempDir, 'phase.sqlite');
    const database = initializeDatabase({
      databaseFilePath,
      schemaFilePath: path.join(process.cwd(), 'db', 'schema.sql'),
      migrationsDirPath: path.join(process.cwd(), 'db', 'migrations'),
    });

    const userColumns = database.prepare("PRAGMA table_info('users')").all();
    const migrations = database.prepare('SELECT name FROM schema_migrations ORDER BY name ASC').all();

    expect(userColumns.some((column) => column.name === 'last_login_at')).toBe(true);
    expect(migrations.map((row) => row.name)).toEqual([
      '001_initial_schema.sql',
      '002_add_last_login_at.sql',
      '003_add_analysis_reports.sql',
      '004_add_analysis_jobs.sql',
      '005_add_report_sharing_and_preferences.sql',
      '006_add_github_access_tokens.sql',
    ]);

    const analysisReportColumns = database.prepare("PRAGMA table_info('analysis_reports')").all();
    expect(analysisReportColumns.some((column) => column.name === 'findings_json')).toBe(true);
    expect(analysisReportColumns.some((column) => column.name === 'share_token')).toBe(true);
    const preferencesColumns = database.prepare("PRAGMA table_info('user_preferences')").all();
    expect(preferencesColumns.some((column) => column.name === 'preferred_landing')).toBe(true);
    expect(userColumns.some((column) => column.name === 'github_access_token')).toBe(true);
    expect(userColumns.some((column) => column.name === 'github_token_scope')).toBe(true);
    expect(userColumns.some((column) => column.name === 'github_token_updated_at')).toBe(true);

    database.close();
  });

  it('baselines the legacy schema and runs newer migrations for an existing database', () => {
    const tempDir = createTempDir();
    const databaseFilePath = path.join(tempDir, 'phase.sqlite');
    const legacyDatabase = new Database(databaseFilePath);

    legacyDatabase.exec(`
      CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT,
        display_name TEXT NOT NULL,
        github_id TEXT UNIQUE,
        github_login TEXT,
        github_avatar_url TEXT,
        github_profile_url TEXT,
        auth_provider TEXT NOT NULL DEFAULT 'local',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE email_verifications (
        email TEXT PRIMARY KEY,
        code_hash TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
    `);
    legacyDatabase.close();

    const database = initializeDatabase({
      databaseFilePath,
      schemaFilePath: path.join(process.cwd(), 'db', 'schema.sql'),
      migrationsDirPath: path.join(process.cwd(), 'db', 'migrations'),
    });

    const userColumns = database.prepare("PRAGMA table_info('users')").all();
    const migrations = database.prepare('SELECT name FROM schema_migrations ORDER BY name ASC').all();

    expect(userColumns.some((column) => column.name === 'last_login_at')).toBe(true);
    expect(migrations.map((row) => row.name)).toEqual([
      '001_initial_schema.sql',
      '002_add_last_login_at.sql',
      '003_add_analysis_reports.sql',
      '004_add_analysis_jobs.sql',
      '005_add_report_sharing_and_preferences.sql',
      '006_add_github_access_tokens.sql',
    ]);

    const analysisReportColumns = database.prepare("PRAGMA table_info('analysis_reports')").all();
    expect(analysisReportColumns.some((column) => column.name === 'application_report')).toBe(true);
    expect(analysisReportColumns.some((column) => column.name === 'share_enabled')).toBe(true);
    const preferencesColumns = database.prepare("PRAGMA table_info('user_preferences')").all();
    expect(preferencesColumns.some((column) => column.name === 'default_analysis_sort')).toBe(true);
    expect(userColumns.some((column) => column.name === 'github_access_token')).toBe(true);
    expect(userColumns.some((column) => column.name === 'github_token_scope')).toBe(true);
    expect(userColumns.some((column) => column.name === 'github_token_updated_at')).toBe(true);

    database.close();
  });

  it('treats the old github migration name as already applied', () => {
    const tempDir = createTempDir();
    const databaseFilePath = path.join(tempDir, 'phase.sqlite');
    const database = new Database(databaseFilePath);

    database.exec(`
      CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT,
        display_name TEXT NOT NULL,
        github_id TEXT UNIQUE,
        github_login TEXT,
        github_avatar_url TEXT,
        github_profile_url TEXT,
        auth_provider TEXT NOT NULL DEFAULT 'local',
        last_login_at TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        github_access_token TEXT,
        github_token_scope TEXT,
        github_token_updated_at TEXT
      );

      CREATE TABLE email_verifications (
        email TEXT PRIMARY KEY,
        code_hash TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL
      );

      CREATE TABLE schema_migrations (
        name TEXT PRIMARY KEY,
        applied_at TEXT NOT NULL
      );
    `);

    const insertMigration = database.prepare('INSERT INTO schema_migrations (name, applied_at) VALUES (?, ?)');
    [
      '001_initial_schema.sql',
      '002_add_last_login_at.sql',
      '003_add_analysis_reports.sql',
      '004_add_analysis_jobs.sql',
      '005_add_report_sharing_and_preferences.sql',
      '006_add_github_repo_access.sql',
    ].forEach((migrationName) => {
      insertMigration.run(migrationName, new Date().toISOString());
    });
    database.close();

    const initialized = initializeDatabase({
      databaseFilePath,
      schemaFilePath: path.join(process.cwd(), 'db', 'schema.sql'),
      migrationsDirPath: path.join(process.cwd(), 'db', 'migrations'),
    });

    const migrations = initialized.prepare('SELECT name FROM schema_migrations ORDER BY name ASC').all();

    expect(migrations.map((row) => row.name)).toContain('006_add_github_repo_access.sql');
    expect(migrations.map((row) => row.name)).toContain('006_add_github_access_tokens.sql');

    initialized.close();
  });
});
