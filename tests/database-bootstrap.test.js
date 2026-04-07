import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
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
    ]);

    database.close();
  });

  it('baselines the legacy schema and runs newer migrations for an existing database', () => {
    const tempDir = createTempDir();
    const databaseFilePath = path.join(tempDir, 'phase.sqlite');
    const legacyDatabase = new DatabaseSync(databaseFilePath);

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
    ]);

    database.close();
  });
});