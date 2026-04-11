import 'server-only';
import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';
import {
  DATA_ROOT_DIR,
  DB_MIGRATIONS_DIR_PATH,
  DB_SCHEMA_FILE_PATH,
  PROJECT_ROOT_DIR,
} from './project-paths';

const MIGRATION_ALIASES = {
  '006_add_github_access_tokens.sql': ['006_add_github_repo_access.sql'],
};

function readSqlFile(filePath) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`SQL 파일을 찾을 수 없습니다: ${filePath}`);
  }

  return fs.readFileSync(filePath, 'utf8').trim();
}

function listMigrationFiles(migrationsDirPath) {
  if (!fs.existsSync(migrationsDirPath)) {
    return [];
  }

  return fs
    .readdirSync(migrationsDirPath)
    .filter((fileName) => fileName.endsWith('.sql'))
    .sort((left, right) => left.localeCompare(right));
}

function hasManagedSchema(database) {
  const result = database
    .prepare(
      `
        SELECT COUNT(*) AS count
        FROM sqlite_master
        WHERE type = 'table'
          AND name IN ('users', 'email_verifications')
      `
    )
    .get();

  return Number(result?.count || 0) > 0;
}

function ensureMigrationTable(database) {
  database.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      name TEXT PRIMARY KEY,
      applied_at TEXT NOT NULL
    );
  `);
}

function getAppliedMigrationNames(database) {
  return new Set(
    database
      .prepare('SELECT name FROM schema_migrations ORDER BY name ASC')
      .all()
      .map((row) => row.name)
  );
}

function recordMigration(database, migrationName) {
  database
    .prepare('INSERT OR IGNORE INTO schema_migrations (name, applied_at) VALUES (?, ?)')
    .run(migrationName, new Date().toISOString());
}

function syncAliasedMigrationNames(database, migrationFiles, appliedMigrationNames) {
  migrationFiles.forEach((fileName) => {
    if (appliedMigrationNames.has(fileName)) {
      return;
    }

    const aliases = MIGRATION_ALIASES[fileName] || [];
    const matchedAlias = aliases.find((alias) => appliedMigrationNames.has(alias));

    if (!matchedAlias) {
      return;
    }

    recordMigration(database, fileName);
    appliedMigrationNames.add(fileName);
  });
}

function baselineExistingDatabase(database, migrationFiles) {
  migrationFiles
    .filter((fileName) => fileName.startsWith('001'))
    .forEach((fileName) => {
      recordMigration(database, fileName);
    });
}

function markSchemaSnapshotMigrations(database, migrationFiles) {
  migrationFiles.forEach((fileName) => {
    recordMigration(database, fileName);
  });
}

function applyMigration(database, migrationName, migrationSql) {
  database.exec('BEGIN');

  try {
    database.exec(migrationSql);
    recordMigration(database, migrationName);
    database.exec('COMMIT');
  } catch (error) {
    database.exec('ROLLBACK');
    throw error;
  }
}

export function resolveDatabasePaths() {
  return {
    rootDir: PROJECT_ROOT_DIR,
    dataDir: DATA_ROOT_DIR,
    databaseFilePath: process.env.PHASE_DB_FILE || path.join(DATA_ROOT_DIR, 'phase-vuln-coach.sqlite'),
    schemaFilePath: process.env.PHASE_DB_SCHEMA_FILE || DB_SCHEMA_FILE_PATH,
    migrationsDirPath: process.env.PHASE_DB_MIGRATIONS_DIR || DB_MIGRATIONS_DIR_PATH,
  };
}

export function initializeDatabase({ databaseFilePath, schemaFilePath, migrationsDirPath }) {
  fs.mkdirSync(path.dirname(databaseFilePath), { recursive: true });

  const database = new Database(databaseFilePath);
  const schemaSql = readSqlFile(schemaFilePath);
  const migrationFiles = listMigrationFiles(migrationsDirPath);
  const hadManagedSchema = hasManagedSchema(database);

  if (!hadManagedSchema) {
    database.exec(schemaSql);
  }

  ensureMigrationTable(database);

  const appliedMigrationNames = getAppliedMigrationNames(database);

  if (!hadManagedSchema) {
    markSchemaSnapshotMigrations(database, migrationFiles);
    return database;
  }

  if (appliedMigrationNames.size === 0) {
    baselineExistingDatabase(database, migrationFiles);
  }

  const refreshedAppliedMigrationNames = getAppliedMigrationNames(database);
  syncAliasedMigrationNames(database, migrationFiles, refreshedAppliedMigrationNames);

  migrationFiles.forEach((fileName) => {
    if (refreshedAppliedMigrationNames.has(fileName)) {
      return;
    }

    const migrationSql = readSqlFile(path.join(migrationsDirPath, fileName));
    applyMigration(database, fileName, migrationSql);
  });

  return database;
}
