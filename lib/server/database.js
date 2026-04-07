import 'server-only';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { initializeDatabase, resolveDatabasePaths } from './database-bootstrap';

const { dataDir, databaseFilePath, schemaFilePath, migrationsDirPath } = resolveDatabasePaths();

export { databaseFilePath };

fs.mkdirSync(dataDir, { recursive: true });

const globalDatabase = globalThis;

if (!globalDatabase.__phaseDatabase) {
  globalDatabase.__phaseDatabase = initializeDatabase({
    databaseFilePath,
    schemaFilePath,
    migrationsDirPath,
  });
}

const db = globalDatabase.__phaseDatabase;

const selectUserByIdStatement = db.prepare('SELECT * FROM users WHERE id = ?');
const selectUserByEmailStatement = db.prepare('SELECT * FROM users WHERE email = ?');
const selectUserByGitHubIdStatement = db.prepare('SELECT * FROM users WHERE github_id = ?');
const insertLocalUserStatement = db.prepare(`
  INSERT INTO users (
    email,
    password_hash,
    display_name,
    auth_provider,
    last_login_at,
    created_at,
    updated_at
  ) VALUES (?, ?, ?, ?, ?, ?, ?)
`);
const insertGitHubUserStatement = db.prepare(`
  INSERT INTO users (
    email,
    password_hash,
    display_name,
    github_id,
    github_login,
    github_avatar_url,
    github_profile_url,
    auth_provider,
    last_login_at,
    created_at,
    updated_at
  ) VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);
const updateGitHubLinkStatement = db.prepare(`
  UPDATE users
  SET github_id = ?,
      github_login = ?,
      github_avatar_url = ?,
      github_profile_url = ?,
      auth_provider = ?,
      updated_at = ?
  WHERE id = ?
`);
const clearGitHubLinkStatement = db.prepare(`
  UPDATE users
  SET github_id = NULL,
      github_login = NULL,
      github_avatar_url = NULL,
      github_profile_url = NULL,
      auth_provider = ?,
      updated_at = ?
  WHERE id = ?
`);
const updateLastLoginStatement = db.prepare(`
  UPDATE users
  SET last_login_at = ?,
      updated_at = ?
  WHERE id = ?
`);
const selectAllUsersStatement = db.prepare(`
  SELECT *
  FROM users
  ORDER BY created_at DESC
`);
const deleteUserByIdStatement = db.prepare('DELETE FROM users WHERE id = ?');
const upsertEmailVerificationStatement = db.prepare(`
  INSERT INTO email_verifications (email, code_hash, expires_at, created_at)
  VALUES (?, ?, ?, ?)
  ON CONFLICT(email)
  DO UPDATE SET code_hash = excluded.code_hash,
                expires_at = excluded.expires_at,
                created_at = excluded.created_at
`);
const selectEmailVerificationStatement = db.prepare('SELECT * FROM email_verifications WHERE email = ?');
const deleteEmailVerificationStatement = db.prepare('DELETE FROM email_verifications WHERE email = ?');

function now() {
  return new Date().toISOString();
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

export function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizeEmail(email));
}

export function isStrongPassword(password) {
  return /^(?=.*[A-Za-z])(?=.*\d).{8,}$/.test(String(password || ''));
}

function buildDisplayName(email, displayName) {
  if (displayName && String(displayName).trim()) {
    return String(displayName).trim();
  }

  const normalizedEmail = normalizeEmail(email);
  return normalizedEmail.split('@')[0] || 'Phase User';
}

function deriveAuthProviderFromParts(passwordHash, githubId) {
  if (passwordHash && githubId) return 'hybrid';
  if (githubId) return 'github';
  return 'local';
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function hashVerificationCode(code) {
  return crypto.createHash('sha256').update(String(code || '')).digest('hex');
}

export function verifyPassword(password, passwordHash) {
  if (!passwordHash || !passwordHash.includes(':')) {
    return false;
  }

  const [salt, storedHash] = passwordHash.split(':');
  const derivedKey = crypto.scryptSync(String(password || ''), salt, 64);
  const storedBuffer = Buffer.from(storedHash, 'hex');

  if (storedBuffer.length !== derivedKey.length) {
    return false;
  }

  return crypto.timingSafeEqual(storedBuffer, derivedKey);
}

export function formatUser(row, authMethod = 'local') {
  if (!row) {
    return null;
  }

  return {
    id: row.id,
    email: row.email,
    name: row.display_name,
    login: row.github_login || null,
    avatarUrl: row.github_avatar_url || '',
    profileUrl: row.github_profile_url || '',
    authMethod,
    githubConnected: Boolean(row.github_id),
    hasPassword: Boolean(row.password_hash),
    lastLoginAt: row.last_login_at || null,
    createdAt: row.created_at,
  };
}

export function findUserById(id) {
  return selectUserByIdStatement.get(id) || null;
}

export function findUserByEmail(email) {
  return selectUserByEmailStatement.get(normalizeEmail(email)) || null;
}

export function findUserByGitHubId(githubId) {
  return selectUserByGitHubIdStatement.get(String(githubId)) || null;
}

export function createLocalUser({ email, password, displayName }) {
  const normalizedEmail = normalizeEmail(email);
  const resolvedName = buildDisplayName(normalizedEmail, displayName);
  const passwordHash = hashPassword(password);
  const timestamp = now();

  const result = insertLocalUserStatement.run(
    normalizedEmail,
    passwordHash,
    resolvedName,
    deriveAuthProviderFromParts(passwordHash, null),
    timestamp,
    timestamp,
    timestamp
  );

  return findUserById(Number(result.lastInsertRowid));
}

export function createGitHubUser({ email, displayName, githubId, githubLogin, githubAvatarUrl, githubProfileUrl }) {
  const normalizedEmail = normalizeEmail(email);
  const resolvedName = buildDisplayName(normalizedEmail, displayName || githubLogin);
  const timestamp = now();

  const result = insertGitHubUserStatement.run(
    normalizedEmail,
    resolvedName,
    String(githubId),
    githubLogin || null,
    githubAvatarUrl || null,
    githubProfileUrl || null,
    deriveAuthProviderFromParts(null, githubId),
    timestamp,
    timestamp,
    timestamp
  );

  return findUserById(Number(result.lastInsertRowid));
}

export function linkGitHubToUser(userId, githubUser) {
  const existingUser = findUserById(userId);

  if (!existingUser) {
    return null;
  }

  updateGitHubLinkStatement.run(
    String(githubUser.id),
    githubUser.login || null,
    githubUser.avatarUrl || null,
    githubUser.profileUrl || null,
    deriveAuthProviderFromParts(existingUser.password_hash, githubUser.id),
    now(),
    userId
  );

  return findUserById(userId);
}

export function unlinkGitHubFromUser(userId) {
  const existingUser = findUserById(userId);

  if (!existingUser) {
    return null;
  }

  clearGitHubLinkStatement.run(
    deriveAuthProviderFromParts(existingUser.password_hash, null),
    now(),
    userId
  );

  return findUserById(userId);
}

export function touchUserLastLogin(userId) {
  const timestamp = now();

  updateLastLoginStatement.run(timestamp, timestamp, userId);
  return findUserById(userId);
}

export function listUsers() {
  return selectAllUsersStatement.all();
}

export function deleteUserById(userId) {
  const result = deleteUserByIdStatement.run(userId);
  return result.changes > 0;
}

export function saveEmailVerification(email, code, expiresAt) {
  const normalizedEmail = normalizeEmail(email);
  const timestamp = now();

  upsertEmailVerificationStatement.run(
    normalizedEmail,
    hashVerificationCode(code),
    expiresAt,
    timestamp
  );
}

export function verifyEmailVerificationCode(email, code) {
  const verification = selectEmailVerificationStatement.get(normalizeEmail(email));

  if (!verification) {
    return { ok: false, reason: 'missing' };
  }

  if (new Date(verification.expires_at).getTime() < Date.now()) {
    deleteEmailVerificationStatement.run(normalizeEmail(email));
    return { ok: false, reason: 'expired' };
  }

  if (verification.code_hash !== hashVerificationCode(code)) {
    return { ok: false, reason: 'invalid' };
  }

  deleteEmailVerificationStatement.run(normalizeEmail(email));
  return { ok: true };
}
