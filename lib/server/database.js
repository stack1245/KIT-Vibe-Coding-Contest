import 'server-only';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { normalizeReportForDisplay } from '../analysis-report-display';
import { initializeDatabase, resolveDatabasePaths } from './database-bootstrap';
import { encryptSecretValue } from './secret-storage';

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
    github_access_token,
    github_token_scope,
    github_token_updated_at,
    auth_provider,
    last_login_at,
    created_at,
    updated_at
  ) VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);
const updateGitHubLinkStatement = db.prepare(`
  UPDATE users
  SET github_id = ?,
      github_login = ?,
      github_avatar_url = ?,
      github_profile_url = ?,
      github_access_token = ?,
      github_token_scope = ?,
      github_token_updated_at = ?,
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
      github_access_token = NULL,
      github_token_scope = NULL,
      github_token_updated_at = NULL,
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
const updateDisplayNameStatement = db.prepare(`
  UPDATE users
  SET display_name = ?,
      updated_at = ?
  WHERE id = ?
`);
const updateUserPasswordStatement = db.prepare(`
  UPDATE users
  SET password_hash = ?,
      auth_provider = ?,
      updated_at = ?
  WHERE id = ?
`);
const selectAllUsersStatement = db.prepare(`
  SELECT *
  FROM users
  ORDER BY created_at DESC
`);
const deleteUserByIdStatement = db.prepare('DELETE FROM users WHERE id = ?');
const insertAnalysisReportStatement = db.prepare(`
  INSERT INTO analysis_reports (
    user_id,
    title,
    application_type,
    summary,
    application_report,
    result_mode,
    overall_severity,
    findings_count,
    findings_json,
    source_files_json,
    created_at,
    updated_at
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);
const selectRecentAnalysisReportsByUserStatement = db.prepare(`
  SELECT *
  FROM analysis_reports
  WHERE user_id = ?
  ORDER BY created_at DESC
  LIMIT ?
`);
const selectAnalysisReportByIdStatement = db.prepare(`
  SELECT *
  FROM analysis_reports
  WHERE id = ?
`);
const selectAnalysisReportByShareTokenStatement = db.prepare(`
  SELECT *
  FROM analysis_reports
  WHERE share_token = ?
    AND share_enabled = 1
`);
const deleteAnalysisReportByIdStatement = db.prepare(`
  DELETE FROM analysis_reports
  WHERE id = ?
`);
const updateAnalysisReportSharingStatement = db.prepare(`
  UPDATE analysis_reports
  SET share_enabled = ?,
      share_token = ?,
      updated_at = ?
  WHERE id = ?
`);
const insertAnalysisJobStatement = db.prepare(`
  INSERT INTO analysis_jobs (
    user_id,
    status,
    stage,
    progress_percent,
    message,
    report_id,
    accepted_files_json,
    rejected_files_json,
    error_message,
    created_at,
    updated_at
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);
const selectAnalysisJobByIdStatement = db.prepare(`
  SELECT *
  FROM analysis_jobs
  WHERE id = ?
`);
const selectLatestActiveAnalysisJobByUserStatement = db.prepare(`
  SELECT *
  FROM analysis_jobs
  WHERE user_id = ?
    AND status IN ('queued', 'running')
  ORDER BY created_at DESC
  LIMIT 1
`);
const selectRecentAnalysisJobsByUserStatement = db.prepare(`
  SELECT *
  FROM analysis_jobs
  WHERE user_id = ?
  ORDER BY created_at DESC
  LIMIT ?
`);
const updateAnalysisJobProgressStatement = db.prepare(`
  UPDATE analysis_jobs
  SET status = ?,
      stage = ?,
      progress_percent = ?,
      message = ?,
      updated_at = ?
  WHERE id = ?
`);
const completeAnalysisJobStatement = db.prepare(`
  UPDATE analysis_jobs
  SET status = 'completed',
      stage = ?,
      progress_percent = 100,
      message = ?,
      report_id = ?,
      updated_at = ?
  WHERE id = ?
`);
const failAnalysisJobStatement = db.prepare(`
  UPDATE analysis_jobs
  SET status = 'failed',
      stage = ?,
      progress_percent = ?,
      message = ?,
      error_message = ?,
      updated_at = ?
  WHERE id = ?
`);
const cancelAnalysisJobStatement = db.prepare(`
  UPDATE analysis_jobs
  SET status = 'cancelled',
      stage = ?,
      progress_percent = ?,
      message = ?,
      error_message = ?,
      updated_at = ?
  WHERE id = ?
`);
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
const selectUserPreferencesByUserIdStatement = db.prepare(`
  SELECT *
  FROM user_preferences
  WHERE user_id = ?
`);
const upsertUserPreferencesStatement = db.prepare(`
  INSERT INTO user_preferences (
    user_id,
    preferred_landing,
    default_analysis_sort,
    email_updates,
    dashboard_digest,
    created_at,
    updated_at
  ) VALUES (?, ?, ?, ?, ?, ?, ?)
  ON CONFLICT(user_id)
  DO UPDATE SET preferred_landing = excluded.preferred_landing,
                default_analysis_sort = excluded.default_analysis_sort,
                email_updates = excluded.email_updates,
                dashboard_digest = excluded.dashboard_digest,
                updated_at = excluded.updated_at
`);
const updateGitHubTokenEncryptionStatement = db.prepare(`
  UPDATE users
  SET github_access_token = ?,
      updated_at = ?
  WHERE id = ?
`);

function now() {
  return new Date().toISOString();
}

function migratePlaintextGitHubTokens() {
  const encryptionSecret = String(
    process.env.GITHUB_TOKEN_ENCRYPTION_KEY
    || process.env.SECRET_STORAGE_KEY
    || process.env.SESSION_SECRET
    || '',
  ).trim();

  if (!encryptionSecret) {
    return;
  }

  const rows = db.prepare(`
    SELECT id, github_access_token
    FROM users
    WHERE github_access_token IS NOT NULL
      AND github_access_token != ''
      AND github_access_token NOT LIKE 'enc:%'
  `).all();

  if (!rows.length) {
    return;
  }

  const timestamp = now();
  rows.forEach((row) => {
    updateGitHubTokenEncryptionStatement.run(
      encryptSecretValue(row.github_access_token),
      timestamp,
      row.id,
    );
  });
}

migratePlaintextGitHubTokens();

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

export function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizeEmail(email));
}

export function isStrongPassword(password) {
  return /^(?=.*[A-Za-z])(?=.*\d).{8,}$/.test(String(password || ''));
}

export function isValidDisplayName(displayName) {
  const value = String(displayName || '').trim();
  return value.length >= 2 && value.length <= 30;
}

function buildDisplayName(email, displayName) {
  if (displayName && String(displayName).trim()) {
    return String(displayName).trim();
  }

  const normalizedEmail = normalizeEmail(email);
  return normalizedEmail.split('@')[0] || 'Phase User';
}

const DEFAULT_USER_PREFERENCES = Object.freeze({
  preferredLanding: '/dashboard',
  defaultAnalysisSort: 'latest',
  emailUpdates: true,
  dashboardDigest: true,
});

function normalizePreferredLanding(value) {
  return ['/dashboard', '/analysis'].includes(value) ? value : DEFAULT_USER_PREFERENCES.preferredLanding;
}

function normalizeAnalysisSort(value) {
  return ['latest', 'severity', 'findings'].includes(value) ? value : DEFAULT_USER_PREFERENCES.defaultAnalysisSort;
}

function normalizeUserPreferences(input = {}) {
  return {
    preferredLanding: normalizePreferredLanding(String(input.preferredLanding || '').trim()),
    defaultAnalysisSort: normalizeAnalysisSort(String(input.defaultAnalysisSort || '').trim()),
    emailUpdates: Boolean(input.emailUpdates),
    dashboardDigest: Boolean(input.dashboardDigest),
  };
}

function formatUserPreferences(row) {
  if (!row) {
    return { ...DEFAULT_USER_PREFERENCES };
  }

  return {
    preferredLanding: normalizePreferredLanding(String(row.preferred_landing || '')),
    defaultAnalysisSort: normalizeAnalysisSort(String(row.default_analysis_sort || '')),
    emailUpdates: Boolean(row.email_updates),
    dashboardDigest: Boolean(row.dashboard_digest),
  };
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
    githubRepoAccess: Boolean(row.github_access_token),
    githubTokenScope: row.github_token_scope || '',
    hasPassword: Boolean(row.password_hash),
    lastLoginAt: row.last_login_at || null,
    createdAt: row.created_at,
  };
}

function safeParseJsonArray(value) {
  try {
    const parsed = JSON.parse(String(value || '[]'));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function formatAnalysisTimestampLabel(value) {
  if (!value) {
    return '';
  }

  try {
    return new Intl.DateTimeFormat('ko-KR', {
      timeZone: 'Asia/Seoul',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      hour12: true,
    }).format(new Date(value));
  } catch {
    return String(value);
  }
}

export function formatAnalysisReport(row) {
  if (!row) {
    return null;
  }

  const findings = safeParseJsonArray(row.findings_json);
  const isLegacyFallbackRecommendation = row.result_mode === 'recommendation'
    && findings.length === 1
    && (
      findings[0]?.id === 'fallback-review-0'
      || findings[0]?.title === '업로드 분석 시간이 길어 추가 검토가 필요'
    );

  return normalizeReportForDisplay({
    id: row.id,
    userId: row.user_id,
    title: row.title,
    applicationType: row.application_type,
    summary: isLegacyFallbackRecommendation
      ? '자동 분석이 제한 시간 안에 확정 결과를 만들지 못했습니다. 추가 검토가 필요합니다.'
      : row.summary,
    applicationReport: row.application_report,
    resultMode: row.result_mode,
    overallSeverity: isLegacyFallbackRecommendation ? 'low' : row.overall_severity,
    findingsCount: isLegacyFallbackRecommendation ? 0 : row.findings_count,
    findings: isLegacyFallbackRecommendation ? [] : findings,
    sourceFiles: safeParseJsonArray(row.source_files_json),
    shareEnabled: Boolean(row.share_enabled),
    shareToken: row.share_token || '',
    createdAt: row.created_at,
    createdAtLabel: formatAnalysisTimestampLabel(row.created_at),
    updatedAt: row.updated_at,
  });
}

export function formatAnalysisJob(row) {
  if (!row) {
    return null;
  }

  return {
    id: row.id,
    userId: row.user_id,
    status: row.status,
    stage: row.stage,
    progressPercent: row.progress_percent,
    message: row.message || '',
    reportId: row.report_id || null,
    acceptedFiles: safeParseJsonArray(row.accepted_files_json),
    rejectedFiles: safeParseJsonArray(row.rejected_files_json),
    errorMessage: row.error_message || '',
    createdAt: row.created_at,
    updatedAt: row.updated_at,
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

export function createGitHubUser({
  email,
  displayName,
  githubId,
  githubLogin,
  githubAvatarUrl,
  githubProfileUrl,
  githubAccessToken,
  githubTokenScope,
}) {
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
    githubAccessToken ? encryptSecretValue(githubAccessToken) : null,
    githubTokenScope || null,
    githubAccessToken ? timestamp : null,
    deriveAuthProviderFromParts(null, githubId),
    timestamp,
    timestamp,
    timestamp
  );

  return findUserById(Number(result.lastInsertRowid));
}

export function linkGitHubToUser(userId, githubUser, { accessToken = '', tokenScope = '' } = {}) {
  const existingUser = findUserById(userId);

  if (!existingUser) {
    return null;
  }

  const timestamp = now();
  updateGitHubLinkStatement.run(
    String(githubUser.id),
    githubUser.login || null,
    githubUser.avatarUrl || null,
    githubUser.profileUrl || null,
    accessToken ? encryptSecretValue(accessToken) : null,
    tokenScope || null,
    accessToken ? timestamp : null,
    deriveAuthProviderFromParts(existingUser.password_hash, githubUser.id),
    timestamp,
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

export function updateUserPassword(userId, password) {
  const existingUser = findUserById(userId);
  if (!existingUser) {
    return null;
  }

  const passwordHash = hashPassword(password);

  updateUserPasswordStatement.run(
    passwordHash,
    deriveAuthProviderFromParts(passwordHash, existingUser.github_id),
    now(),
    userId
  );

  return findUserById(userId);
}

export function updateUserDisplayName(userId, displayName) {
  const existingUser = findUserById(userId);
  if (!existingUser) {
    return null;
  }

  updateDisplayNameStatement.run(String(displayName || '').trim(), now(), userId);
  return findUserById(userId);
}

export function listUsers() {
  return selectAllUsersStatement.all();
}

export function deleteUserById(userId) {
  const result = deleteUserByIdStatement.run(userId);
  return result.changes > 0;
}

export function createAnalysisReport(userId, report) {
  const timestamp = now();
  const result = insertAnalysisReportStatement.run(
    userId,
    report.title,
    report.applicationType,
    report.summary,
    report.applicationReport,
    report.resultMode,
    report.overallSeverity,
    report.findingsCount,
    JSON.stringify(Array.isArray(report.findings) ? report.findings : []),
    JSON.stringify(Array.isArray(report.sourceFiles) ? report.sourceFiles : []),
    timestamp,
    timestamp
  );

  return formatAnalysisReport(
    db.prepare('SELECT * FROM analysis_reports WHERE id = ?').get(Number(result.lastInsertRowid))
  );
}

export function listAnalysisReportsByUser(userId, limit = 6) {
  return selectRecentAnalysisReportsByUserStatement
    .all(userId, limit)
    .map((row) => formatAnalysisReport(row))
    .filter(Boolean);
}

export function findAnalysisReportById(reportId) {
  return formatAnalysisReport(selectAnalysisReportByIdStatement.get(reportId));
}

export function findSharedAnalysisReportByToken(token) {
  return formatAnalysisReport(selectAnalysisReportByShareTokenStatement.get(String(token || '').trim()));
}

export function deleteAnalysisReportById(reportId) {
  return deleteAnalysisReportByIdStatement.run(reportId).changes > 0;
}

export function updateAnalysisReportSharing(reportId, enabled) {
  const report = findAnalysisReportById(reportId);
  if (!report) {
    return null;
  }

  const shareEnabled = Boolean(enabled);
  const shareToken = shareEnabled
    ? (report.shareToken || crypto.randomBytes(18).toString('hex'))
    : null;

  updateAnalysisReportSharingStatement.run(
    shareEnabled ? 1 : 0,
    shareToken,
    now(),
    reportId
  );

  return findAnalysisReportById(reportId);
}

export function createAnalysisJob(userId, { acceptedFiles = [], rejectedFiles = [] } = {}) {
  const timestamp = now();
  const result = insertAnalysisJobStatement.run(
    userId,
    'queued',
    '업로드 진행 중',
    5,
    '업로드를 정리하고 있습니다.',
    null,
    JSON.stringify(Array.isArray(acceptedFiles) ? acceptedFiles : []),
    JSON.stringify(Array.isArray(rejectedFiles) ? rejectedFiles : []),
    null,
    timestamp,
    timestamp
  );

  return formatAnalysisJob(selectAnalysisJobByIdStatement.get(Number(result.lastInsertRowid)));
}

export function findAnalysisJobById(jobId) {
  return formatAnalysisJob(selectAnalysisJobByIdStatement.get(jobId));
}

export function findLatestActiveAnalysisJobByUser(userId) {
  return formatAnalysisJob(selectLatestActiveAnalysisJobByUserStatement.get(userId));
}

export function listRecentAnalysisJobsByUser(userId, limit = 6) {
  return selectRecentAnalysisJobsByUserStatement
    .all(userId, limit)
    .map((row) => formatAnalysisJob(row))
    .filter(Boolean);
}

export function updateAnalysisJobProgress(jobId, { status = 'running', stage, progressPercent, message }) {
  updateAnalysisJobProgressStatement.run(
    status,
    stage,
    Number(progressPercent || 0),
    message || '',
    now(),
    jobId
  );

  return findAnalysisJobById(jobId);
}

export function completeAnalysisJob(jobId, { stage = '분석 완료', message = '분석이 완료되었습니다.', reportId }) {
  completeAnalysisJobStatement.run(
    stage,
    message,
    reportId || null,
    now(),
    jobId
  );

  return findAnalysisJobById(jobId);
}

export function failAnalysisJob(jobId, { stage = '분석 실패', progressPercent = 100, message = '분석에 실패했습니다.', errorMessage = '' }) {
  failAnalysisJobStatement.run(
    stage,
    Number(progressPercent || 100),
    message,
    errorMessage,
    now(),
    jobId
  );

  return findAnalysisJobById(jobId);
}

export function cancelAnalysisJob(
  jobId,
  {
    stage = '분석 취소됨',
    progressPercent = 100,
    message = '분석을 취소했습니다.',
    errorMessage = 'cancelled-by-user',
  } = {}
) {
  cancelAnalysisJobStatement.run(
    stage,
    Number(progressPercent || 100),
    message,
    errorMessage,
    now(),
    jobId
  );

  return findAnalysisJobById(jobId);
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

export function getUserPreferences(userId) {
  if (!Number.isInteger(Number(userId))) {
    return { ...DEFAULT_USER_PREFERENCES };
  }

  return formatUserPreferences(selectUserPreferencesByUserIdStatement.get(Number(userId)));
}

export function updateUserPreferences(userId, preferences) {
  const existingUser = findUserById(userId);
  if (!existingUser) {
    return null;
  }

  const normalized = normalizeUserPreferences(preferences);
  const timestamp = now();

  upsertUserPreferencesStatement.run(
    userId,
    normalized.preferredLanding,
    normalized.defaultAnalysisSort,
    normalized.emailUpdates ? 1 : 0,
    normalized.dashboardDigest ? 1 : 0,
    timestamp,
    timestamp
  );

  return getUserPreferences(userId);
}

export { DEFAULT_USER_PREFERENCES, normalizeUserPreferences };
