import 'server-only';
import crypto from 'node:crypto';

export const SESSION_COOKIE_NAME = 'phase.sid';
export const SESSION_MAX_AGE_MS = 1000 * 60 * 60 * 24 * 7;
export const SIGNUP_CODE_TTL_MS = 1000 * 60 * 3;
export const SIGNUP_VERIFICATION_SESSION_TTL_MS = 1000 * 60 * 10;
export const AUTH_RATE_LIMITS = {
  login: {
    limit: 5,
    windowMs: 1000 * 60 * 5,
    message: '로그인 시도가 너무 많습니다. 5분 후 다시 시도해주세요.',
  },
  signup: {
    limit: 5,
    windowMs: 1000 * 60 * 5,
    message: '회원가입 시도가 너무 많습니다. 5분 후 다시 후 시도해주세요.',
  },
  verificationRequest: {
    limit: 5,
    windowMs: 1000 * 60 * 50,
    message: '인증 코드 요청이 너무 많습니다. 5분 후 다시 시도해주세요.',
  },
  verificationConfirm: {
    limit: 10,
    windowMs: 1000 * 60 * 10,
    message: '인증 코드 확인 시도가 너무 많습니다. 10분 후 다시 시도해주세요.',
  },
  admin: {
    limit: 60,
    windowMs: 1000 * 60,
    message: '관리자 요청이 너무 많습니다. 잠시 후 다시 시도해주세요.',
  },
};

const LOOPBACK_HOSTNAMES = new Set(['localhost', '127.0.0.1', '0.0.0.0', '::1', '[::1]']);

function shouldTrustProxyHeaders() {
  return String(process.env.TRUST_PROXY_HEADERS || 'false').trim().toLowerCase() === 'true';
}

function normalizeProtocol(value = '') {
  const protocol = String(value || '').trim().replace(/:$/, '');
  return protocol === 'http' || protocol === 'https' ? protocol : '';
}

function normalizeOrigin(value = '') {
  const rawValue = String(value || '').trim();

  if (!rawValue) {
    return '';
  }

  try {
    return new URL(rawValue).origin;
  } catch {
    return '';
  }
}

function normalizeAbsoluteUrl(value = '') {
  const rawValue = String(value || '').trim();

  if (!rawValue) {
    return '';
  }

  try {
    return new URL(rawValue).toString().replace(/\/+$/, '');
  } catch {
    return '';
  }
}

function isLoopbackOrigin(value = '') {
  const normalizedOrigin = normalizeOrigin(value);

  if (!normalizedOrigin) {
    return false;
  }

  try {
    return LOOPBACK_HOSTNAMES.has(new URL(normalizedOrigin).hostname);
  } catch {
    return false;
  }
}

function getRequestHeader(request, name) {
  const headers = request?.headers;

  if (!headers) {
    return '';
  }

  const rawValue = typeof headers.get === 'function'
    ? headers.get(name)
    : headers[name] || headers[String(name).toLowerCase()];

  return String(rawValue || '')
    .split(',')[0]
    .trim();
}

function getHeaderOrigin(request) {
  const host = getRequestHeader(request, 'x-forwarded-host') || getRequestHeader(request, 'host');
  const forwardedPort = getRequestHeader(request, 'x-forwarded-port');
  const protocol = normalizeProtocol(getRequestHeader(request, 'x-forwarded-proto'))
    || normalizeProtocol(request?.nextUrl?.protocol)
    || normalizeProtocol(request?.url ? new URL(request.url).protocol : '');

  if (!host) {
    return '';
  }

  const defaultPort = protocol === 'https' ? '443' : protocol === 'http' ? '80' : '';
  const hostWithPort = host.includes(':') || !forwardedPort || forwardedPort === defaultPort
    ? host
    : `${host}:${forwardedPort}`;

  return normalizeOrigin(`${protocol || 'http'}://${hostWithPort}`);
}

export function getAppOrigin(origin = '') {
  const configuredOrigin = normalizeOrigin(process.env.APP_BASE_URL);
  const fallbackOrigin = normalizeOrigin(origin);

  if (configuredOrigin && !isLoopbackOrigin(configuredOrigin)) {
    return configuredOrigin;
  }

  if (fallbackOrigin && !isLoopbackOrigin(fallbackOrigin)) {
    return fallbackOrigin;
  }

  return configuredOrigin || fallbackOrigin || 'http://localhost:3000';
}

export function getRequestAppOrigin(request) {
  const configuredOrigin = normalizeOrigin(process.env.APP_BASE_URL);
  const headerOrigin = getHeaderOrigin(request);
  const requestOrigin = normalizeOrigin(request?.nextUrl?.origin || request?.url || '');
  const trustedHeaderOrigin = shouldTrustProxyHeaders() ? headerOrigin : '';

  if (configuredOrigin && !isLoopbackOrigin(configuredOrigin)) {
    return configuredOrigin;
  }

  if (requestOrigin && !isLoopbackOrigin(requestOrigin)) {
    return requestOrigin;
  }

  if (trustedHeaderOrigin && !isLoopbackOrigin(trustedHeaderOrigin)) {
    return trustedHeaderOrigin;
  }

  return configuredOrigin || requestOrigin || trustedHeaderOrigin || 'http://localhost:3000';
}

export function getGitHubConfig(originOrRequest = '') {
  const appOrigin = typeof originOrRequest === 'object' && originOrRequest !== null
    ? getRequestAppOrigin(originOrRequest)
    : getAppOrigin(originOrRequest);
  const configuredRedirectUri = normalizeAbsoluteUrl(process.env.GITHUB_REDIRECT_URI);
  const derivedRedirectUri = `${appOrigin}/auth/github/callback`;
  const redirectUri = configuredRedirectUri && (!isLoopbackOrigin(configuredRedirectUri) || isLoopbackOrigin(appOrigin))
    ? configuredRedirectUri
    : derivedRedirectUri;

  return {
    clientId: process.env.GITHUB_CLIENT_ID || '',
    clientSecret: process.env.GITHUB_CLIENT_SECRET || '',
    redirectUri,
    scope: process.env.GITHUB_SCOPE || 'read:user user:email',
  };
}

export function hasGitHubConfig(config) {
  return Boolean(config.clientId && config.clientSecret && config.redirectUri);
}

export function getMailConfig() {
  return {
    host: process.env.SMTP_HOST || '',
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE || 'false') === 'true',
    user: process.env.SMTP_USER || '',
    pass: process.env.SMTP_PASS || '',
    from: process.env.SMTP_FROM || 'Phase Vuln Coach <no-reply@phase.local>',
  };
}

export function hasMailConfig(config) {
  return Boolean(config.host && config.port && config.from);
}

export function getAdminEmails() {
  return String(process.env.ADMIN_EMAILS || '')
    .split(',')
    .map((email) => email.trim().toLowerCase())
    .filter(Boolean);
}

export function isAdminEmail(email) {
  return getAdminEmails().includes(String(email || '').trim().toLowerCase());
}

export function getVerificationMessage(reason) {
  const messages = {
    missing: '이메일 인증 코드 요청이 없습니다. 다시 인증을 요청해주세요.',
    expired: '인증 코드가 만료되었습니다. 다시 요청해주세요.',
    invalid: '인증 코드가 올바르지 않습니다.',
    session_expired: '이메일 인증 완료 상태가 만료되었습니다. 다시 인증해주세요.',
  };

  return messages[reason] || '이메일 인증에 실패했습니다.';
}

export function getMailErrorMessage(error) {
  const rawMessage = String(error?.message || '');

  if (/application-specific password required|534-5\.7\.9|534 5\.7\.9/i.test(rawMessage)) {
    return 'Gmail SMTP 인증이 거부되었습니다. 일반 비밀번호가 아니라 Google 앱 비밀번호를 SMTP_PASS에 넣어야 합니다.';
  }

  if (/invalid login|username and password not accepted|535-5\.7\.8|535 5\.7\.8/i.test(rawMessage)) {
    return 'SMTP 로그인에 실패했습니다. SMTP_USER 또는 SMTP_PASS 값을 다시 확인해주세요.';
  }

  if (/ECONNECTION|ETIMEDOUT|ESOCKET|connection/i.test(rawMessage)) {
    return '메일 서버 연결에 실패했습니다. SMTP_HOST, SMTP_PORT, SMTP_SECURE 값을 다시 확인해주세요.';
  }

  return '인증 메일 발송에 실패했습니다. SMTP 설정을 다시 확인해주세요.';
}

export function generateVerificationCode() {
  return String(crypto.randomInt(100000, 1000000));
}

export function generateOAuthState() {
  return crypto.randomBytes(24).toString('hex');
}
