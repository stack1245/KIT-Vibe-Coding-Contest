import 'server-only';
import crypto from 'node:crypto';
import { cookies } from 'next/headers';
import { SESSION_COOKIE_NAME, SESSION_MAX_AGE_MS } from './config';

function toBase64Url(value) {
  return Buffer.from(value).toString('base64url');
}

function fromBase64Url(value) {
  return Buffer.from(value, 'base64url').toString('utf8');
}

function sign(value) {
  return crypto
    .createHmac('sha256', process.env.SESSION_SECRET || 'change-this-session-secret')
    .update(value)
    .digest('base64url');
}

export function createEmptySession() {
  return {
    accountId: null,
    authMethod: null,
    oauthState: null,
    oauthMode: null,
    oauthAccountId: null,
    signupVerification: null,
    issuedAt: Date.now(),
  };
}

function normalizeSession(session) {
  return {
    ...createEmptySession(),
    ...session,
    issuedAt: Date.now(),
  };
}

function encodeSession(session) {
  const normalized = normalizeSession(session);
  const payload = toBase64Url(JSON.stringify(normalized));
  const signature = sign(payload);
  return `${payload}.${signature}`;
}

function decodeSession(value) {
  if (!value || !value.includes('.')) {
    return createEmptySession();
  }

  const [payload, signature] = value.split('.');

  if (sign(payload) !== signature) {
    return createEmptySession();
  }

  try {
    const parsed = JSON.parse(fromBase64Url(payload));
    return normalizeSession(parsed);
  } catch {
    return createEmptySession();
  }
}

function getCookieValueFromRequest(request, cookieName) {
  const cookieHeader = typeof request?.headers?.get === 'function'
    ? request.headers.get('cookie')
    : request?.headers?.cookie;
  const rawCookieHeader = String(cookieHeader || '');

  if (!rawCookieHeader) {
    return '';
  }

  return rawCookieHeader
    .split(';')
    .map((entry) => entry.trim())
    .find((entry) => entry.startsWith(`${cookieName}=`))
    ?.slice(cookieName.length + 1) || '';
}

export async function getSession(request) {
  if (request) {
    return decodeSession(getCookieValueFromRequest(request, SESSION_COOKIE_NAME));
  }

  try {
    const cookieStore = await cookies();
    return decodeSession(cookieStore.get(SESSION_COOKIE_NAME)?.value || '');
  } catch {
    return createEmptySession();
  }
}

export function commitSession(response, session) {
  response.cookies.set({
    name: SESSION_COOKIE_NAME,
    value: encodeSession(session),
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: Math.floor(SESSION_MAX_AGE_MS / 1000),
    path: '/',
  });

  return response;
}

export function clearSession(response) {
  response.cookies.set({
    name: SESSION_COOKIE_NAME,
    value: '',
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 0,
    path: '/',
  });

  return response;
}
