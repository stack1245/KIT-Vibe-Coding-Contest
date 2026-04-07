import 'server-only';
import nodemailer from 'nodemailer';
import {
  getMailConfig,
  getAdminEmails,
  getVerificationMessage,
  hasMailConfig,
  isAdminEmail,
} from './config';
import { findUserById, formatUser } from './database';
import {
  clearSignupVerification,
  createSignupVerifiedSession,
  hasValidSignupVerification,
} from './signup-verification';

export function buildSessionUser(row, authMethod) {
  const user = formatUser(row, authMethod);

  if (!user) {
    return null;
  }

  return {
    ...user,
    isAdmin: isAdminEmail(user.email),
  };
}

export function getSessionUser(session) {
  if (!session?.accountId) {
    return null;
  }

  const user = findUserById(session.accountId);
  if (!user) {
    return null;
  }

  return buildSessionUser(user, session.authMethod || 'local');
}

export function setAuthenticatedSession(session, userId, authMethod) {
  return {
    ...session,
    accountId: userId,
    authMethod,
    oauthState: null,
    oauthMode: null,
    oauthAccountId: null,
  };
}

export function clearOAuthSession(session) {
  return {
    ...session,
    oauthState: null,
    oauthMode: null,
    oauthAccountId: null,
  };
}

export function resolvePrimaryEmail(emails) {
  if (!Array.isArray(emails)) {
    return null;
  }

  const primary = emails.find((email) => email.primary && email.verified);
  if (primary) {
    return primary.email;
  }

  const verified = emails.find((email) => email.verified);
  return verified ? verified.email : null;
}

export async function fetchGitHubUser(accessToken) {
  const headers = {
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${accessToken}`,
    'User-Agent': 'phase-vuln-coach',
  };

  const [profileResponse, emailsResponse] = await Promise.all([
    fetch('https://api.github.com/user', { headers, cache: 'no-store' }),
    fetch('https://api.github.com/user/emails', { headers, cache: 'no-store' }),
  ]);

  if (!profileResponse.ok) {
    throw new Error('GitHub 프로필 정보를 가져오지 못했습니다.');
  }

  const profile = await profileResponse.json();
  const emails = emailsResponse.ok ? await emailsResponse.json() : [];

  return {
    id: String(profile.id),
    login: profile.login,
    name: profile.name || profile.login,
    avatarUrl: profile.avatar_url,
    profileUrl: profile.html_url,
    email: profile.email || resolvePrimaryEmail(emails),
  };
}

export async function sendVerificationEmail(email, code) {
  const mailConfig = getMailConfig();

  if (!hasMailConfig(mailConfig)) {
    throw new Error('현재 서버에 메일 발송 설정이 없습니다. SMTP 값을 먼저 설정해주세요.');
  }

  const transporter = nodemailer.createTransport({
    host: mailConfig.host,
    port: mailConfig.port,
    secure: mailConfig.secure,
    auth: mailConfig.user && mailConfig.pass ? { user: mailConfig.user, pass: mailConfig.pass } : undefined,
  });

  await transporter.sendMail({
    from: mailConfig.from,
    to: email,
    subject: '[Phase Vuln Coach] 이메일 인증 코드',
    text: `Phase Vuln Coach 이메일 인증 코드: ${code}\n3분 이내에 입력해주세요.`,
    html: `<div style="font-family:Arial,sans-serif;line-height:1.6;color:#111"><h2>Phase Vuln Coach 이메일 인증</h2><p>아래 인증 코드를 3분 이내에 입력해주세요.</p><p style="font-size:28px;font-weight:700;letter-spacing:0.18em">${code}</p></div>`,
  });

  return { delivered: true };
}

export function createAuthConfigPayload(origin = '') {
  return {
    database: 'phase-vuln-coach.sqlite',
    adminConfigured: getAdminEmails().length > 0,
    emailVerificationRequired: true,
    origin,
  };
}

export { getVerificationMessage };
export { clearSignupVerification, createSignupVerifiedSession, hasValidSignupVerification };