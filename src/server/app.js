const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const dotenv = require('dotenv');
const express = require('express');
const session = require('express-session');

const {
  databaseFilePath,
  formatUser,
  findUserByEmail,
  findUserByGitHubId,
  findUserById,
  createGitHubUser,
  createLocalUser,
  deleteUserById,
  isStrongPassword,
  isValidEmail,
  linkGitHubToUser,
  listUsers,
  saveEmailVerification,
  verifyEmailVerificationCode,
  verifyPassword,
} = require('./database');

dotenv.config({ quiet: true });

const app = express();
const rootDir = path.resolve(__dirname, '..', '..');
const pagesDir = path.join(rootDir, 'src', 'pages');
const assetsDir = path.join(rootDir, 'src', 'assets');
const SIGNUP_CODE_TTL_MS = 1000 * 60 * 3;
const SIGNUP_VERIFICATION_SESSION_TTL_MS = 1000 * 60 * 10;

const paths = {
  home: path.join(pagesDir, 'index.html'),
  login: path.join(pagesDir, 'login.html'),
  dashboard: path.join(pagesDir, 'dashboard.html'),
  analysis: path.join(pagesDir, 'analysis.html'),
  admin: path.join(pagesDir, 'admin.html'),
};

const port = Number(process.env.PORT || 3000);

app.set('trust proxy', 1);

app.use(express.json());
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  next();
});
app.use(
  session({
    name: 'phase.sid',
    secret: process.env.SESSION_SECRET || 'change-this-session-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  })
);

app.use('/assets', express.static(assetsDir));

function getBaseUrl(req) {
  return process.env.APP_BASE_URL || `${req.protocol}://${req.get('host')}`;
}

function getGitHubConfig(req) {
  return {
    clientId: process.env.GITHUB_CLIENT_ID || '',
    clientSecret: process.env.GITHUB_CLIENT_SECRET || '',
    redirectUri:
      process.env.GITHUB_REDIRECT_URI || `${getBaseUrl(req)}/auth/github/callback`,
    scope: process.env.GITHUB_SCOPE || 'read:user user:email',
  };
}

function hasGitHubConfig(config) {
  return Boolean(config.clientId && config.clientSecret && config.redirectUri);
}

function getMailConfig() {
  return {
    host: process.env.SMTP_HOST || '',
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE || 'false') === 'true',
    user: process.env.SMTP_USER || '',
    pass: process.env.SMTP_PASS || '',
    from: process.env.SMTP_FROM || 'Phase Vuln Coach <no-reply@phase.local>',
  };
}

function hasMailConfig(config) {
  return Boolean(config.host && config.port && config.from);
}

function createMailTransport(config) {
  if (!hasMailConfig(config)) {
    return null;
  }

  return nodemailer.createTransport({
    host: config.host,
    port: config.port,
    secure: config.secure,
    auth: config.user && config.pass ? { user: config.user, pass: config.pass } : undefined,
  });
}

function generateVerificationCode() {
  return String(crypto.randomInt(100000, 1000000));
}

function getVerificationMessage(reason) {
  const messages = {
    missing: '이메일 인증 코드 요청이 없습니다. 다시 인증을 요청해주세요.',
    expired: '인증 코드가 만료되었습니다. 다시 요청해주세요.',
    invalid: '인증 코드가 올바르지 않습니다.',
    session_expired: '이메일 인증 완료 상태가 만료되었습니다. 다시 인증해주세요.',
  };

  return messages[reason] || '이메일 인증에 실패했습니다.';
}

function clearSignupVerification(req) {
  req.session.signupVerification = null;
}

function hasValidSignupVerification(req, email) {
  const signupVerification = req.session.signupVerification;

  if (!signupVerification) {
    return { ok: false, reason: 'missing' };
  }

  if (signupVerification.email !== String(email || '').trim().toLowerCase()) {
    return { ok: false, reason: 'missing' };
  }

  if (!signupVerification.expiresAt || new Date(signupVerification.expiresAt).getTime() < Date.now()) {
    clearSignupVerification(req);
    return { ok: false, reason: 'session_expired' };
  }

  return { ok: true };
}

function getMailErrorMessage(error) {
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

async function sendVerificationEmail(email, code) {
  const mailConfig = getMailConfig();
  const transporter = createMailTransport(mailConfig);

  if (!transporter) {
    throw new Error('현재 서버에 메일 발송 설정이 없습니다. SMTP 값을 먼저 설정해주세요.');
  }

  await transporter.sendMail({
    from: mailConfig.from,
    to: email,
    subject: '[Phase Vuln Coach] 이메일 인증 코드',
    text: `Phase Vuln Coach 이메일 인증 코드: ${code}\n3분 이내에 입력해주세요.`,
    html: `<div style="font-family:Arial,sans-serif;line-height:1.6;color:#111"><h2>Phase Vuln Coach 이메일 인증</h2><p>아래 인증 코드를 3분 이내에 입력해주세요.</p><p style="font-size:28px;font-weight:700;letter-spacing:0.18em">${code}</p></div>`,
  });

  return { delivered: true };
}

function getAdminEmails() {
  return String(process.env.ADMIN_EMAILS || '')
    .split(',')
    .map((email) => email.trim().toLowerCase())
    .filter(Boolean);
}

function isAdminEmail(email) {
  return getAdminEmails().includes(String(email || '').trim().toLowerCase());
}

function buildSessionUser(row, authMethod) {
  const user = formatUser(row, authMethod);

  if (!user) {
    return null;
  }

  return {
    ...user,
    isAdmin: isAdminEmail(user.email),
  };
}

function setAuthenticatedSession(req, userId, authMethod) {
  req.session.accountId = userId;
  req.session.authMethod = authMethod;
}

function clearOAuthSession(req) {
  req.session.oauthState = null;
  req.session.oauthMode = null;
  req.session.oauthAccountId = null;
}

function getSessionUser(req) {
  if (!req.session.accountId) {
    return null;
  }

  const user = findUserById(req.session.accountId);

  if (!user) {
    req.session.accountId = null;
    req.session.authMethod = null;
    return null;
  }

  return buildSessionUser(user, req.session.authMethod || 'local');
}

function ensureAuthenticated(req, res, next) {
  const user = getSessionUser(req);

  if (!user) {
    return res.redirect('/login#signin');
  }

  req.currentUser = user;
  return next();
}

function ensureAdmin(req, res, next) {
  const user = getSessionUser(req);

  if (!user) {
    return res.redirect('/login#signin');
  }

  if (!user.isAdmin) {
    return res.status(403).send('관리자 권한이 필요합니다.');
  }

  req.currentUser = user;
  return next();
}

function redirectWithParams(res, pathname, params = {}, hash = '') {
  const search = new URLSearchParams();

  Object.entries(params).forEach(([key, value]) => {
    if (value) {
      search.set(key, value);
    }
  });

  const query = search.toString();
  res.redirect(`${pathname}${query ? `?${query}` : ''}${hash}`);
}

function resolvePrimaryEmail(emails) {
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

async function fetchGitHubUser(accessToken) {
  const headers = {
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${accessToken}`,
    'User-Agent': 'phase-vuln-coach',
  };

  const [profileResponse, emailsResponse] = await Promise.all([
    fetch('https://api.github.com/user', { headers }),
    fetch('https://api.github.com/user/emails', { headers }),
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

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

app.get('/api/auth/config', (req, res) => {
  const config = getGitHubConfig(req);

  res.json({
    enabled: hasGitHubConfig(config),
    provider: 'github',
    loginUrl: '/auth/github',
    linkUrl: '/auth/github?mode=link',
    database: path.basename(databaseFilePath),
    adminConfigured: getAdminEmails().length > 0,
    emailVerificationRequired: true,
    emailDeliveryConfigured: hasMailConfig(getMailConfig()),
  });
});

app.get('/api/auth/session', (req, res) => {
  const user = getSessionUser(req);

  if (!user) {
    return res.json({ authenticated: false, user: null });
  }

  return res.json({ authenticated: true, user });
});

app.post('/api/auth/email-verification/request', async (req, res) => {
  const email = String(req.body?.email || '').trim();

  clearSignupVerification(req);

  if (!email) {
    return res.status(400).json({ ok: false, message: '이메일을 입력해주세요.' });
  }

  if (!isValidEmail(email)) {
    return res.status(400).json({ ok: false, message: '올바른 이메일 형식을 입력해주세요.' });
  }

  if (findUserByEmail(email)) {
    return res.status(409).json({ ok: false, message: '이미 가입된 이메일입니다.' });
  }

  const code = generateVerificationCode();
  const expiresAt = new Date(Date.now() + SIGNUP_CODE_TTL_MS).toISOString();

  try {
    await sendVerificationEmail(email, code);
    saveEmailVerification(email, code, expiresAt);

    return res.json({
      ok: true,
      message: '인증 코드를 이메일로 전송했습니다.',
      expiresAt,
    });
  } catch (error) {
    return res.status(503).json({ ok: false, message: getMailErrorMessage(error) });
  }
});

app.post('/api/auth/email-verification/confirm', (req, res) => {
  const email = String(req.body?.email || '').trim();
  const code = String(req.body?.code || '').trim();

  if (!email || !code) {
    return res.status(400).json({ ok: false, message: '이메일과 인증 코드를 입력해주세요.' });
  }

  if (!isValidEmail(email)) {
    return res.status(400).json({ ok: false, message: '올바른 이메일 형식을 입력해주세요.' });
  }

  const verificationResult = verifyEmailVerificationCode(email, code);

  if (!verificationResult.ok) {
    clearSignupVerification(req);
    return res.status(400).json({ ok: false, message: getVerificationMessage(verificationResult.reason) });
  }

  req.session.signupVerification = {
    email: email.toLowerCase(),
    verifiedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + SIGNUP_VERIFICATION_SESSION_TTL_MS).toISOString(),
  };

  return res.json({ ok: true, message: '이메일 인증이 완료되었습니다.' });
});

app.delete('/api/auth/account', (req, res) => {
  const user = getSessionUser(req);

  if (!user) {
    return res.status(401).json({ ok: false, message: '로그인이 필요합니다.' });
  }

  const deleted = deleteUserById(user.id);

  if (!deleted) {
    return res.status(404).json({ ok: false, message: '삭제할 계정을 찾지 못했습니다.' });
  }

  req.session.destroy((error) => {
    if (error) {
      return res.status(500).json({ ok: false, message: '회원탈퇴는 완료되었지만 세션 정리에 실패했습니다.' });
    }

    res.clearCookie('phase.sid');
    return res.json({ ok: true });
  });
});

app.get('/api/admin/users', (req, res) => {
  const user = getSessionUser(req);

  if (!user) {
    return res.status(401).json({ ok: false, message: '로그인이 필요합니다.' });
  }

  if (!user.isAdmin) {
    return res.status(403).json({ ok: false, message: '관리자 권한이 필요합니다.' });
  }

  return res.json({
    ok: true,
    users: listUsers().map((row) => buildSessionUser(row, row.auth_provider)),
  });
});

app.delete('/api/admin/users/:id', (req, res) => {
  const user = getSessionUser(req);
  const targetId = Number(req.params.id);

  if (!user) {
    return res.status(401).json({ ok: false, message: '로그인이 필요합니다.' });
  }

  if (!user.isAdmin) {
    return res.status(403).json({ ok: false, message: '관리자 권한이 필요합니다.' });
  }

  if (!Number.isInteger(targetId) || targetId <= 0) {
    return res.status(400).json({ ok: false, message: '올바르지 않은 회원 ID입니다.' });
  }

  if (targetId === user.id) {
    return res.status(400).json({ ok: false, message: '본인 계정은 관리자 목록에서 삭제할 수 없습니다. 대시보드에서 회원탈퇴를 사용하세요.' });
  }

  const deleted = deleteUserById(targetId);

  if (!deleted) {
    return res.status(404).json({ ok: false, message: '삭제할 회원을 찾지 못했습니다.' });
  }

  return res.json({ ok: true });
});

app.post('/api/auth/signup', (req, res) => {
  const email = String(req.body?.email || '').trim();
  const password = String(req.body?.password || '');

  if (!email || !password) {
    return res.status(400).json({ ok: false, message: '이메일과 비밀번호를 모두 입력해주세요.' });
  }

  if (!isValidEmail(email)) {
    return res.status(400).json({ ok: false, message: '올바른 이메일 형식을 입력해주세요.' });
  }

  if (!isStrongPassword(password)) {
    return res.status(400).json({ ok: false, message: '비밀번호는 영문과 숫자를 포함한 8자 이상이어야 합니다.' });
  }

  if (findUserByEmail(email)) {
    return res.status(409).json({ ok: false, message: '이미 가입된 이메일입니다.' });
  }

  const signupVerification = hasValidSignupVerification(req, email);

  if (!signupVerification.ok) {
    return res.status(400).json({ ok: false, message: getVerificationMessage(signupVerification.reason) });
  }

  const user = createLocalUser({ email, password });
  clearSignupVerification(req);
  setAuthenticatedSession(req, user.id, 'local');

  return res.status(201).json({ ok: true, user: formatUser(user, 'local') });
});

app.post('/api/auth/login', (req, res) => {
  const email = String(req.body?.email || '').trim();
  const password = String(req.body?.password || '');
  const user = findUserByEmail(email);

  if (!user || !user.password_hash || !verifyPassword(password, user.password_hash)) {
    return res.status(401).json({ ok: false, message: '이메일 또는 비밀번호가 올바르지 않습니다.' });
  }

  setAuthenticatedSession(req, user.id, 'local');
  return res.json({ ok: true, user: formatUser(user, 'local') });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      return res.status(500).json({ ok: false, message: '로그아웃에 실패했습니다.' });
    }

    res.clearCookie('phase.sid');
    return res.json({ ok: true });
  });
});

app.get('/auth/github', (req, res) => {
  const config = getGitHubConfig(req);
  const mode = req.query.mode === 'link' ? 'link' : req.query.mode === 'signup' ? 'signup' : 'signin';

  if (!hasGitHubConfig(config)) {
    return redirectWithParams(res, '/login', { error: 'config_missing' }, `#${mode}`);
  }

  if (mode === 'link' && !req.session.accountId) {
    return redirectWithParams(res, '/login', { error: 'login_required' }, '#signin');
  }

  const state = crypto.randomBytes(24).toString('hex');
  req.session.oauthState = state;
  req.session.oauthMode = mode;
  req.session.oauthAccountId = req.session.accountId || null;

  const authorizeUrl = new URL('https://github.com/login/oauth/authorize');
  authorizeUrl.searchParams.set('client_id', config.clientId);
  authorizeUrl.searchParams.set('redirect_uri', config.redirectUri);
  authorizeUrl.searchParams.set('scope', config.scope);
  authorizeUrl.searchParams.set('state', state);

  return res.redirect(authorizeUrl.toString());
});

app.get('/auth/github/callback', async (req, res) => {
  const config = getGitHubConfig(req);
  const mode = req.session.oauthMode === 'link' ? 'link' : req.session.oauthMode === 'signup' ? 'signup' : 'signin';

  if (req.query.error) {
    return redirectWithParams(res, '/login', { error: 'github_access_denied' }, `#${mode}`);
  }

  if (!hasGitHubConfig(config)) {
    return redirectWithParams(res, '/login', { error: 'config_missing' }, `#${mode}`);
  }

  if (!req.query.code || !req.query.state || req.query.state !== req.session.oauthState) {
    return redirectWithParams(res, '/login', { error: 'invalid_state' }, `#${mode}`);
  }

  try {
    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        'User-Agent': 'phase-vuln-coach',
      },
      body: JSON.stringify({
        client_id: config.clientId,
        client_secret: config.clientSecret,
        code: req.query.code,
        redirect_uri: config.redirectUri,
        state: req.query.state,
      }),
    });

    const tokenPayload = await tokenResponse.json();

    if (!tokenResponse.ok || tokenPayload.error || !tokenPayload.access_token) {
      return redirectWithParams(res, '/login', { error: 'token_exchange_failed' }, `#${mode}`);
    }

    const githubUser = await fetchGitHubUser(tokenPayload.access_token);

    if (mode === 'link') {
      const currentUserId = req.session.oauthAccountId || req.session.accountId;

      if (!currentUserId) {
        clearOAuthSession(req);
        return redirectWithParams(res, '/login', { error: 'login_required' }, '#signin');
      }

      const currentUser = findUserById(currentUserId);
      const linkedUser = findUserByGitHubId(githubUser.id);

      if (!currentUser) {
        clearOAuthSession(req);
        return redirectWithParams(res, '/login', { error: 'login_required' }, '#signin');
      }

      if (linkedUser && linkedUser.id !== currentUser.id) {
        clearOAuthSession(req);
        return redirectWithParams(res, '/login', { error: 'github_already_linked' }, '#signin');
      }

      const updatedUser = linkGitHubToUser(currentUser.id, githubUser);
      clearOAuthSession(req);
      setAuthenticatedSession(req, updatedUser.id, req.session.authMethod || 'local');
      return redirectWithParams(res, '/dashboard', { auth: 'link_success' });
    }

    const linkedUser = findUserByGitHubId(githubUser.id);

    if (linkedUser) {
      clearOAuthSession(req);
      setAuthenticatedSession(req, linkedUser.id, 'github');
      return redirectWithParams(res, '/dashboard', { auth: 'success' });
    }

    if (!githubUser.email) {
      clearOAuthSession(req);
      return redirectWithParams(res, '/login', { error: 'github_email_missing' }, `#${mode}`);
    }

    const existingEmailUser = findUserByEmail(githubUser.email);

    if (existingEmailUser) {
      clearOAuthSession(req);
      return redirectWithParams(res, '/login', { error: 'github_not_linked' }, '#signin');
    }

    const createdUser = createGitHubUser({
      email: githubUser.email,
      displayName: githubUser.name,
      githubId: githubUser.id,
      githubLogin: githubUser.login,
      githubAvatarUrl: githubUser.avatarUrl,
      githubProfileUrl: githubUser.profileUrl,
    });

    clearOAuthSession(req);
    setAuthenticatedSession(req, createdUser.id, 'github');
    return redirectWithParams(res, '/dashboard', { auth: 'success' });
  } catch (_error) {
    clearOAuthSession(req);
    return redirectWithParams(res, '/login', { error: 'github_request_failed' }, `#${mode}`);
  }
});

app.get('/login', (req, res) => {
  const user = getSessionUser(req);

  if (user) {
    return res.redirect('/dashboard');
  }

  res.sendFile(paths.login);
});

app.get('/dashboard', ensureAuthenticated, (_req, res) => {
  res.sendFile(paths.dashboard);
});

app.get('/analysis', ensureAuthenticated, (_req, res) => {
  res.sendFile(paths.analysis);
});

app.get('/admin', ensureAdmin, (_req, res) => {
  res.sendFile(paths.admin);
});

app.get('/', (_req, res) => {
  res.sendFile(paths.home);
});

module.exports = {
  app,
  port,
};