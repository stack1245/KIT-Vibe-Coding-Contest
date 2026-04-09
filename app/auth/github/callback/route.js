import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';
export const revalidate = 0;
export const fetchCache = 'force-no-store';
export const runtime = 'nodejs';

function redirectWithParams(appOrigin, pathname, params = {}, hash = '') {
  const url = new URL(pathname, `${appOrigin}/`);
  Object.entries(params).forEach(([key, value]) => {
    if (value) {
      url.searchParams.set(key, value);
    }
  });
  url.hash = hash;
  return NextResponse.redirect(url);
}

export async function GET(request) {
  if (!request) {
    return NextResponse.redirect(new URL('/login', 'http://localhost:3000'));
  }

  const [
    { clearOAuthSession, fetchGitHubUser, setAuthenticatedSession },
    databaseModule,
    configModule,
    { commitSession, getSession },
  ] = await Promise.all([
    import('../../../../lib/server/auth'),
    import('../../../../lib/server/database'),
    import('../../../../lib/server/config'),
    import('../../../../lib/server/session'),
  ]);
  const appOrigin = configModule.getRequestAppOrigin(request);
  const config = configModule.getGitHubConfig(request);
  const session = await getSession(request);
  const mode = session.oauthMode === 'link' ? 'link' : session.oauthMode === 'signup' ? 'signup' : 'signin';
  const code = request.nextUrl.searchParams.get('code');
  const state = request.nextUrl.searchParams.get('state');

  if (request.nextUrl.searchParams.get('error')) {
    return commitSession(redirectWithParams(appOrigin, '/login', { error: 'github_access_denied' }, mode), clearOAuthSession(session));
  }

  if (!configModule.hasGitHubConfig(config)) {
    return commitSession(redirectWithParams(appOrigin, '/login', { error: 'config_missing' }, mode), clearOAuthSession(session));
  }

  if (!code || !state || state !== session.oauthState) {
    return commitSession(redirectWithParams(appOrigin, '/login', { error: 'invalid_state' }, mode), clearOAuthSession(session));
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
        code,
        redirect_uri: config.redirectUri,
        state,
      }),
      cache: 'no-store',
    });

    const tokenPayload = await tokenResponse.json();
    if (!tokenResponse.ok || tokenPayload.error || !tokenPayload.access_token) {
      return commitSession(redirectWithParams(appOrigin, '/login', { error: 'token_exchange_failed' }, mode), clearOAuthSession(session));
    }

    const githubUser = await fetchGitHubUser(tokenPayload.access_token);
    const githubTokenScope = String(tokenPayload.scope || '');

    if (mode === 'link') {
      const currentUserId = session.oauthAccountId || session.accountId;

      if (!currentUserId) {
        return commitSession(redirectWithParams(appOrigin, '/login', { error: 'login_required' }, 'signin'), clearOAuthSession(session));
      }

      const currentUser = databaseModule.findUserById(currentUserId);
      const linkedUser = databaseModule.findUserByGitHubId(githubUser.id);

      if (!currentUser) {
        return commitSession(redirectWithParams(appOrigin, '/login', { error: 'login_required' }, 'signin'), clearOAuthSession(session));
      }

      if (linkedUser && linkedUser.id !== currentUser.id) {
        return commitSession(redirectWithParams(appOrigin, '/login', { error: 'github_already_linked' }, 'signin'), clearOAuthSession(session));
      }

      const updatedUser = databaseModule.linkGitHubToUser(currentUser.id, githubUser, {
        accessToken: tokenPayload.access_token,
        tokenScope: githubTokenScope,
      });
      return commitSession(redirectWithParams(appOrigin, '/dashboard', { auth: 'link_success' }), setAuthenticatedSession(clearOAuthSession(session), updatedUser.id, session.authMethod || 'local'));
    }

    const linkedUser = databaseModule.findUserByGitHubId(githubUser.id);
    if (linkedUser) {
      databaseModule.linkGitHubToUser(linkedUser.id, githubUser, {
        accessToken: tokenPayload.access_token,
        tokenScope: githubTokenScope,
      });
      const authenticatedUser = databaseModule.touchUserLastLogin(linkedUser.id);
      return commitSession(redirectWithParams(appOrigin, '/dashboard', { auth: 'success' }), setAuthenticatedSession(clearOAuthSession(session), authenticatedUser.id, 'github'));
    }

    if (!githubUser.email) {
      return commitSession(redirectWithParams(appOrigin, '/login', { error: 'github_email_missing' }, mode), clearOAuthSession(session));
    }

    const existingEmailUser = databaseModule.findUserByEmail(githubUser.email);
    if (existingEmailUser) {
      return commitSession(redirectWithParams(appOrigin, '/login', { error: 'github_not_linked' }, 'signin'), clearOAuthSession(session));
    }

    const createdUser = databaseModule.createGitHubUser({
      email: githubUser.email,
      displayName: githubUser.name,
      githubId: githubUser.id,
      githubLogin: githubUser.login,
      githubAvatarUrl: githubUser.avatarUrl,
      githubProfileUrl: githubUser.profileUrl,
      githubAccessToken: tokenPayload.access_token,
      githubTokenScope,
    });

    return commitSession(redirectWithParams(appOrigin, '/dashboard', { auth: 'success' }), setAuthenticatedSession(clearOAuthSession(session), createdUser.id, 'github'));
  } catch {
    return commitSession(redirectWithParams(appOrigin, '/login', { error: 'github_request_failed' }, mode), clearOAuthSession(session));
  }
}
