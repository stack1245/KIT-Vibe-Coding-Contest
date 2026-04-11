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

function sanitizeReturnTo(value) {
  const nextValue = String(value || '').trim();

  if (!nextValue.startsWith('/') || nextValue.startsWith('//')) {
    return '';
  }

  if (nextValue.startsWith('/auth/') || nextValue.startsWith('/api/')) {
    return '';
  }

  return nextValue;
}

function getLoginRedirectParams(error, returnTo) {
  return returnTo
    ? { error, returnTo }
    : { error };
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
  const oauthReturnTo = sanitizeReturnTo(session.oauthReturnTo);
  const successRedirect = oauthReturnTo || '/dashboard';
  const code = request.nextUrl.searchParams.get('code');
  const state = request.nextUrl.searchParams.get('state');

  if (request.nextUrl.searchParams.get('error')) {
    return commitSession(
      redirectWithParams(appOrigin, '/login', getLoginRedirectParams('github_access_denied', oauthReturnTo), mode),
      clearOAuthSession(session)
    );
  }

  if (!configModule.hasGitHubConfig(config)) {
    return commitSession(
      redirectWithParams(appOrigin, '/login', getLoginRedirectParams('config_missing', oauthReturnTo), mode),
      clearOAuthSession(session)
    );
  }

  if (!code || !state || state !== session.oauthState) {
    return commitSession(
      redirectWithParams(appOrigin, '/login', getLoginRedirectParams('invalid_state', oauthReturnTo), mode),
      clearOAuthSession(session)
    );
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
      return commitSession(
        redirectWithParams(appOrigin, '/login', getLoginRedirectParams('token_exchange_failed', oauthReturnTo), mode),
        clearOAuthSession(session)
      );
    }

    const githubUser = await fetchGitHubUser(tokenPayload.access_token);
    const githubTokenScope = String(tokenPayload.scope || '');

    if (mode === 'link') {
      const currentUserId = session.oauthAccountId || session.accountId;

      if (!currentUserId) {
        return commitSession(
          redirectWithParams(appOrigin, '/login', getLoginRedirectParams('login_required', oauthReturnTo), 'signin'),
          clearOAuthSession(session)
        );
      }

      const currentUser = databaseModule.findUserById(currentUserId);
      const linkedUser = databaseModule.findUserByGitHubId(githubUser.id);

      if (!currentUser) {
        return commitSession(
          redirectWithParams(appOrigin, '/login', getLoginRedirectParams('login_required', oauthReturnTo), 'signin'),
          clearOAuthSession(session)
        );
      }

      if (linkedUser && linkedUser.id !== currentUser.id) {
        return commitSession(
          redirectWithParams(appOrigin, '/login', getLoginRedirectParams('github_already_linked', oauthReturnTo), 'signin'),
          clearOAuthSession(session)
        );
      }

      const updatedUser = databaseModule.linkGitHubToUser(currentUser.id, githubUser, {
        accessToken: tokenPayload.access_token,
        tokenScope: githubTokenScope,
      });
      return commitSession(
        redirectWithParams(appOrigin, successRedirect, { auth: 'link_success' }),
        setAuthenticatedSession(clearOAuthSession(session), updatedUser.id, session.authMethod || 'local')
      );
    }

    const linkedUser = databaseModule.findUserByGitHubId(githubUser.id);
    if (linkedUser) {
      databaseModule.linkGitHubToUser(linkedUser.id, githubUser, {
        accessToken: tokenPayload.access_token,
        tokenScope: githubTokenScope,
      });
      const authenticatedUser = databaseModule.touchUserLastLogin(linkedUser.id);
      return commitSession(
        redirectWithParams(appOrigin, successRedirect, { auth: 'success' }),
        setAuthenticatedSession(clearOAuthSession(session), authenticatedUser.id, 'github')
      );
    }

    if (!githubUser.email) {
      return commitSession(
        redirectWithParams(appOrigin, '/login', getLoginRedirectParams('github_email_missing', oauthReturnTo), mode),
        clearOAuthSession(session)
      );
    }

    const existingEmailUser = databaseModule.findUserByEmail(githubUser.email);
    if (existingEmailUser) {
      return commitSession(
        redirectWithParams(appOrigin, '/login', getLoginRedirectParams('github_not_linked', oauthReturnTo), 'signin'),
        clearOAuthSession(session)
      );
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

    return commitSession(
      redirectWithParams(appOrigin, successRedirect, { auth: 'success' }),
      setAuthenticatedSession(clearOAuthSession(session), createdUser.id, 'github')
    );
  } catch {
    return commitSession(
      redirectWithParams(appOrigin, '/login', getLoginRedirectParams('github_request_failed', oauthReturnTo), mode),
      clearOAuthSession(session)
    );
  }
}
