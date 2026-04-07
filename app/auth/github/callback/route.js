import { NextResponse } from 'next/server';
import { clearOAuthSession, fetchGitHubUser, setAuthenticatedSession } from '../../../../lib/server/auth';
import {
  createGitHubUser,
  findUserByEmail,
  findUserByGitHubId,
  findUserById,
  linkGitHubToUser,
  touchUserLastLogin,
} from '../../../../lib/server/database';
import { getGitHubConfig, hasGitHubConfig } from '../../../../lib/server/config';
import { commitSession, getSession } from '../../../../lib/server/session';

function redirectWithParams(request, pathname, params = {}, hash = '') {
  const url = new URL(pathname, request.url);
  Object.entries(params).forEach(([key, value]) => {
    if (value) {
      url.searchParams.set(key, value);
    }
  });
  url.hash = hash;
  return NextResponse.redirect(url);
}

export async function GET(request) {
  const config = getGitHubConfig(request.nextUrl.origin);
  const session = await getSession();
  const mode = session.oauthMode === 'link' ? 'link' : session.oauthMode === 'signup' ? 'signup' : 'signin';
  const code = request.nextUrl.searchParams.get('code');
  const state = request.nextUrl.searchParams.get('state');

  if (request.nextUrl.searchParams.get('error')) {
    return commitSession(redirectWithParams(request, '/login', { error: 'github_access_denied' }, mode), clearOAuthSession(session));
  }

  if (!hasGitHubConfig(config)) {
    return commitSession(redirectWithParams(request, '/login', { error: 'config_missing' }, mode), clearOAuthSession(session));
  }

  if (!code || !state || state !== session.oauthState) {
    return commitSession(redirectWithParams(request, '/login', { error: 'invalid_state' }, mode), clearOAuthSession(session));
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
      return commitSession(redirectWithParams(request, '/login', { error: 'token_exchange_failed' }, mode), clearOAuthSession(session));
    }

    const githubUser = await fetchGitHubUser(tokenPayload.access_token);

    if (mode === 'link') {
      const currentUserId = session.oauthAccountId || session.accountId;

      if (!currentUserId) {
        return commitSession(redirectWithParams(request, '/login', { error: 'login_required' }, 'signin'), clearOAuthSession(session));
      }

      const currentUser = findUserById(currentUserId);
      const linkedUser = findUserByGitHubId(githubUser.id);

      if (!currentUser) {
        return commitSession(redirectWithParams(request, '/login', { error: 'login_required' }, 'signin'), clearOAuthSession(session));
      }

      if (linkedUser && linkedUser.id !== currentUser.id) {
        return commitSession(redirectWithParams(request, '/login', { error: 'github_already_linked' }, 'signin'), clearOAuthSession(session));
      }

      const updatedUser = linkGitHubToUser(currentUser.id, githubUser);
      return commitSession(redirectWithParams(request, '/dashboard', { auth: 'link_success' }), setAuthenticatedSession(clearOAuthSession(session), updatedUser.id, session.authMethod || 'local'));
    }

    const linkedUser = findUserByGitHubId(githubUser.id);
    if (linkedUser) {
      const authenticatedUser = touchUserLastLogin(linkedUser.id);
      return commitSession(redirectWithParams(request, '/dashboard', { auth: 'success' }), setAuthenticatedSession(clearOAuthSession(session), authenticatedUser.id, 'github'));
    }

    if (!githubUser.email) {
      return commitSession(redirectWithParams(request, '/login', { error: 'github_email_missing' }, mode), clearOAuthSession(session));
    }

    const existingEmailUser = findUserByEmail(githubUser.email);
    if (existingEmailUser) {
      return commitSession(redirectWithParams(request, '/login', { error: 'github_not_linked' }, 'signin'), clearOAuthSession(session));
    }

    const createdUser = createGitHubUser({
      email: githubUser.email,
      displayName: githubUser.name,
      githubId: githubUser.id,
      githubLogin: githubUser.login,
      githubAvatarUrl: githubUser.avatarUrl,
      githubProfileUrl: githubUser.profileUrl,
    });

    return commitSession(redirectWithParams(request, '/dashboard', { auth: 'success' }), setAuthenticatedSession(clearOAuthSession(session), createdUser.id, 'github'));
  } catch {
    return commitSession(redirectWithParams(request, '/login', { error: 'github_request_failed' }, mode), clearOAuthSession(session));
  }
}