import { NextResponse } from 'next/server';
import { generateOAuthState, getGitHubConfig, hasGitHubConfig } from '../../../lib/server/config';
import { commitSession, getSession } from '../../../lib/server/session';

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
  const mode = request.nextUrl.searchParams.get('mode') === 'link'
    ? 'link'
    : request.nextUrl.searchParams.get('mode') === 'signup'
      ? 'signup'
      : 'signin';
  const session = await getSession();

  if (!hasGitHubConfig(config)) {
    return redirectWithParams(request, '/login', { error: 'config_missing' }, mode);
  }

  if (mode === 'link' && !session.accountId) {
    return redirectWithParams(request, '/login', { error: 'login_required' }, 'signin');
  }

  const state = generateOAuthState();
  const nextSession = {
    ...session,
    oauthState: state,
    oauthMode: mode,
    oauthAccountId: session.accountId || null,
  };

  const authorizeUrl = new URL('https://github.com/login/oauth/authorize');
  authorizeUrl.searchParams.set('client_id', config.clientId);
  authorizeUrl.searchParams.set('redirect_uri', config.redirectUri);
  authorizeUrl.searchParams.set('scope', config.scope);
  authorizeUrl.searchParams.set('state', state);

  return commitSession(NextResponse.redirect(authorizeUrl), nextSession);
}