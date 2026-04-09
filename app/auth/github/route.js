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

  const [configModule, { commitSession, getSession }] = await Promise.all([
    import('../../../lib/server/config'),
    import('../../../lib/server/session'),
  ]);
  const appOrigin = configModule.getRequestAppOrigin(request);
  const config = configModule.getGitHubConfig(request);
  const mode = request.nextUrl.searchParams.get('mode') === 'link'
    ? 'link'
    : request.nextUrl.searchParams.get('mode') === 'signup'
      ? 'signup'
      : 'signin';
  const session = await getSession(request);

  if (!configModule.hasGitHubConfig(config)) {
    return redirectWithParams(appOrigin, '/login', { error: 'config_missing' }, mode);
  }

  if (mode === 'link' && !session.accountId) {
    return redirectWithParams(appOrigin, '/login', { error: 'login_required' }, 'signin');
  }

  const state = configModule.generateOAuthState();
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
