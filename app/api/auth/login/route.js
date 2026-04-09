import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';
export const revalidate = 0;
export const fetchCache = 'force-no-store';
export const runtime = 'nodejs';

export async function POST(request) {
  if (!request) {
    return NextResponse.json({ ok: false, message: '잘못된 요청입니다.' }, { status: 400 });
  }

  const [databaseModule, { setAuthenticatedSession }, configModule, { enforceRateLimit }, { commitSession, getSession }] = await Promise.all([
    import('../../../../lib/server/database'),
    import('../../../../lib/server/auth'),
    import('../../../../lib/server/config'),
    import('../../../../lib/server/rate-limit'),
    import('../../../../lib/server/session'),
  ]);
  const body = await request.json().catch(() => ({}));
  const email = String(body.email || '').trim();
  const password = String(body.password || '');
  const rateLimitedResponse = enforceRateLimit(request, {
    namespace: 'auth-login',
    identifier: email,
    ...configModule.AUTH_RATE_LIMITS.login,
  });

  if (rateLimitedResponse) {
    return rateLimitedResponse;
  }

  const user = databaseModule.findUserByEmail(email);

  if (!user || !user.password_hash || !databaseModule.verifyPassword(password, user.password_hash)) {
    return NextResponse.json({ ok: false, message: '이메일 또는 비밀번호가 올바르지 않습니다.' }, { status: 401 });
  }

  const authenticatedUser = databaseModule.touchUserLastLogin(user.id);
  const response = NextResponse.json({ ok: true, user: databaseModule.formatUser(authenticatedUser, 'local') });
  return commitSession(response, setAuthenticatedSession(await getSession(request), authenticatedUser.id, 'local'));
}
