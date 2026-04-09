import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';
export const revalidate = 0;
export const fetchCache = 'force-no-store';
export const runtime = 'nodejs';

export async function POST(request) {
  if (!request) {
    return NextResponse.json({ ok: false, message: '잘못된 요청입니다.' }, { status: 400 });
  }

  const [{ clearSignupVerification, hasValidSignupVerification, setAuthenticatedSession }, { commitSession, getSession }, databaseModule, configModule, { enforceRateLimit }] = await Promise.all([
    import('../../../../lib/server/auth'),
    import('../../../../lib/server/session'),
    import('../../../../lib/server/database'),
    import('../../../../lib/server/config'),
    import('../../../../lib/server/rate-limit'),
  ]);
  const body = await request.json().catch(() => ({}));
  const email = String(body.email || '').trim();
  const password = String(body.password || '');
  const confirmPassword = String(body.confirmPassword || '');
  const session = await getSession(request);
  const rateLimitedResponse = enforceRateLimit(request, {
    namespace: 'auth-signup',
    identifier: email,
    ...configModule.AUTH_RATE_LIMITS.signup,
  });

  if (rateLimitedResponse) {
    return rateLimitedResponse;
  }

  if (!email || !password) {
    return NextResponse.json({ ok: false, message: '이메일과 비밀번호를 모두 입력해주세요.' }, { status: 400 });
  }

  if (!databaseModule.isValidEmail(email)) {
    return NextResponse.json({ ok: false, message: '올바른 이메일 형식을 입력해주세요.' }, { status: 400 });
  }

  if (!databaseModule.isStrongPassword(password)) {
    return NextResponse.json({ ok: false, message: '비밀번호는 영문과 숫자를 포함한 8자 이상이어야 합니다.' }, { status: 400 });
  }

  if (password !== confirmPassword) {
    return NextResponse.json({ ok: false, message: '비밀번호와 비밀번호 확인이 일치하지 않습니다.' }, { status: 400 });
  }

  if (databaseModule.findUserByEmail(email)) {
    return NextResponse.json({ ok: false, message: '이미 가입된 이메일입니다.' }, { status: 409 });
  }

  const signupVerification = hasValidSignupVerification(session, email);
  if (!signupVerification.ok) {
    return NextResponse.json({ ok: false, message: configModule.getVerificationMessage(signupVerification.reason) }, { status: 400 });
  }

  const user = databaseModule.createLocalUser({ email, password });
  const response = NextResponse.json({ ok: true, user: databaseModule.formatUser(user, 'local') }, { status: 201 });
  return commitSession(response, clearSignupVerification(setAuthenticatedSession(session, user.id, 'local')));
}
