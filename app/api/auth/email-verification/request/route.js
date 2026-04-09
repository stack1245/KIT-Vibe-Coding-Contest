import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';
export const revalidate = 0;
export const fetchCache = 'force-no-store';
export const runtime = 'nodejs';

export async function POST(request) {
  if (!request) {
    return NextResponse.json({ ok: false, message: '잘못된 요청입니다.' }, { status: 400 });
  }

  const [{ clearSignupVerification, sendVerificationEmail }, { commitSession, getSession }, databaseModule, configModule, { enforceRateLimit }] = await Promise.all([
    import('../../../../../lib/server/auth'),
    import('../../../../../lib/server/session'),
    import('../../../../../lib/server/database'),
    import('../../../../../lib/server/config'),
    import('../../../../../lib/server/rate-limit'),
  ]);
  const body = await request.json().catch(() => ({}));
  const email = String(body.email || '').trim();
  const session = clearSignupVerification(await getSession(request));
  const rateLimitedResponse = enforceRateLimit(request, {
    namespace: 'verification-request',
    identifier: email,
    ...configModule.AUTH_RATE_LIMITS.verificationRequest,
  });

  if (rateLimitedResponse) {
    return commitSession(rateLimitedResponse, session);
  }

  if (!email) {
    return commitSession(NextResponse.json({ ok: false, message: '이메일을 입력해주세요.' }, { status: 400 }), session);
  }

  if (!databaseModule.isValidEmail(email)) {
    return commitSession(NextResponse.json({ ok: false, message: '올바른 이메일 형식을 입력해주세요.' }, { status: 400 }), session);
  }

  if (databaseModule.findUserByEmail(email)) {
    return commitSession(NextResponse.json({ ok: false, message: '이미 가입된 이메일입니다.' }, { status: 409 }), session);
  }

  const code = configModule.generateVerificationCode();
  const expiresAt = new Date(Date.now() + configModule.SIGNUP_CODE_TTL_MS).toISOString();

  try {
    await sendVerificationEmail(email, code);
    databaseModule.saveEmailVerification(email, code, expiresAt);
    return commitSession(NextResponse.json({ ok: true, message: '인증 코드를 이메일로 전송했습니다.', expiresAt }), session);
  } catch (error) {
    return commitSession(NextResponse.json({ ok: false, message: configModule.getMailErrorMessage(error) }, { status: 503 }), session);
  }
}
