import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';
export const revalidate = 0;
export const fetchCache = 'force-no-store';
export const runtime = 'nodejs';

export async function POST(request) {
  if (!request) {
    return NextResponse.json({ ok: false, message: '잘못된 요청입니다.' }, { status: 400 });
  }

  const [{ sendPasswordResetEmail }, configModule, databaseModule, { enforceRateLimit }] = await Promise.all([
    import('../../../../../lib/server/auth'),
    import('../../../../../lib/server/config'),
    import('../../../../../lib/server/database'),
    import('../../../../../lib/server/rate-limit'),
  ]);
  const body = await request.json().catch(() => ({}));
  const email = String(body.email || '').trim();
  const rateLimitedResponse = enforceRateLimit(request, {
    namespace: 'password-reset-request',
    identifier: email,
    ...configModule.AUTH_RATE_LIMITS.verificationRequest,
  });

  if (rateLimitedResponse) {
    return rateLimitedResponse;
  }

  if (!email) {
    return NextResponse.json({ ok: false, message: '이메일을 입력해주세요.' }, { status: 400 });
  }

  if (!databaseModule.isValidEmail(email)) {
    return NextResponse.json({ ok: false, message: '올바른 이메일 형식을 입력해주세요.' }, { status: 400 });
  }

  if (!databaseModule.findUserByEmail(email)) {
    return NextResponse.json({ ok: false, message: '해당 이메일로 가입된 계정이 없습니다.' }, { status: 404 });
  }

  const code = configModule.generateVerificationCode();
  const expiresAt = new Date(Date.now() + configModule.SIGNUP_CODE_TTL_MS).toISOString();

  try {
    await sendPasswordResetEmail(email, code);
    databaseModule.saveEmailVerification(email, code, expiresAt);
    return NextResponse.json({ ok: true, message: '인증 코드를 이메일로 전송했습니다.', expiresAt });
  } catch (error) {
    return NextResponse.json({ ok: false, message: configModule.getMailErrorMessage(error) }, { status: 503 });
  }
}
