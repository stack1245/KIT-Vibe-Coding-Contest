import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';
export const revalidate = 0;
export const fetchCache = 'force-no-store';
export const runtime = 'nodejs';

export async function POST(request) {
  if (!request) {
    return NextResponse.json({ ok: false, message: '잘못된 요청입니다.' }, { status: 400 });
  }

  const [{ clearSignupVerification, createSignupVerifiedSession }, { commitSession, getSession }, databaseModule, configModule, { enforceRateLimit }] = await Promise.all([
    import('../../../../../lib/server/auth'),
    import('../../../../../lib/server/session'),
    import('../../../../../lib/server/database'),
    import('../../../../../lib/server/config'),
    import('../../../../../lib/server/rate-limit'),
  ]);
  const body = await request.json().catch(() => ({}));
  const email = String(body.email || '').trim();
  const code = String(body.code || '').trim();
  const session = await getSession(request);
  const rateLimitedResponse = enforceRateLimit(request, {
    namespace: 'verification-confirm',
    identifier: email,
    ...configModule.AUTH_RATE_LIMITS.verificationConfirm,
  });

  if (rateLimitedResponse) {
    return commitSession(rateLimitedResponse, clearSignupVerification(session));
  }

  if (!email || !code) {
    return NextResponse.json({ ok: false, message: '이메일과 인증 코드를 입력해주세요.' }, { status: 400 });
  }

  if (!databaseModule.isValidEmail(email)) {
    return NextResponse.json({ ok: false, message: '올바른 이메일 형식을 입력해주세요.' }, { status: 400 });
  }

  const verificationResult = databaseModule.verifyEmailVerificationCode(email, code);
  if (!verificationResult.ok) {
    return commitSession(
      NextResponse.json({ ok: false, message: configModule.getVerificationMessage(verificationResult.reason) }, { status: 400 }),
      clearSignupVerification(session)
    );
  }

  return commitSession(
    NextResponse.json({ ok: true, message: '이메일 인증이 완료되었습니다.' }),
    createSignupVerifiedSession(session, email)
  );
}
