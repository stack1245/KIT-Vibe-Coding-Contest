import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';
export const revalidate = 0;
export const fetchCache = 'force-no-store';
export const runtime = 'nodejs';

const resetCodeMessages = {
  missing: '인증 코드 요청이 없습니다. 다시 요청해주세요.',
  expired: '인증 코드가 만료되었습니다. 다시 요청해주세요.',
  invalid: '인증 코드가 올바르지 않습니다.',
};

export async function POST(request) {
  if (!request) {
    return NextResponse.json({ ok: false, message: '잘못된 요청입니다.' }, { status: 400 });
  }

  const [configModule, databaseModule, { enforceRateLimit }] = await Promise.all([
    import('../../../../../lib/server/config'),
    import('../../../../../lib/server/database'),
    import('../../../../../lib/server/rate-limit'),
  ]);
  const body = await request.json().catch(() => ({}));
  const email = String(body.email || '').trim();
  const code = String(body.code || '').trim();
  const password = String(body.password || '');
  const confirmPassword = String(body.confirmPassword || '');
  const rateLimitedResponse = enforceRateLimit(request, {
    namespace: 'password-reset-confirm',
    identifier: email,
    ...configModule.AUTH_RATE_LIMITS.verificationConfirm,
  });

  if (rateLimitedResponse) {
    return rateLimitedResponse;
  }

  if (!email || !code || !password || !confirmPassword) {
    return NextResponse.json({ ok: false, message: '이메일, 인증 코드, 새 비밀번호를 모두 입력해주세요.' }, { status: 400 });
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

  const user = databaseModule.findUserByEmail(email);
  if (!user) {
    return NextResponse.json({ ok: false, message: '해당 이메일로 가입된 계정이 없습니다.' }, { status: 404 });
  }

  if (user.password_hash && databaseModule.verifyPassword(password, user.password_hash)) {
    return NextResponse.json({ ok: false, message: '이전 비밀번호와 동일합니다.' }, { status: 400 });
  }

  const verificationResult = databaseModule.verifyEmailVerificationCode(email, code);
  if (!verificationResult.ok) {
    return NextResponse.json(
      { ok: false, message: resetCodeMessages[verificationResult.reason] || '인증 코드 확인에 실패했습니다.' },
      { status: 400 }
    );
  }

  databaseModule.updateUserPassword(user.id, password);
  return NextResponse.json({ ok: true, message: '비밀번호를 재설정했습니다. 새 비밀번호로 로그인해주세요.' });
}
