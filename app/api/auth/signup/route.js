import { NextResponse } from 'next/server';
import { clearSignupVerification, hasValidSignupVerification, setAuthenticatedSession } from '../../../../lib/server/auth';
import { commitSession, getSession } from '../../../../lib/server/session';
import { createLocalUser, findUserByEmail, formatUser, isStrongPassword, isValidEmail } from '../../../../lib/server/database';
import { AUTH_RATE_LIMITS, getVerificationMessage } from '../../../../lib/server/config';
import { enforceRateLimit } from '../../../../lib/server/rate-limit';

export async function POST(request) {
  const body = await request.json().catch(() => ({}));
  const email = String(body.email || '').trim();
  const password = String(body.password || '');
  const confirmPassword = String(body.confirmPassword || '');
  const session = await getSession();
  const rateLimitedResponse = enforceRateLimit(request, {
    namespace: 'auth-signup',
    identifier: email,
    ...AUTH_RATE_LIMITS.signup,
  });

  if (rateLimitedResponse) {
    return rateLimitedResponse;
  }

  if (!email || !password) {
    return NextResponse.json({ ok: false, message: '이메일과 비밀번호를 모두 입력해주세요.' }, { status: 400 });
  }

  if (!isValidEmail(email)) {
    return NextResponse.json({ ok: false, message: '올바른 이메일 형식을 입력해주세요.' }, { status: 400 });
  }

  if (!isStrongPassword(password)) {
    return NextResponse.json({ ok: false, message: '비밀번호는 영문과 숫자를 포함한 8자 이상이어야 합니다.' }, { status: 400 });
  }

  if (password !== confirmPassword) {
    return NextResponse.json({ ok: false, message: '비밀번호와 비밀번호 확인이 일치하지 않습니다.' }, { status: 400 });
  }

  if (findUserByEmail(email)) {
    return NextResponse.json({ ok: false, message: '이미 가입된 이메일입니다.' }, { status: 409 });
  }

  const signupVerification = hasValidSignupVerification(session, email);
  if (!signupVerification.ok) {
    return NextResponse.json({ ok: false, message: getVerificationMessage(signupVerification.reason) }, { status: 400 });
  }

  const user = createLocalUser({ email, password });
  const response = NextResponse.json({ ok: true, user: formatUser(user, 'local') }, { status: 201 });
  return commitSession(response, clearSignupVerification(setAuthenticatedSession(session, user.id, 'local')));
}