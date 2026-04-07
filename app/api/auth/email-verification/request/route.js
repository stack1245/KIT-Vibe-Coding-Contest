import { NextResponse } from 'next/server';
import { clearSignupVerification, sendVerificationEmail } from '../../../../../lib/server/auth';
import { commitSession, getSession } from '../../../../../lib/server/session';
import { findUserByEmail, isValidEmail, saveEmailVerification } from '../../../../../lib/server/database';
import {
  AUTH_RATE_LIMITS,
  SIGNUP_CODE_TTL_MS,
  generateVerificationCode,
  getMailErrorMessage,
} from '../../../../../lib/server/config';
import { enforceRateLimit } from '../../../../../lib/server/rate-limit';

export async function POST(request) {
  const body = await request.json().catch(() => ({}));
  const email = String(body.email || '').trim();
  const session = clearSignupVerification(await getSession());
  const rateLimitedResponse = enforceRateLimit(request, {
    namespace: 'verification-request',
    identifier: email,
    ...AUTH_RATE_LIMITS.verificationRequest,
  });

  if (rateLimitedResponse) {
    return commitSession(rateLimitedResponse, session);
  }

  if (!email) {
    return commitSession(NextResponse.json({ ok: false, message: '이메일을 입력해주세요.' }, { status: 400 }), session);
  }

  if (!isValidEmail(email)) {
    return commitSession(NextResponse.json({ ok: false, message: '올바른 이메일 형식을 입력해주세요.' }, { status: 400 }), session);
  }

  if (findUserByEmail(email)) {
    return commitSession(NextResponse.json({ ok: false, message: '이미 가입된 이메일입니다.' }, { status: 409 }), session);
  }

  const code = generateVerificationCode();
  const expiresAt = new Date(Date.now() + SIGNUP_CODE_TTL_MS).toISOString();

  try {
    await sendVerificationEmail(email, code);
    saveEmailVerification(email, code, expiresAt);
    return commitSession(NextResponse.json({ ok: true, message: '인증 코드를 이메일로 전송했습니다.', expiresAt }), session);
  } catch (error) {
    return commitSession(NextResponse.json({ ok: false, message: getMailErrorMessage(error) }, { status: 503 }), session);
  }
}