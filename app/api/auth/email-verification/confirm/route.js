import { NextResponse } from 'next/server';
import { clearSignupVerification, createSignupVerifiedSession } from '../../../../../lib/server/auth';
import { commitSession, getSession } from '../../../../../lib/server/session';
import { isValidEmail, verifyEmailVerificationCode } from '../../../../../lib/server/database';
import { getVerificationMessage } from '../../../../../lib/server/config';

export async function POST(request) {
  const body = await request.json().catch(() => ({}));
  const email = String(body.email || '').trim();
  const code = String(body.code || '').trim();
  const session = await getSession();

  if (!email || !code) {
    return NextResponse.json({ ok: false, message: '이메일과 인증 코드를 입력해주세요.' }, { status: 400 });
  }

  if (!isValidEmail(email)) {
    return NextResponse.json({ ok: false, message: '올바른 이메일 형식을 입력해주세요.' }, { status: 400 });
  }

  const verificationResult = verifyEmailVerificationCode(email, code);
  if (!verificationResult.ok) {
    return commitSession(
      NextResponse.json({ ok: false, message: getVerificationMessage(verificationResult.reason) }, { status: 400 }),
      clearSignupVerification(session)
    );
  }

  return commitSession(
    NextResponse.json({ ok: true, message: '이메일 인증이 완료되었습니다.' }),
    createSignupVerifiedSession(session, email)
  );
}