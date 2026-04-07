import { NextResponse } from 'next/server';
import { findUserByEmail, formatUser, verifyPassword } from '../../../../lib/server/database';
import { setAuthenticatedSession } from '../../../../lib/server/auth';
import { commitSession, getSession } from '../../../../lib/server/session';

export async function POST(request) {
  const body = await request.json().catch(() => ({}));
  const email = String(body.email || '').trim();
  const password = String(body.password || '');
  const user = findUserByEmail(email);

  if (!user || !user.password_hash || !verifyPassword(password, user.password_hash)) {
    return NextResponse.json({ ok: false, message: '이메일 또는 비밀번호가 올바르지 않습니다.' }, { status: 401 });
  }

  const response = NextResponse.json({ ok: true, user: formatUser(user, 'local') });
  return commitSession(response, setAuthenticatedSession(await getSession(), user.id, 'local'));
}