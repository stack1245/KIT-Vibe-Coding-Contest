import { NextResponse } from 'next/server';
import { buildSessionUser, getSessionUser } from '../../../../lib/server/auth';
import { listUsers } from '../../../../lib/server/database';
import { getSession } from '../../../../lib/server/session';

export async function GET() {
  const session = await getSession();
  const user = getSessionUser(session);

  if (!user) {
    return NextResponse.json({ ok: false, message: '로그인이 필요합니다.' }, { status: 401 });
  }

  if (!user.isAdmin) {
    return NextResponse.json({ ok: false, message: '관리자 권한이 필요합니다.' }, { status: 403 });
  }

  return NextResponse.json({
    ok: true,
    users: listUsers().map((row) => buildSessionUser(row, row.auth_provider)),
  });
}