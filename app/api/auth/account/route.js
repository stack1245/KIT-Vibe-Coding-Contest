import { NextResponse } from 'next/server';
import { getSessionUser } from '../../../../lib/server/auth';
import { deleteUserById } from '../../../../lib/server/database';
import { clearSession, getSession } from '../../../../lib/server/session';

export async function DELETE() {
  const session = await getSession();
  const user = getSessionUser(session);

  if (!user) {
    return NextResponse.json({ ok: false, message: '로그인이 필요합니다.' }, { status: 401 });
  }

  const deleted = deleteUserById(user.id);
  if (!deleted) {
    return NextResponse.json({ ok: false, message: '삭제할 계정을 찾지 못했습니다.' }, { status: 404 });
  }

  return clearSession(NextResponse.json({ ok: true }));
}