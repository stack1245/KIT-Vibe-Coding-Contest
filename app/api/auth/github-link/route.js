import { NextResponse } from 'next/server';
import { getSessionUser, setAuthenticatedSession } from '../../../../../lib/server/auth';
import { unlinkGitHubFromUser } from '../../../../../lib/server/database';
import { commitSession, getSession } from '../../../../../lib/server/session';

export async function DELETE() {
  const session = await getSession();
  const user = getSessionUser(session);

  if (!user) {
    return NextResponse.json({ ok: false, message: '로그인이 필요합니다.' }, { status: 401 });
  }

  if (!user.githubConnected) {
    return NextResponse.json({ ok: false, message: '해지할 GitHub 연결이 없습니다.' }, { status: 400 });
  }

  if (!user.hasPassword) {
    return NextResponse.json({ ok: false, message: 'GitHub 단독 로그인 계정은 연결 해지를 할 수 없습니다.' }, { status: 400 });
  }

  const updatedUser = unlinkGitHubFromUser(user.id);
  if (!updatedUser) {
    return NextResponse.json({ ok: false, message: '계정 정보를 찾지 못했습니다.' }, { status: 404 });
  }

  return commitSession(
    NextResponse.json({ ok: true }),
    setAuthenticatedSession(session, updatedUser.id, 'local')
  );
}
