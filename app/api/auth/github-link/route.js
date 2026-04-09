import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';
export const revalidate = 0;
export const fetchCache = 'force-no-store';
export const runtime = 'nodejs';

export async function DELETE(request) {
  if (!request) {
    return NextResponse.json({ ok: false, message: '잘못된 요청입니다.' }, { status: 400 });
  }

  const [{ getSessionUser, setAuthenticatedSession }, { unlinkGitHubFromUser }, { commitSession, getSession }] = await Promise.all([
    import('../../../../lib/server/auth'),
    import('../../../../lib/server/database'),
    import('../../../../lib/server/session'),
  ]);
  const session = await getSession(request);
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
