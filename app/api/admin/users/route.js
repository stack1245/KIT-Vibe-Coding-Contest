import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';
export const revalidate = 0;
export const fetchCache = 'force-no-store';
export const runtime = 'nodejs';

export async function GET(request) {
  if (!request) {
    return NextResponse.json({ ok: false, message: '잘못된 요청입니다.' }, { status: 400 });
  }

  const [{ buildSessionUser, getSessionUser }, { listUsers }, { getSession }] = await Promise.all([
    import('../../../../lib/server/auth'),
    import('../../../../lib/server/database'),
    import('../../../../lib/server/session'),
  ]);
  const session = await getSession(request);
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
