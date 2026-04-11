import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';
export const revalidate = 0;
export const fetchCache = 'force-no-store';
export const runtime = 'nodejs';

export async function DELETE(request, context) {
  if (!request) {
    return NextResponse.json({ ok: false, message: '잘못된 요청입니다.' }, { status: 400 });
  }

  const [{ getSessionUser }, { deleteUserById, findUserById }, { getSession }] = await Promise.all([
    import('../../../../../lib/server/auth'),
    import('../../../../../lib/server/database'),
    import('../../../../../lib/server/session'),
  ]);
  const session = await getSession(request);
  const user = getSessionUser(session);

  if (!user) {
    return NextResponse.json({ ok: false, message: '로그인이 필요합니다.' }, { status: 401 });
  }

  if (!user.isAdmin) {
    return NextResponse.json({ ok: false, message: '관리자 권한이 필요합니다.' }, { status: 403 });
  }

  const params = await context?.params;
  const targetId = Number(params?.id);

  if (!Number.isInteger(targetId) || targetId <= 0) {
    return NextResponse.json({ ok: false, message: '올바르지 않은 회원 ID입니다.' }, { status: 400 });
  }

  if (targetId === user.id) {
    return NextResponse.json(
      { ok: false, message: '본인 계정은 관리자 목록에서 삭제할 수 없습니다. 대시보드에서 회원탈퇴를 사용하세요.' },
      { status: 400 }
    );
  }

  const targetUser = findUserById(targetId);
  if (!targetUser) {
    return NextResponse.json({ ok: false, message: '삭제할 회원을 찾지 못했습니다.' }, { status: 404 });
  }

  if (!deleteUserById(targetId)) {
    return NextResponse.json({ ok: false, message: '회원 삭제에 실패했습니다.' }, { status: 500 });
  }

  return NextResponse.json({ ok: true, deletedId: targetId });
}
