import { NextResponse } from 'next/server';
import { getSessionUser } from '../../../../../lib/server/auth';
import { deleteUserById } from '../../../../../lib/server/database';
import { AUTH_RATE_LIMITS } from '../../../../../lib/server/config';
import { enforceRateLimit } from '../../../../../lib/server/rate-limit';
import { getSession } from '../../../../../lib/server/session';

export async function DELETE(request, { params }) {
  const session = await getSession();
  const user = getSessionUser(session);
  const targetId = Number(params.id);

  if (!user) {
    return NextResponse.json({ ok: false, message: '로그인이 필요합니다.' }, { status: 401 });
  }

  if (!user.isAdmin) {
    return NextResponse.json({ ok: false, message: '관리자 권한이 필요합니다.' }, { status: 403 });
  }

  const rateLimitedResponse = enforceRateLimit(request, {
    namespace: 'admin-users-delete',
    identifier: user.id,
    ...AUTH_RATE_LIMITS.admin,
  });

  if (rateLimitedResponse) {
    return rateLimitedResponse;
  }

  if (!Number.isInteger(targetId) || targetId <= 0) {
    return NextResponse.json({ ok: false, message: '올바르지 않은 회원 ID입니다.' }, { status: 400 });
  }

  if (targetId === user.id) {
    return NextResponse.json({ ok: false, message: '본인 계정은 관리자 목록에서 삭제할 수 없습니다. 대시보드에서 회원탈퇴를 사용하세요.' }, { status: 400 });
  }

  const deleted = deleteUserById(targetId);
  if (!deleted) {
    return NextResponse.json({ ok: false, message: '삭제할 회원을 찾지 못했습니다.' }, { status: 404 });
  }

  return NextResponse.json({ ok: true });
}