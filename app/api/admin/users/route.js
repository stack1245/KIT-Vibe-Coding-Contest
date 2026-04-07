import { NextResponse } from 'next/server';
import { buildSessionUser, getSessionUser } from '../../../../lib/server/auth';
import { listUsers } from '../../../../lib/server/database';
import { AUTH_RATE_LIMITS } from '../../../../lib/server/config';
import { enforceRateLimit } from '../../../../lib/server/rate-limit';
import { getSession } from '../../../../lib/server/session';

export async function GET(request) {
  const session = await getSession();
  const user = getSessionUser(session);

  if (!user) {
    return NextResponse.json({ ok: false, message: '로그인이 필요합니다.' }, { status: 401 });
  }

  if (!user.isAdmin) {
    return NextResponse.json({ ok: false, message: '관리자 권한이 필요합니다.' }, { status: 403 });
  }

  const rateLimitedResponse = enforceRateLimit(request, {
    namespace: 'admin-users-list',
    identifier: user.id,
    ...AUTH_RATE_LIMITS.admin,
  });

  if (rateLimitedResponse) {
    return rateLimitedResponse;
  }

  return NextResponse.json({
    ok: true,
    users: listUsers().map((row) => buildSessionUser(row, row.auth_provider)),
  });
}