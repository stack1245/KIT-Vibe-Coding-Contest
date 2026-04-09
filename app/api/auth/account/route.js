import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';
export const revalidate = 0;
export const fetchCache = 'force-no-store';
export const runtime = 'nodejs';

async function updateAccountProfile(request) {
  try {
    if (!request) {
      return NextResponse.json({ ok: false, message: '잘못된 요청입니다.' }, { status: 400 });
    }

    const [{ buildSessionUser, getSessionUser }, databaseModule, { getSession }] = await Promise.all([
      import('../../../../lib/server/auth'),
      import('../../../../lib/server/database'),
      import('../../../../lib/server/session'),
    ]);
    const session = await getSession(request);
    const user = getSessionUser(session);

    if (!user) {
      return NextResponse.json({ ok: false, message: '로그인이 필요합니다.' }, { status: 401 });
    }

    const payload = await request.json().catch(() => ({}));
    const nextDisplayName = Object.prototype.hasOwnProperty.call(payload, 'displayName')
      ? String(payload.displayName || '').trim()
      : null;
    const nextPreferences = Object.prototype.hasOwnProperty.call(payload, 'preferences')
      ? databaseModule.normalizeUserPreferences(payload.preferences || {})
      : null;

    if (nextDisplayName !== null && !databaseModule.isValidDisplayName(nextDisplayName)) {
      return NextResponse.json(
        { ok: false, message: '닉네임은 2자 이상 30자 이하로 입력해주세요.' },
        { status: 400 }
      );
    }

    let updatedUserRow = null;

    if (nextDisplayName !== null) {
      updatedUserRow = databaseModule.updateUserDisplayName(user.id, nextDisplayName);
      if (!updatedUserRow) {
        return NextResponse.json({ ok: false, message: '계정을 찾지 못했습니다.' }, { status: 404 });
      }
    }

    const preferences = nextPreferences
      ? databaseModule.updateUserPreferences(user.id, nextPreferences)
      : databaseModule.getUserPreferences(user.id);

    if (nextPreferences && !preferences) {
      return NextResponse.json({ ok: false, message: '환경설정을 저장하지 못했습니다.' }, { status: 404 });
    }

    return NextResponse.json({
      ok: true,
      user: buildSessionUser(updatedUserRow || databaseModule.findUserById(user.id), session.authMethod || 'local'),
      preferences,
    });
  } catch (error) {
    return NextResponse.json(
      {
        ok: false,
        message: error instanceof Error && error.message
          ? error.message
          : '닉네임 변경 중 오류가 발생했습니다.',
      },
      { status: 500 }
    );
  }
}

export async function PATCH(request) {
  return updateAccountProfile(request);
}

export async function POST(request) {
  return updateAccountProfile(request);
}

export async function DELETE(request) {
  const [{ getSessionUser }, { deleteUserById }, { clearSession, getSession }] = await Promise.all([
    import('../../../../lib/server/auth'),
    import('../../../../lib/server/database'),
    import('../../../../lib/server/session'),
  ]);
  const session = await getSession(request);
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
