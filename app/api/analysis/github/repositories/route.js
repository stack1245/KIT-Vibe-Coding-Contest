import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';
export const revalidate = 0;
export const fetchCache = 'force-no-store';
export const runtime = 'nodejs';

export async function GET(request) {
  if (!request) {
    return NextResponse.json({ ok: false, message: '잘못된 요청입니다.' }, { status: 400 });
  }

  try {
    const [{ getSessionUser }, databaseModule, githubRepositoriesModule, { getSession }] = await Promise.all([
      import('../../../../../lib/server/auth'),
      import('../../../../../lib/server/database'),
      import('../../../../../lib/server/github-repositories'),
      import('../../../../../lib/server/session'),
    ]);
    const session = await getSession(request);
    const user = getSessionUser(session);

    if (!user) {
      return NextResponse.json({ ok: false, message: '로그인이 필요합니다.' }, { status: 401 });
    }

    const userRow = databaseModule.findUserById(user.id);
    const payload = await githubRepositoriesModule.listGitHubRepositories(userRow);

    return NextResponse.json({
      ok: true,
      repositories: payload.repositories,
      githubConnected: Boolean(userRow?.github_id),
      githubRepoAccess: Boolean(userRow?.github_access_token),
      hasRepositoryScope: payload.hasRepositoryScope,
      tokenScope: payload.tokenScope,
    });
  } catch (error) {
    return NextResponse.json(
      {
        ok: false,
        message: error instanceof Error && error.message ? error.message : 'GitHub 저장소 목록을 불러오지 못했습니다.',
        code: error?.code || '',
      },
      { status: Number(error?.statusCode || 500) }
    );
  }
}
