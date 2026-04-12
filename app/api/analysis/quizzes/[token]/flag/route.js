import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';
export const revalidate = 0;
export const fetchCache = 'force-no-store';
export const runtime = 'nodejs';

export async function POST(request, context) {
  try {
    const [{ getSessionUser }, databaseModule, { getSession }] = await Promise.all([
      import('../../../../../../lib/server/auth'),
      import('../../../../../../lib/server/database'),
      import('../../../../../../lib/server/session'),
    ]);
    const session = await getSession(request);
    const user = getSessionUser(session);

    if (!user) {
      return NextResponse.json({ ok: false, message: '로그인이 필요합니다.' }, { status: 401 });
    }

    const params = await context?.params;
    const sessionToken = String(params?.token || '').trim();
    const quizSession = databaseModule.findReportQuizSessionByToken(sessionToken);

    if (!quizSession || quizSession.userId !== user.id) {
      return NextResponse.json({ ok: false, message: '플래그 제출 대상을 찾지 못했습니다.' }, { status: 404 });
    }

    const payload = await request.json().catch(() => ({}));
    const submittedFlag = String(payload?.flag || '').trim();

    if (!submittedFlag) {
      return NextResponse.json({ ok: false, message: '플래그를 입력해 주세요.' }, { status: 400 });
    }

    if (submittedFlag !== quizSession.flagValue) {
      return NextResponse.json({ ok: false, message: '플래그가 올바르지 않습니다.' }, { status: 400 });
    }

    const solvedSession = databaseModule.markReportQuizSessionSolved(sessionToken);
    const report = databaseModule.findAnalysisReportById(solvedSession?.reportId);

    return NextResponse.json({
      ok: true,
      message: '플래그 제출이 완료되었습니다.',
      report,
    });
  } catch (error) {
    console.error('[analysis/report-quiz/flag] failed', error);
    return NextResponse.json({ ok: false, message: '플래그 제출에 실패했습니다.' }, { status: 500 });
  }
}
