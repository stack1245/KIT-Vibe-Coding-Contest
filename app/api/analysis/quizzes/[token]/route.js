import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';
export const revalidate = 0;
export const fetchCache = 'force-no-store';
export const runtime = 'nodejs';

export async function POST(request, context) {
  try {
    const [{ getSessionUser }, databaseModule, { getSession }, quizModule] = await Promise.all([
      import('../../../../../lib/server/auth'),
      import('../../../../../lib/server/database'),
      import('../../../../../lib/server/session'),
      import('../../../../../lib/server/report-quiz'),
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
      return NextResponse.json({ ok: false, message: '문제를 찾지 못했습니다.' }, { status: 404 });
    }

    const payload = await request.json().catch(() => ({}));
    const result = quizModule.gradeFindingQuiz(quizSession.quiz, payload?.answers || {});

    if (!result.correct) {
      return NextResponse.json({
        ok: true,
        correct: false,
        incorrectQuestionIds: result.incorrectQuestionIds,
        totalQuestions: result.totalQuestions,
        message: '아직 틀린 문항이 있습니다. 다시 확인해 보세요.',
      });
    }

    return NextResponse.json({
      ok: true,
      correct: true,
      flag: quizSession.flagValue,
      totalQuestions: result.totalQuestions,
      message: '모든 문제를 맞췄습니다. 플래그를 복사해 원래 화면에 제출하세요.',
    });
  } catch (error) {
    console.error('[analysis/report-quiz/check] failed', error);
    return NextResponse.json({ ok: false, message: '문제 채점에 실패했습니다.' }, { status: 500 });
  }
}
