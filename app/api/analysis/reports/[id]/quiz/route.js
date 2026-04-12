import { NextResponse } from 'next/server';
import { buildFindingQuizKey } from '../../../../../../lib/report-quiz';

export const dynamic = 'force-dynamic';
export const revalidate = 0;
export const fetchCache = 'force-no-store';
export const runtime = 'nodejs';

export async function POST(request, context) {
  try {
    const [{ getSessionUser }, databaseModule, { getSession }, quizModule] = await Promise.all([
      import('../../../../../../lib/server/auth'),
      import('../../../../../../lib/server/database'),
      import('../../../../../../lib/server/session'),
      import('../../../../../../lib/server/report-quiz'),
    ]);
    const session = await getSession(request);
    const user = getSessionUser(session);

    if (!user) {
      return NextResponse.json({ ok: false, message: '로그인이 필요합니다.' }, { status: 401 });
    }

    const params = await context?.params;
    const numericReportId = Number(params?.id);
    if (!Number.isInteger(numericReportId) || numericReportId <= 0) {
      return NextResponse.json({ ok: false, message: '잘못된 분석 ID입니다.' }, { status: 400 });
    }

    const report = databaseModule.findAnalysisReportById(numericReportId);
    if (!report || report.userId !== user.id) {
      return NextResponse.json({ ok: false, message: '분석 리포트를 찾지 못했습니다.' }, { status: 404 });
    }

    const payload = await request.json().catch(() => ({}));
    const requestedFindingKey = String(payload?.findingKey || '').trim();
    const findingIndex = Array.isArray(report.findings)
      ? report.findings.findIndex((finding, index) => buildFindingQuizKey(finding, index) === requestedFindingKey)
      : -1;

    if (findingIndex === -1) {
      return NextResponse.json({ ok: false, message: '실습할 취약점을 찾지 못했습니다.' }, { status: 404 });
    }

    const finding = report.findings[findingIndex];
    if (String(finding?.severity || '').trim() !== 'high') {
      return NextResponse.json({ ok: false, message: 'high 취약점만 문제를 생성할 수 있습니다.' }, { status: 400 });
    }

    const existingSession = databaseModule.findReportQuizSessionByReportAndFinding(report.id, requestedFindingKey);
    if (existingSession) {
      return NextResponse.json({
        ok: true,
        session: {
          sessionToken: existingSession.sessionToken,
          status: existingSession.status,
          findingKey: existingSession.findingKey,
        },
        report: databaseModule.findAnalysisReportById(report.id),
      });
    }

    const generatedQuiz = await quizModule.generateFindingQuiz({
      report,
      finding,
      findingIndex,
    });

    const savedSession = databaseModule.upsertReportQuizSession({
      reportId: report.id,
      userId: user.id,
      findingKey: generatedQuiz.findingKey,
      findingTitle: finding.title,
      sessionToken: generatedQuiz.sessionToken,
      status: 'ready',
      quiz: generatedQuiz.quiz,
      flagValue: generatedQuiz.flagValue,
      generatedAt: new Date().toISOString(),
    });

    return NextResponse.json({
      ok: true,
      session: {
        sessionToken: savedSession.sessionToken,
        status: savedSession.status,
        findingKey: savedSession.findingKey,
      },
      report: databaseModule.findAnalysisReportById(report.id),
    });
  } catch (error) {
    console.error('[analysis/report-quiz/create] failed', error);
    return NextResponse.json({ ok: false, message: '문제 생성에 실패했습니다.' }, { status: 500 });
  }
}
