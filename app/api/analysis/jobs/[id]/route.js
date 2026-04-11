import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';
export const revalidate = 0;
export const fetchCache = 'force-no-store';
export const runtime = 'nodejs';

export async function GET(request, context) {
  if (!request) {
    return NextResponse.json({ ok: false, message: '잘못된 요청입니다.' }, { status: 400 });
  }

  const [{ getSessionUser }, databaseModule, analysisJobRunnerModule, { getSession }] = await Promise.all([
    import('../../../../../lib/server/auth'),
    import('../../../../../lib/server/database'),
    import('../../../../../lib/server/analysis-job-runner'),
    import('../../../../../lib/server/session'),
  ]);
  const session = await getSession(request);
  const user = getSessionUser(session);

  if (!user) {
    return NextResponse.json({ ok: false, message: '로그인이 필요합니다.' }, { status: 401 });
  }

  const params = await context?.params;
  const numericJobId = Number(params?.id);

  if (!Number.isFinite(numericJobId) || numericJobId <= 0) {
    return NextResponse.json({ ok: false, message: '잘못된 작업 ID입니다.' }, { status: 400 });
  }

  const existingJob = databaseModule.findAnalysisJobById(numericJobId);
  if (!existingJob || existingJob.userId !== user.id) {
    return NextResponse.json({ ok: false, message: '작업을 찾을 수 없습니다.' }, { status: 404 });
  }

  const job = analysisJobRunnerModule.ensureAnalysisJobRunning(numericJobId) || existingJob;

  const report = job.reportId ? databaseModule.findAnalysisReportById(job.reportId) : null;
  return NextResponse.json({ ok: true, job, report });
}
