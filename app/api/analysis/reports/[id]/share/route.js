import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';
export const revalidate = 0;
export const fetchCache = 'force-no-store';
export const runtime = 'nodejs';

export async function POST(request, context) {
  if (!request) {
    return NextResponse.json({ ok: false, message: '잘못된 요청입니다.' }, { status: 400 });
  }

  const [{ getSessionUser }, databaseModule, configModule, { getSession }] = await Promise.all([
    import('../../../../../../lib/server/auth'),
    import('../../../../../../lib/server/database'),
    import('../../../../../../lib/server/config'),
    import('../../../../../../lib/server/session'),
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
  const enabled = typeof payload?.enabled === 'boolean' ? payload.enabled : !report.shareEnabled;
  const updatedReport = databaseModule.updateAnalysisReportSharing(numericReportId, enabled);

  if (!updatedReport) {
    return NextResponse.json({ ok: false, message: '공유 상태를 저장하지 못했습니다.' }, { status: 500 });
  }

  const requestOrigin = configModule.getRequestAppOrigin(request);
  const shareUrl = updatedReport.shareEnabled && updatedReport.shareToken && requestOrigin
    ? `${requestOrigin}/shared/${updatedReport.shareToken}`
    : '';

  return NextResponse.json({
    ok: true,
    report: updatedReport,
    shareUrl,
  });
}
