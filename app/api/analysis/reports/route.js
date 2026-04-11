import fs from 'node:fs';
import path from 'node:path';
import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';
export const revalidate = 0;
export const fetchCache = 'force-no-store';
export const runtime = 'nodejs';

function removeReportFiles(sourceFiles, uploadRootDir) {
  if (!Array.isArray(sourceFiles)) {
    return;
  }

  sourceFiles.forEach((entry) => {
    const relativePath = typeof entry === 'string' ? '' : String(entry?.relativePath || '');
    if (!relativePath) {
      return;
    }

    const uploadRootPath = path.resolve(uploadRootDir);
    const uploadRelativePath = relativePath
      .replace(/\\/g, '/')
      .replace(/^upload\//, '');
    const resolvedPath = path.resolve(uploadRootPath, uploadRelativePath);

    if (!resolvedPath.startsWith(uploadRootPath)) {
      return;
    }

    if (!fs.existsSync(resolvedPath)) {
      return;
    }

    fs.rmSync(resolvedPath, { force: true });

    const parentDir = path.dirname(resolvedPath);
    if (parentDir.startsWith(uploadRootPath) && fs.existsSync(parentDir) && fs.readdirSync(parentDir).length === 0) {
      fs.rmdirSync(parentDir);
    }
  });
}

export async function DELETE(request) {
  try {
    if (!request) {
      return NextResponse.json({ ok: false, message: '잘못된 요청입니다.' }, { status: 400 });
    }

    const [{ getSessionUser }, databaseModule, { getSession }, { UPLOAD_ROOT_DIR }] = await Promise.all([
      import('../../../../lib/server/auth'),
      import('../../../../lib/server/database'),
      import('../../../../lib/server/session'),
      import('../../../../lib/server/project-paths'),
    ]);
    const session = await getSession(request);
    const user = getSessionUser(session);

    if (!user) {
      return NextResponse.json({ ok: false, message: '로그인이 필요합니다.' }, { status: 401 });
    }

    const payload = await request.json().catch(() => ({}));
    const reportIds = Array.isArray(payload?.reportIds)
      ? payload.reportIds.map((value) => Number(value)).filter((value) => Number.isInteger(value) && value > 0)
      : [];

    if (!reportIds.length) {
      return NextResponse.json({ ok: false, message: '삭제할 분석 리포트가 없습니다.' }, { status: 400 });
    }

    const uniqueReportIds = Array.from(new Set(reportIds));
    let deletedCount = 0;

    uniqueReportIds.forEach((reportId) => {
      const report = databaseModule.findAnalysisReportById(reportId);
      if (!report || report.userId !== user.id) {
        return;
      }

      removeReportFiles(report.sourceFiles, UPLOAD_ROOT_DIR);
      if (databaseModule.deleteAnalysisReportById(reportId)) {
        deletedCount += 1;
      }
    });

    return NextResponse.json({
      ok: true,
      deletedCount,
      message: deletedCount ? `분석 리포트 ${deletedCount}개를 삭제했습니다.` : '삭제된 분석 리포트가 없습니다.',
    });
  } catch (error) {
    console.error('[analysis/reports/bulk-delete] failed', error);
    return NextResponse.json({ ok: false, message: '전체 삭제에 실패했습니다.' }, { status: 500 });
  }
}
