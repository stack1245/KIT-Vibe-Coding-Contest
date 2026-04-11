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

    if (!resolvedPath.startsWith(uploadRootPath) || !fs.existsSync(resolvedPath)) {
      return;
    }

    fs.rmSync(resolvedPath, { force: true });

    const parentDir = path.dirname(resolvedPath);
    if (parentDir.startsWith(uploadRootPath) && fs.existsSync(parentDir) && fs.readdirSync(parentDir).length === 0) {
      fs.rmdirSync(parentDir);
    }
  });
}

export async function DELETE(request, context) {
  if (!request) {
    return NextResponse.json({ ok: false, message: '잘못된 요청입니다.' }, { status: 400 });
  }

  const [{ getSessionUser }, databaseModule, { UPLOAD_ROOT_DIR }, { getSession }] = await Promise.all([
    import('../../../../../lib/server/auth'),
    import('../../../../../lib/server/database'),
    import('../../../../../lib/server/project-paths'),
    import('../../../../../lib/server/session'),
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

  removeReportFiles(report.sourceFiles, UPLOAD_ROOT_DIR);
  databaseModule.deleteAnalysisReportById(numericReportId);

  return NextResponse.json({ ok: true, deletedId: numericReportId });
}
