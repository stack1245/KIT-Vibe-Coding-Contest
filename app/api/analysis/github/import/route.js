import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';
export const revalidate = 0;
export const fetchCache = 'force-no-store';
export const runtime = 'nodejs';

function buildGitHubSummaryMessage(acceptedCount, rejectedCount) {
  if (acceptedCount && rejectedCount) {
    return `${acceptedCount}개 저장소를 가져왔고 ${rejectedCount}개 저장소는 제외했습니다.`;
  }

  if (acceptedCount) {
    return `${acceptedCount}개 저장소 가져오기를 시작했습니다.`;
  }

  if (rejectedCount) {
    return `가져올 수 있는 저장소가 없어 ${rejectedCount}개 저장소를 제외했습니다.`;
  }

  return '처리할 저장소가 없습니다.';
}

function bufferToArrayBuffer(buffer) {
  return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
}

function createBufferBackedFile(buffer, fileName, contentType) {
  return {
    name: fileName,
    type: contentType,
    size: buffer.length,
    async arrayBuffer() {
      return bufferToArrayBuffer(buffer);
    },
  };
}

function toUploadByteSize(value) {
  const numericValue = Number(value || 0);
  if (!Number.isFinite(numericValue) || numericValue <= 0) {
    return 0n;
  }

  return BigInt(Math.floor(numericValue));
}

export async function POST(request) {
  if (!request) {
    return NextResponse.json({ ok: false, message: '잘못된 요청입니다.' }, { status: 400 });
  }

  try {
    const [{ getSessionUser }, databaseModule, { startAnalysisJob }, githubRepositoriesModule, uploadScreeningModule, { getSession }] = await Promise.all([
      import('../../../../../lib/server/auth'),
      import('../../../../../lib/server/database'),
      import('../../../../../lib/server/analysis-job-runner'),
      import('../../../../../lib/server/github-repositories'),
      import('../../../../../lib/server/upload-screening'),
      import('../../../../../lib/server/session'),
    ]);
    const session = await getSession(request);
    const user = getSessionUser(session);

    if (!user) {
      return NextResponse.json({ ok: false, message: '로그인이 필요합니다.' }, { status: 401 });
    }

    const body = await request.json().catch(() => ({}));
    const normalizedFullName = String(body.fullName || '').trim();
    const normalizedRef = String(body.ref || '').trim();

    if (!normalizedFullName) {
      return NextResponse.json({ ok: false, message: '가져올 저장소를 선택해주세요.' }, { status: 400 });
    }

    let currentUploadSize = uploadScreeningModule.getUploadDirectorySize();
    if (currentUploadSize >= uploadScreeningModule.UPLOAD_TOTAL_LIMIT_BYTES) {
      return NextResponse.json({ ok: false, message: uploadScreeningModule.UPLOAD_CAPACITY_ERROR_MESSAGE }, { status: 503 });
    }

    const userRow = databaseModule.findUserById(user.id);
    const archive = await githubRepositoriesModule.fetchGitHubRepositoryArchive({
      userRow,
      fullName: normalizedFullName,
      ref: normalizedRef,
    });
    const archiveSize = toUploadByteSize(archive.buffer.length);
    const file = createBufferBackedFile(archive.buffer, archive.fileName, archive.contentType);
    const previewBuffer = archive.buffer.subarray(0, 32 * 1024);

    const rejected = [];
    const accepted = [];
    let job = null;

    const screening = await uploadScreeningModule.screenUploadedFile({
      fileName: archive.fileName,
      contentType: archive.contentType,
      previewBuffer,
      file,
    });

    if (!screening.accepted) {
      rejected.push({
        originalName: archive.fileName,
        repository: archive.repository.fullName,
        reason: screening.reason,
        source: screening.source,
        category: screening.category,
        signals: Array.isArray(screening.signals) ? screening.signals : [],
      });
    } else if (currentUploadSize + archiveSize > uploadScreeningModule.UPLOAD_TOTAL_LIMIT_BYTES) {
      rejected.push({
        originalName: archive.fileName,
        repository: archive.repository.fullName,
        reason: `${uploadScreeningModule.UPLOAD_CAPACITY_ERROR_MESSAGE} (남은 공간 부족: ${uploadScreeningModule.toDisplayBytes(archive.buffer.length)})`,
        source: 'capacity',
      });
    } else {
      const stored = await uploadScreeningModule.saveUploadedFile({
        userId: user.id,
        file,
        originalName: archive.fileName,
      });

      currentUploadSize += toUploadByteSize(stored.size);
      accepted.push({
        originalName: archive.fileName,
        repository: archive.repository.fullName,
        storedPath: stored.relativePath,
        size: stored.size,
        reason: screening.reason,
        source: screening.source,
        category: screening.category,
        signals: Array.isArray(screening.signals) ? screening.signals : [],
      });

      job = databaseModule.createAnalysisJob(user.id, {
        acceptedFiles: [
          {
            originalName: archive.fileName,
            relativePath: stored.relativePath,
            storedPath: stored.relativePath,
            size: stored.size,
            category: screening.category || '',
            source: screening.source || 'github',
            reason: screening.reason || '',
            signals: screening.signals || [],
          },
        ],
        rejectedFiles: rejected,
      });
      startAnalysisJob(job);
    }

    return NextResponse.json({
      ok: accepted.length > 0,
      message: buildGitHubSummaryMessage(accepted.length, rejected.length),
      accepted,
      rejected,
      job,
      repository: archive.repository,
    }, {
      status: accepted.length > 0 ? 200 : 400,
    });
  } catch (error) {
    return NextResponse.json(
      {
        ok: false,
        message: error instanceof Error && error.message ? error.message : 'GitHub 저장소 가져오기에 실패했습니다.',
        code: error?.code || '',
      },
      { status: Number(error?.statusCode || 500) }
    );
  }
}
