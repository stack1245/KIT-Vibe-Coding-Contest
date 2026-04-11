'use server';

import fs from 'node:fs';
import path from 'node:path';

async function getAuthenticatedUserContext() {
  const [{ getSessionUser }, { getSession }] = await Promise.all([
    import('../../lib/server/auth'),
    import('../../lib/server/session'),
  ]);
  const session = await getSession();
  const user = getSessionUser(session);
  if (!user) {
    throw new Error('로그인이 필요합니다.');
  }
  return { session, user };
}

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

function toUploadByteSize(value) {
  const numericValue = Number(value || 0);
  if (!Number.isFinite(numericValue) || numericValue <= 0) {
    return 0n;
  }

  return BigInt(Math.floor(numericValue));
}

export async function getAnalysisJobStatusAction(jobId) {
  const [{ user }, databaseModule, analysisJobRunnerModule] = await Promise.all([
    getAuthenticatedUserContext(),
    import('../../lib/server/database'),
    import('../../lib/server/analysis-job-runner'),
  ]);
  const numericJobId = Number(jobId);

  if (!Number.isFinite(numericJobId) || numericJobId <= 0) {
    throw new Error('잘못된 작업 ID입니다.');
  }

  const existingJob = databaseModule.findAnalysisJobById(numericJobId);
  if (!existingJob || existingJob.userId !== user.id) {
    throw new Error('작업을 찾을 수 없습니다.');
  }

  const job = analysisJobRunnerModule.ensureAnalysisJobRunning(numericJobId) || existingJob;

  const report = job.reportId ? databaseModule.findAnalysisReportById(job.reportId) : null;
  return { ok: true, job, report };
}

export async function cancelAnalysisJobAction(jobId) {
  const [{ user }, databaseModule, { stopAnalysisJob }] = await Promise.all([
    getAuthenticatedUserContext(),
    import('../../lib/server/database'),
    import('../../lib/server/analysis-job-runner'),
  ]);
  const numericJobId = Number(jobId);

  if (!Number.isFinite(numericJobId) || numericJobId <= 0) {
    throw new Error('잘못된 작업 ID입니다.');
  }

  const job = databaseModule.findAnalysisJobById(numericJobId);
  if (!job || job.userId !== user.id) {
    throw new Error('작업을 찾을 수 없습니다.');
  }

  if (!(job.status === 'queued' || job.status === 'running')) {
    throw new Error('취소할 수 없는 작업 상태입니다.');
  }

  return {
    ok: true,
    job: stopAnalysisJob(numericJobId),
    message: '분석을 취소했습니다.',
  };
}

export async function deleteAnalysisReportAction(reportId) {
  const [{ user }, databaseModule, { UPLOAD_ROOT_DIR }] = await Promise.all([
    getAuthenticatedUserContext(),
    import('../../lib/server/database'),
    import('../../lib/server/project-paths'),
  ]);
  const numericReportId = Number(reportId);

  if (!Number.isInteger(numericReportId) || numericReportId <= 0) {
    throw new Error('잘못된 분석 ID입니다.');
  }

  const report = databaseModule.findAnalysisReportById(numericReportId);
  if (!report || report.userId !== user.id) {
    throw new Error('분석 리포트를 찾지 못했습니다.');
  }

  removeReportFiles(report.sourceFiles, UPLOAD_ROOT_DIR);
  databaseModule.deleteAnalysisReportById(numericReportId);

  return { ok: true, deletedId: numericReportId };
}

export async function toggleAnalysisReportShareAction(reportId, enabled, origin = '') {
  const [{ user }, databaseModule, configModule] = await Promise.all([
    getAuthenticatedUserContext(),
    import('../../lib/server/database'),
    import('../../lib/server/config'),
  ]);
  const numericReportId = Number(reportId);

  if (!Number.isInteger(numericReportId) || numericReportId <= 0) {
    throw new Error('잘못된 분석 ID입니다.');
  }

  const report = databaseModule.findAnalysisReportById(numericReportId);
  if (!report || report.userId !== user.id) {
    throw new Error('분석 리포트를 찾지 못했습니다.');
  }

  const updatedReport = databaseModule.updateAnalysisReportSharing(
    numericReportId,
    typeof enabled === 'boolean' ? enabled : !report.shareEnabled
  );

  if (!updatedReport) {
    throw new Error('공유 상태를 저장하지 못했습니다.');
  }

  const resolvedOrigin = configModule.getAppOrigin();
  const shareUrl = updatedReport.shareEnabled && updatedReport.shareToken
    ? `${resolvedOrigin}/shared/${updatedReport.shareToken}`
    : '';

  return {
    ok: true,
    report: updatedReport,
    shareUrl,
  };
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

export async function listGitHubRepositoriesAction() {
  const [{ user }, databaseModule, githubRepositoriesModule] = await Promise.all([
    getAuthenticatedUserContext(),
    import('../../lib/server/database'),
    import('../../lib/server/github-repositories'),
  ]);
  const userRow = databaseModule.findUserById(user.id);
  const payload = await githubRepositoriesModule.listGitHubRepositories(userRow);

  return {
    ok: true,
    repositories: payload.repositories,
    githubConnected: Boolean(userRow?.github_id),
    githubRepoAccess: Boolean(userRow?.github_access_token),
    hasRepositoryScope: payload.hasRepositoryScope,
    tokenScope: payload.tokenScope,
  };
}

export async function importGitHubRepositoryAction(fullName, ref = '') {
  const [{ user }, databaseModule, { startAnalysisJob }, githubRepositoriesModule, uploadScreeningModule] = await Promise.all([
    getAuthenticatedUserContext(),
    import('../../lib/server/database'),
    import('../../lib/server/analysis-job-runner'),
    import('../../lib/server/github-repositories'),
    import('../../lib/server/upload-screening'),
  ]);
  const normalizedFullName = String(fullName || '').trim();
  const normalizedRef = String(ref || '').trim();

  if (!normalizedFullName) {
    throw new Error('가져올 저장소를 선택해주세요.');
  }

  let currentUploadSize = uploadScreeningModule.getUploadDirectorySize();
  if (currentUploadSize >= uploadScreeningModule.UPLOAD_TOTAL_LIMIT_BYTES) {
    throw new Error(uploadScreeningModule.UPLOAD_CAPACITY_ERROR_MESSAGE);
  }

  const userRow = databaseModule.findUserById(user.id);
  const archive = await githubRepositoriesModule.fetchGitHubRepositoryArchive({
    userRow,
    fullName: normalizedFullName,
    ref: normalizedRef,
  });
  const archiveSize = toUploadByteSize(archive.buffer.length);
  const file = createBufferBackedFile(archive.buffer, archive.fileName, archive.contentType);

  const rejected = [];
  const accepted = [];
  let job = null;

  const previewBuffer = archive.buffer.subarray(0, 32 * 1024);
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

  return {
    ok: accepted.length > 0,
    message: buildGitHubSummaryMessage(accepted.length, rejected.length),
    accepted,
    rejected,
    job,
    repository: archive.repository,
  };
}
