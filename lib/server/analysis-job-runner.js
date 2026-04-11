import 'server-only';
import path from 'node:path';
import { generateAnalysisReport } from './analysis-report';
import {
  cancelAnalysisJob,
  completeAnalysisJob,
  createAnalysisReport,
  failAnalysisJob,
  findAnalysisJobById,
  updateAnalysisJobProgress,
} from './database';
import { normalizeStoredUploadRelativePath, UPLOAD_ROOT_DIR } from './project-paths';

const globalAnalysisJobs = globalThis;
const STALLED_JOB_THRESHOLD_MS = 12 * 60 * 1000;

if (!globalAnalysisJobs.__phaseRunningAnalysisJobs) {
  globalAnalysisJobs.__phaseRunningAnalysisJobs = new Map();
}

function getRunningJobsSet() {
  return globalAnalysisJobs.__phaseRunningAnalysisJobs;
}

function markJobHeartbeat(jobId) {
  getRunningJobsSet().set(jobId, Date.now());
}

function clearJobHeartbeat(jobId) {
  getRunningJobsSet().delete(jobId);
}

function isJobActiveStatus(status) {
  return status === 'queued' || status === 'running';
}

function getCurrentRunnableJob(jobId) {
  const job = findAnalysisJobById(jobId);
  return job && isJobActiveStatus(job.status) ? job : null;
}

function isJobHeartbeatStale(jobId, updatedAt) {
  const runningJobs = getRunningJobsSet();
  const heartbeatAt = runningJobs.get(jobId);

  if (typeof heartbeatAt === 'number') {
    return Date.now() - heartbeatAt > STALLED_JOB_THRESHOLD_MS;
  }

  const updatedAtMs = Date.parse(String(updatedAt || ''));
  if (Number.isFinite(updatedAtMs)) {
    return Date.now() - updatedAtMs > STALLED_JOB_THRESHOLD_MS;
  }

  return true;
}

function normalizeAcceptedFiles(acceptedFiles = []) {
  return acceptedFiles
    .map((file) => {
      const relativePath = normalizeStoredUploadRelativePath(file.relativePath || file.storedPath || '');
      if (!relativePath) {
        return null;
      }

      return {
        originalName: String(file.originalName || path.basename(relativePath) || 'upload'),
        relativePath,
        absolutePath: path.join(UPLOAD_ROOT_DIR, relativePath),
        size: Number(file.size || 0),
      };
    })
    .filter(Boolean);
}

async function runAnalysisJob({ jobId, userId, acceptedFiles }) {
  const runningJobs = getRunningJobsSet();
  if (runningJobs.has(jobId)) {
    return;
  }

  markJobHeartbeat(jobId);

  try {
    if (!getCurrentRunnableJob(jobId)) {
      return;
    }

    markJobHeartbeat(jobId);
    updateAnalysisJobProgress(jobId, {
      status: 'running',
      stage: '구조 분석 중',
      progressPercent: 22,
      message: '파일 구조, import, 엔트리포인트, 핵심 모듈을 읽고 있습니다.',
    });

    if (!getCurrentRunnableJob(jobId)) {
      return;
    }

    markJobHeartbeat(jobId);
    updateAnalysisJobProgress(jobId, {
      status: 'running',
      stage: '로직 분석 중',
      progressPercent: 40,
      message: '실행 경로와 데이터 흐름을 복원하고 있습니다.',
    });

    const generatedReport = await generateAnalysisReport({
      acceptedFiles,
      onProgress: ({ stage, progressPercent, message }) => {
        if (!getCurrentRunnableJob(jobId)) {
          return;
        }

        markJobHeartbeat(jobId);
        updateAnalysisJobProgress(jobId, {
          status: 'running',
          stage: stage || '취약점 검증 중',
          progressPercent: typeof progressPercent === 'number' ? progressPercent : 56,
          message: message || '분석 진행 중입니다.',
        });
      },
    });

    if (!getCurrentRunnableJob(jobId)) {
      return;
    }

    markJobHeartbeat(jobId);
    updateAnalysisJobProgress(jobId, {
      status: 'running',
      stage: generatedReport.resultMode === 'recommendation' ? '보안 조언 정리 중' : '취약점 리포트 정리 중',
      progressPercent: 86,
      message: generatedReport.resultMode === 'recommendation'
        ? '코드 기반 보완 포인트와 운영상 위험 요인을 정리하고 있습니다.'
        : '확정된 취약점, 코드 위치, 공격 경로를 정리하고 있습니다.',
    });

    if (!getCurrentRunnableJob(jobId)) {
      return;
    }

    const report = createAnalysisReport(userId, generatedReport);

    if (!getCurrentRunnableJob(jobId)) {
      return;
    }

    markJobHeartbeat(jobId);
    completeAnalysisJob(jobId, {
      stage: '분석 완료',
      message: '분석이 완료되었습니다.',
      reportId: report.id,
    });
  } catch (error) {
    console.error('[analysis/job] failed', error);

    if (!getCurrentRunnableJob(jobId)) {
      return;
    }

    failAnalysisJob(jobId, {
      stage: '분석 실패',
      progressPercent: 100,
      message: '분석 중 오류가 발생했습니다.',
      errorMessage: error instanceof Error ? error.message : 'unknown-error',
    });
  } finally {
    clearJobHeartbeat(jobId);
  }
}

export function startAnalysisJob(job) {
  if (!job || !isJobActiveStatus(job.status)) {
    return;
  }

  const acceptedFiles = normalizeAcceptedFiles(job.acceptedFiles);
  if (!acceptedFiles.length) {
    failAnalysisJob(job.id, {
      stage: '분석 실패',
      progressPercent: 100,
      message: '분석 파일 정보를 복구하지 못했습니다.',
      errorMessage: 'missing-accepted-files',
    });
    return;
  }

  void runAnalysisJob({
    jobId: job.id,
    userId: job.userId,
    acceptedFiles,
  });
}

export function ensureAnalysisJobRunning(jobId) {
  const job = findAnalysisJobById(jobId);
  if (!job || !isJobActiveStatus(job.status)) {
    return job;
  }

  if (isJobHeartbeatStale(job.id, job.updatedAt)) {
    clearJobHeartbeat(job.id);
  }

  startAnalysisJob(job);
  return job;
}

export function stopAnalysisJob(jobId) {
  clearJobHeartbeat(jobId);
  return cancelAnalysisJob(jobId);
}
