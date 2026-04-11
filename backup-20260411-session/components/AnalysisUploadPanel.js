'use client';

import { useEffect, useState } from 'react';
import { fetchJson } from '../lib/client/fetch-json';
import styles from './AnalysisPage.module.css';

function formatBytes(value) {
  if (!Number.isFinite(value)) {
    return '-';
  }

  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let amount = value;
  let unitIndex = 0;

  while (amount >= 1024 && unitIndex < units.length - 1) {
    amount /= 1024;
    unitIndex += 1;
  }

  return `${amount.toFixed(amount >= 10 || unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

function formatElapsedTime(totalSeconds) {
  const safeSeconds = Math.max(0, Math.floor(Number(totalSeconds) || 0));
  const hours = Math.floor(safeSeconds / 3600);
  const minutes = Math.floor((safeSeconds % 3600) / 60);
  const seconds = safeSeconds % 60;

  if (hours > 0) {
    return `${hours}시간 ${minutes}분 ${seconds}초`;
  }

  if (minutes > 0) {
    return `${minutes}분 ${seconds}초`;
  }

  return `${seconds}초`;
}

const ANALYSIS_STAGES = [
  '업로드 진행 중',
  '내용 분석 중',
  '취약점 분석 중',
  '조언 생성 중',
];
const DISPLAY_STAGE_ALIASES = {
  '업로드 진행 중': '업로드 진행 중',
  '구조 분석 중': '내용 분석 중',
  '로직 분석 중': '내용 분석 중',
  '내용 분석 중': '내용 분석 중',
  '취약점 검증 중': '취약점 분석 중',
  '취약점 분석 중': '취약점 분석 중',
  '보안 조언 정리 중': '조언 생성 중',
  '취약점 리포트 정리 중': '조언 생성 중',
  '조언 생성 중': '조언 생성 중',
  '리포트 정리 중': '조언 생성 중',
};
const STAGE_PROGRESS_CAPS = {
  '업로드 진행 중': 18,
  '구조 분석 중': 30,
  '내용 분석 중': 48,
  '로직 분석 중': 55,
  '취약점 분석 중': 74,
  '취약점 검증 중': 80,
  '정밀 재검증 중': 88,
  '조언 생성 중': 94,
  '리포트 정리 중': 94,
  '분석 완료': 100,
  '분석 실패': 100,
};

function normalizeDisplayStage(stage, uploadScreening = false) {
  if (!stage) {
    return uploadScreening ? '업로드 진행 중' : '내용 분석 중';
  }

  if (DISPLAY_STAGE_ALIASES[stage]) {
    return DISPLAY_STAGE_ALIASES[stage];
  }

  if (/업로드/.test(stage)) {
    return '업로드 진행 중';
  }

  if (/조언|정리/.test(stage)) {
    return '조언 생성 중';
  }

  if (/취약점/.test(stage)) {
    return '취약점 분석 중';
  }

  if (/구조|로직|내용/.test(stage)) {
    return '내용 분석 중';
  }

  return uploadScreening ? '업로드 진행 중' : '내용 분석 중';
}

function getStageProgressCap(stage, uploadScreening = false) {
  return STAGE_PROGRESS_CAPS[normalizeDisplayStage(stage, uploadScreening)] ?? 90;
}

function getStageIndex(stage, uploadScreening) {
  const normalizedStage = (stage === '리포트 정리 중' || stage === '취약점 검증 중' || stage === '정밀 재검증 중')
    ? '취약점 분석 중'
    : (stage === '로직 분석 중' || stage === '구조 분석 중')
      ? '내용 분석 중'
      : stage;
  const index = ANALYSIS_STAGES.findIndex((item) => item === normalizedStage);

  return index >= 0 ? index : 0;
}

function getReadableJobError(job) {
  if (!job) {
    return '분석 중 오류가 발생했습니다.';
  }

  if (job.errorMessage === 'stale-analysis-job') {
    return '이전 분석 작업이 중단되어 자동으로 정리했습니다. 다시 업로드해 주세요.';
  }

  if (job.status === 'cancelled' || job.errorMessage === 'cancelled-by-user') {
    return '분석을 취소했습니다.';
  }

  return job.message || job.errorMessage || '분석 중 오류가 발생했습니다.';
}

function getStageDescription(stage) {
  switch (stage) {
    case '업로드 진행 중':
      return '파일을 정리하고 분석 작업을 준비하고 있습니다.';
    case '내용 분석 중':
      return '파일 구조와 핵심 로직을 읽으며 분석 대상을 분류하고 있습니다.';
    case '취약점 분석 중':
      return '취약점 근거와 악용 가능성을 비교하며 검증하고 있습니다.';
    case '조언 생성 중':
    case '리포트 정리 중':
      return '결과를 사람이 읽기 쉬운 리포트 형태로 정리하고 있습니다.';
    case '분석 완료':
      return '분석이 끝났습니다. 최신 리포트를 확인할 수 있습니다.';
    default:
      return '분석 작업을 진행하고 있습니다.';
  }
}

export default function AnalysisUploadPanel({ onReportCreated, github = null }) {
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [activeUploadFiles, setActiveUploadFiles] = useState([]);
  const [repositories, setRepositories] = useState([]);
  const [selectedRepository, setSelectedRepository] = useState('');
  const [loadingRepositories, setLoadingRepositories] = useState(false);
  const [importingRepository, setImportingRepository] = useState(false);
  const [repositoryNotice, setRepositoryNotice] = useState('');
  const [requiresGitHubReconnect, setRequiresGitHubReconnect] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [feedback, setFeedback] = useState({ message: '', type: 'neutral' });
  const [progressValue, setProgressValue] = useState(0);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [currentJob, setCurrentJob] = useState(null);
  const [uploadScreening, setUploadScreening] = useState(false);

  useEffect(() => {
    if (!currentJob?.id || !(currentJob.status === 'queued' || currentJob.status === 'running')) {
      return undefined;
    }

    let cancelled = false;
    const interval = window.setInterval(async () => {
      const payload = await fetchJson(`/api/analysis/jobs/${currentJob.id}`).catch(() => null);
      if (cancelled || !payload?.job) {
        return;
      }

      setCurrentJob(payload.job);
      setProgressValue((current) => Math.max(current, Number(payload.job.progressPercent || 0)));

      if (payload.job.status === 'completed') {
        setProgressValue(100);
        setSubmitting(false);
        setCancelling(false);
        setCurrentJob(null);
        setUploadScreening(false);
        setActiveUploadFiles([]);
        if (payload.report && typeof onReportCreated === 'function') {
          onReportCreated(payload.report);
        }
      }

      if (payload.job.status === 'failed' || payload.job.status === 'cancelled') {
        setSubmitting(false);
        setCancelling(false);
        setCurrentJob(null);
        setUploadScreening(false);
        setProgressValue(0);
        setActiveUploadFiles([]);
        setFeedback({
          message: getReadableJobError(payload.job),
          type: payload.job.status === 'cancelled' ? 'neutral' : 'error',
        });
      }
    }, 2500);

    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [currentJob?.id, currentJob?.status, onReportCreated]);

  useEffect(() => {
    if (!submitting) {
      setElapsedSeconds(0);
      return undefined;
    }

    const startedAt = Date.now();
    const interval = window.setInterval(() => {
      const elapsed = Math.floor((Date.now() - startedAt) / 1000);
      setElapsedSeconds(elapsed);
    }, 700);

    return () => {
      window.clearInterval(interval);
    };
  }, [submitting]);

  useEffect(() => {
    if (!submitting) {
      return undefined;
    }

    const interval = window.setInterval(() => {
      setProgressValue((current) => {
        if (!currentJob?.id || !(currentJob.status === 'queued' || currentJob.status === 'running')) {
          if (current >= 18) {
            return current;
          }

          return Math.min(current + (elapsedSeconds < 8 ? 2 : 0.6), 18);
        }

        const stage = normalizeDisplayStage(currentJob.stage, uploadScreening);
        const floor = Number(currentJob.progressPercent || 0);
        const cap = getStageProgressCap(stage, uploadScreening);
        const nextBase = Math.max(current, floor);

        if (nextBase >= cap) {
          return nextBase;
        }

        const delta = stage === '취약점 분석 중'
          ? 0.35
          : stage === '내용 분석 중'
            ? 0.55
            : 0.45;

        return Math.min(Number((nextBase + delta).toFixed(1)), cap);
      });
    }, 700);

    return () => {
      window.clearInterval(interval);
    };
  }, [submitting, currentJob, elapsedSeconds, uploadScreening]);

  const displayedFiles = submitting && activeUploadFiles.length ? activeUploadFiles : selectedFiles;
  const totalSelectedSize = displayedFiles.reduce((total, file) => total + file.size, 0);
  const currentStageIndex = getStageIndex(currentJob?.stage, uploadScreening);
  const currentStage = normalizeDisplayStage(currentJob?.stage, uploadScreening);
  const roundedProgressValue = Math.max(0, Math.min(100, Math.round(progressValue)));
  const stageStepLabel = `${Math.min(currentStageIndex + 1, ANALYSIS_STAGES.length)} / ${ANALYSIS_STAGES.length}`;
  const stageMessage = getStageDescription(currentStage);

  function applySelectedFiles(nextFiles) {
    setSelectedFiles(nextFiles);

    if (!nextFiles.length) {
      setFeedback({ message: '', type: 'neutral' });
      return;
    }

    setFeedback({
      message: `${nextFiles.length}개 파일을 선택했습니다. 총 ${formatBytes(nextFiles.reduce((total, file) => total + file.size, 0))}`,
      type: 'neutral',
    });
  }

  function handleChange(event) {
    applySelectedFiles(Array.from(event.target.files || []));
  }

  function handleDragEnter(event) {
    event.preventDefault();
    if (submitting) {
      return;
    }

    setIsDragging(true);
  }

  function handleDragOver(event) {
    event.preventDefault();
    if (submitting) {
      return;
    }

    setIsDragging(true);
  }

  function handleDragLeave(event) {
    event.preventDefault();
    if (event.currentTarget.contains(event.relatedTarget)) {
      return;
    }

    setIsDragging(false);
  }

  function handleDrop(event) {
    event.preventDefault();
    setIsDragging(false);

    if (submitting) {
      return;
    }

    applySelectedFiles(Array.from(event.dataTransfer?.files || []));
  }

  async function handleSubmit(event) {
    event.preventDefault();

    if (!selectedFiles.length) {
      setFeedback({ message: '업로드할 파일을 먼저 선택해주세요.', type: 'error' });
      return;
    }

    setSubmitting(true);
    setCancelling(false);
    setUploadScreening(true);
    setProgressValue(8);
    setActiveUploadFiles(selectedFiles);
    const formElement = event.currentTarget;

    const formData = new FormData();
    let createdJobId = null;
    selectedFiles.forEach((file) => {
      formData.append('files', file);
    });

    try {
      const response = await fetch('/api/analysis/upload', {
        method: 'POST',
        credentials: 'same-origin',
        body: formData,
      });
      const payload = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(payload.message || '업로드된 파일을 분석할 수 없습니다. 다른 파일로 시도 해주세요!');
      }

      if (payload.job?.id) {
        createdJobId = payload.job.id;
        setCurrentJob(payload.job);
        setUploadScreening(false);
        setProgressValue((current) => Math.max(current, Number(payload.job.progressPercent || 8)));
      }

      setFeedback({ message: '업로드가 완료되었습니다. 분석은 백그라운드에서 계속 진행됩니다.', type: 'neutral' });
      setSelectedFiles([]);
      formElement.reset();
    } catch (error) {
      setFeedback({ message: error.message || '업로드에 실패했습니다.', type: 'error' });
      setCurrentJob(null);
      setUploadScreening(false);
      setProgressValue(0);
      setActiveUploadFiles([]);
    } finally {
      if (!createdJobId) {
        setSubmitting(false);
        setUploadScreening(false);
      }
    }
  }

  async function handleLoadRepositories() {
    if (loadingRepositories || submitting) {
      return;
    }

    setLoadingRepositories(true);
    setRepositoryNotice('');

    try {
      const payload = await fetchJson('/api/analysis/github/repositories');

      const nextRepositories = Array.isArray(payload.repositories) ? payload.repositories : [];
      setRepositories(nextRepositories);
      setSelectedRepository((current) => current || nextRepositories[0]?.fullName || '');
      setRequiresGitHubReconnect(false);
      setRepositoryNotice(nextRepositories.length ? `${nextRepositories.length}개 저장소를 불러왔습니다.` : '표시할 저장소가 없습니다.');
    } catch (error) {
      setRepositoryNotice(error.message || 'GitHub 저장소 목록을 불러오지 못했습니다.');
    } finally {
      setLoadingRepositories(false);
    }
  }

  async function handleImportRepository() {
    if (!selectedRepository || importingRepository || submitting) {
      return;
    }

    const currentRepository = repositories.find((repository) => repository.fullName === selectedRepository);

    setImportingRepository(true);
    setSubmitting(true);
    setCancelling(false);
    setUploadScreening(true);
    setProgressValue(8);
    setCurrentJob(null);
    setFeedback({ message: '', type: 'neutral' });
    setRepositoryNotice('');
    setActiveUploadFiles([
      {
        name: `${selectedRepository}.zip`,
        size: Number(currentRepository?.size || 0) * 1024,
      },
    ]);

    let createdJobId = null;

    try {
      const payload = await fetchJson('/api/analysis/github/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fullName: selectedRepository }),
      });

      if (payload.job?.id) {
        createdJobId = payload.job.id;
        setCurrentJob(payload.job);
        setUploadScreening(false);
        setProgressValue((current) => Math.max(current, Number(payload.job.progressPercent || 8)));
      }

      setFeedback({
        message: payload.message || 'GitHub 저장소를 가져왔습니다. 분석은 백그라운드에서 계속 진행됩니다.',
        type: 'neutral',
      });
    } catch (error) {
      setFeedback({ message: error.message || 'GitHub 저장소 가져오기에 실패했습니다.', type: 'error' });
      setCurrentJob(null);
      setUploadScreening(false);
      setProgressValue(0);
      setActiveUploadFiles([]);
    } finally {
      if (!createdJobId) {
        setSubmitting(false);
        setUploadScreening(false);
      }
      setImportingRepository(false);
    }
  }

  async function handleCancelAnalysis() {
    if (!currentJob?.id || cancelling) {
      return;
    }

    setCancelling(true);

    try {
      const payload = await fetchJson(`/api/analysis/jobs/${currentJob.id}/cancel`, {
        method: 'POST',
      });

      setSubmitting(false);
      setCurrentJob(null);
      setUploadScreening(false);
      setProgressValue(0);
      setActiveUploadFiles([]);
      setFeedback({
        message: payload.message || '분석을 취소했습니다.',
        type: 'neutral',
      });
    } catch (error) {
      setFeedback({ message: error.message || '분석 취소에 실패했습니다.', type: 'error' });
    } finally {
      setCancelling(false);
    }
  }

  const githubEnabled = Boolean(github?.enabled);
  const githubConnected = Boolean(github?.connected);
  const githubRepoAccess = Boolean(github?.repoAccess);
  const githubLinkUrl = String(github?.linkUrl || '/auth/github?mode=link');

  return (
    <section className={styles.uploadPanel}>
      <form className={styles.uploadBox} onSubmit={handleSubmit}>
        <input
          id="analysis-upload-input"
          className={styles.hiddenInput}
          type="file"
          multiple
          onChange={handleChange}
        />

        <label
          className={`${styles.uploadDropzone} ${isDragging ? styles.uploadDropzoneActive : ''}`.trim()}
          htmlFor={submitting ? undefined : 'analysis-upload-input'}
          onDragEnter={handleDragEnter}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
        >
          <span className={styles.uploadIcon}>
            <img src="/assets/images/upload.png" alt="업로드 아이콘" />
          </span>

          <h2 className={styles.uploadTitle}>솔루션할 파일을 올려주세요</h2>
          <p className={styles.uploadDesc}>
            C, C++, Python, 웹 프로젝트, 모바일 프로젝트 등 분석할 파일을 업로드하면
            자동으로 취약점을 탐지하고 결과와 함께 실습 가능한 환경까지 연결합니다.
          </p>
          <span className={styles.uploadHint}>이 박스 아무 곳이나 눌러 파일을 선택할 수 있습니다.</span>
        </label>

        <div className={styles.uploadMetaRow}>
          <span>선택 파일 {displayedFiles.length}개</span>
          <span>총 {formatBytes(totalSelectedSize)}</span>
        </div>

        {displayedFiles.length ? (
          <ul className={styles.selectedFileList}>
            {displayedFiles.map((file) => (
              <li key={`${file.name}-${file.size}`}>
                <strong>{file.name}</strong>
                <span>{formatBytes(file.size)}</span>
              </li>
            ))}
          </ul>
        ) : null}

        {submitting ? (
          <div className={styles.analysisLoadingCard}>
            <div className={styles.analysisLoadingHead}>
              <div className={styles.analysisLoadingTitleBlock}>
                <strong>분석 진행 중</strong>
                <p>{stageMessage || getStageDescription(currentStage)}</p>
              </div>
              <span className={styles.analysisElapsed}>{formatElapsedTime(elapsedSeconds)} 경과</span>
            </div>

            <div className={styles.analysisStatusRow}>
              <div className={styles.analysisStatusPill}>{currentStage}</div>
              <div className={styles.analysisStatusPillMuted}>단계 {stageStepLabel}</div>
            </div>

            <div className={styles.analysisProgressTrack}>
              <div className={styles.analysisProgressFill} style={{ width: `${progressValue}%` }} />
            </div>

            <div className={styles.analysisLoadingMeta}>
              <span>전체 진행률</span>
              <strong>{roundedProgressValue}%</strong>
            </div>

            <ol className={styles.analysisStageList}>
              {ANALYSIS_STAGES.map((stage, index) => {
                const stateClassName = index < currentStageIndex
                  ? styles.analysisStageDone
                  : index === currentStageIndex
                    ? styles.analysisStageActive
                    : styles.analysisStagePending;

                return (
                  <li key={stage} className={`${styles.analysisStageItem} ${stateClassName}`}>
                    <span className={styles.analysisStageDot} />
                    <span>{stage}</span>
                  </li>
                );
              })}
            </ol>
          </div>
        ) : null}

        <div className={styles.uploadActions}>
          <button className={styles.solidButton} type="submit" disabled={submitting}>
            {submitting ? '분석 중...' : '파일 업로드'}
          </button>
          {submitting && currentJob?.id ? (
            <button
              className={styles.secondaryButton}
              type="button"
              onClick={handleCancelAnalysis}
              disabled={cancelling}
            >
              {cancelling ? '취소 중...' : '분석 취소'}
            </button>
          ) : null}
        </div>
      </form>

      <div className={styles.githubRepoSection}>
        <div className={styles.githubRepoHead}>
          <div>
            <strong>GitHub 저장소 가져오기</strong>
            <p>연동된 GitHub 계정의 저장소를 zipball로 가져와 동일한 필터링과 분석 파이프라인에 태웁니다.</p>
          </div>
        </div>

        {!githubEnabled ? (
          <p className={styles.uploadNeutral}>현재 서버에 GitHub OAuth 설정이 없어 저장소 가져오기를 사용할 수 없습니다.</p>
        ) : null}

        {githubEnabled && !githubConnected ? (
          <div className={styles.githubRepoEmpty}>
            <p className={styles.uploadNeutral}>저장소를 가져오려면 먼저 GitHub 계정을 연동해야 합니다.</p>
            <a className={styles.solidButton} href={githubLinkUrl}>GitHub 연동</a>
          </div>
        ) : null}

        {githubEnabled && githubConnected && (!githubRepoAccess || requiresGitHubReconnect) ? (
          <div className={styles.githubRepoEmpty}>
            <p className={styles.uploadNeutral}>저장소 목록을 읽으려면 `repo` 권한이 포함되도록 GitHub 계정을 다시 연동해야 합니다.</p>
            <a className={styles.solidButton} href={githubLinkUrl}>GitHub 다시 연동</a>
          </div>
        ) : null}

        {githubEnabled && githubConnected && githubRepoAccess && !requiresGitHubReconnect ? (
          <>
            <div className={styles.githubRepoControls}>
              <button
                className={styles.solidButton}
                type="button"
                onClick={handleLoadRepositories}
                disabled={loadingRepositories || submitting}
              >
                {loadingRepositories ? '불러오는 중...' : '저장소 불러오기'}
              </button>

              <label className={styles.githubRepoField}>
                <span>저장소 선택</span>
                <select
                  className={styles.githubRepoSelect}
                  value={selectedRepository}
                  onChange={(event) => setSelectedRepository(event.target.value)}
                  disabled={!repositories.length || submitting}
                >
                  <option value="">{repositories.length ? '저장소를 선택하세요' : '먼저 저장소 목록을 불러오세요'}</option>
                  {repositories.map((repository) => (
                    <option key={repository.id || repository.fullName} value={repository.fullName}>
                      {repository.fullName}{repository.private ? ' (private)' : ''}
                    </option>
                  ))}
                </select>
              </label>

              <button
                className={styles.solidButton}
                type="button"
                onClick={handleImportRepository}
                disabled={!selectedRepository || importingRepository || submitting}
              >
                {importingRepository ? '가져오는 중...' : '저장소 분석'}
              </button>
            </div>

            {selectedRepository ? (
              <p className={styles.githubRepoSelection}>
                선택된 저장소: <strong>{selectedRepository}</strong>
              </p>
            ) : null}
          </>
        ) : null}
      </div>

      {repositoryNotice ? (
        <p className={styles.uploadNeutral}>{repositoryNotice}</p>
      ) : null}

      {feedback.message ? (
        <p className={feedback.type === 'error' ? styles.uploadError : feedback.type === 'success' ? styles.uploadSuccess : styles.uploadNeutral}>
          {feedback.message}
        </p>
      ) : null}
    </section>
  );
}
