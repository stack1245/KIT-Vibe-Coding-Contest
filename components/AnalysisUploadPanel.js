'use client';

import { useMemo, useState } from 'react';
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

export default function AnalysisUploadPanel() {
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [submitting, setSubmitting] = useState(false);
  const [feedback, setFeedback] = useState({ message: '', type: 'neutral' });
  const [result, setResult] = useState(null);

  const totalSelectedSize = useMemo(() => {
    return selectedFiles.reduce((total, file) => total + file.size, 0);
  }, [selectedFiles]);

  function handleChange(event) {
    const nextFiles = Array.from(event.target.files || []);
    setSelectedFiles(nextFiles);
    setResult(null);

    if (!nextFiles.length) {
      setFeedback({ message: '', type: 'neutral' });
      return;
    }

    setFeedback({
      message: `${nextFiles.length}개 파일을 선택했습니다. 총 ${formatBytes(nextFiles.reduce((total, file) => total + file.size, 0))}`,
      type: 'neutral',
    });
  }

  async function handleSubmit(event) {
    event.preventDefault();

    if (!selectedFiles.length) {
      setFeedback({ message: '업로드할 파일을 먼저 선택해주세요.', type: 'error' });
      return;
    }

    setSubmitting(true);
    setResult(null);
    const formElement = event.currentTarget;

    const formData = new FormData();
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

      setResult(payload);

      if (!response.ok) {
        throw new Error(payload.message || '업로드를 처리하지 못했습니다.');
      }

      setFeedback({ message: payload.message || '업로드가 완료되었습니다.', type: 'success' });
      setSelectedFiles([]);
      formElement.reset();
    } catch (error) {
      setFeedback({ message: error.message || '업로드에 실패했습니다.', type: 'error' });
    } finally {
      setSubmitting(false);
    }
  }

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

        <label className={styles.uploadDropzone} htmlFor="analysis-upload-input">
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
          <span>선택 파일 {selectedFiles.length}개</span>
          <span>총 {formatBytes(totalSelectedSize)}</span>
        </div>

        {selectedFiles.length ? (
          <ul className={styles.selectedFileList}>
            {selectedFiles.map((file) => (
              <li key={`${file.name}-${file.size}`}>
                <strong>{file.name}</strong>
                <span>{formatBytes(file.size)}</span>
              </li>
            ))}
          </ul>
        ) : null}

        <div className={styles.uploadActions}>
          <button className={styles.solidButton} type="submit" disabled={submitting}>
            {submitting ? '검사 중...' : '파일 업로드'}
          </button>
        </div>
      </form>

      {feedback.message ? (
        <p className={feedback.type === 'error' ? styles.uploadError : feedback.type === 'success' ? styles.uploadSuccess : styles.uploadNeutral}>
          {feedback.message}
        </p>
      ) : null}

      {result ? (
        <div className={styles.uploadResultGrid}>
          <article className={styles.uploadResultCard}>
            <h3>허용된 파일</h3>
            <p>{result.accepted?.length || 0}개</p>
            <ul className={styles.uploadResultList}>
              {(result.accepted || []).map((entry) => (
                <li key={entry.storedPath}>
                  <strong>{entry.originalName}</strong>
                  <span>{entry.storedPath}</span>
                  <span>{entry.reason}</span>
                </li>
              ))}
            </ul>
          </article>

          <article className={styles.uploadResultCard}>
            <h3>제외된 파일</h3>
            <p>{result.rejected?.length || 0}개</p>
            <ul className={styles.uploadResultList}>
              {(result.rejected || []).map((entry, index) => (
                <li key={`${entry.originalName}-${index}`}>
                  <strong>{entry.originalName}</strong>
                  <span>{entry.reason}</span>
                </li>
              ))}
            </ul>
          </article>
        </div>
      ) : null}
    </section>
  );
}
