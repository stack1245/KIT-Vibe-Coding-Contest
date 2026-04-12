'use client';

import { useEffect, useMemo, useState } from 'react';
import AnalysisUploadPanel from './AnalysisUploadPanel';
import AppHeader from './AppHeader';
import PageVideoBackdrop from './PageVideoBackdrop';
import styles from './AnalysisPage.module.css';
import { normalizeReportForDisplay } from '../lib/analysis-report-display';
import { fetchJson } from '../lib/client/fetch-json';

function getSeverityRank(value) {
  return { high: 3, medium: 2, low: 1 }[value] || 0;
}

function getSeverityCounts(reports) {
  return reports.reduce((counts, report) => {
    const findings = Array.isArray(report.findings) ? report.findings : [];

    findings.forEach((finding) => {
      if (finding?.severity === 'high' || finding?.severity === 'medium' || finding?.severity === 'low') {
        counts[finding.severity] += 1;
      }
    });

    return counts;
  }, { high: 0, medium: 0, low: 0 });
}

function sanitizeDisplayText(value) {
  return String(value || '')
    .replace(/`/g, '')
    .trim();
}

function getFindingSections(finding) {
  if (finding?.explanation || finding?.detail || finding?.remediation || finding?.location || finding?.patchExample) {
    const sections = [
      {
        label: '1) 취약점 설명',
        value: sanitizeDisplayText(finding.explanation || '설명이 없습니다.'),
        isCodeBlock: false,
      },
      {
        label: '2) 취약점 원인 분석',
        value: sanitizeDisplayText([finding.detail, finding.abuse].filter(Boolean).join('\n\n') || '원인 분석 정보가 없습니다.'),
        isCodeBlock: false,
      },
      {
        label: '3) 파일 경로 및 핵심 코드',
        value: sanitizeDisplayText([
          `파일 경로: ${finding.location || '위치 정보가 없습니다.'}`,
          '핵심 코드:',
          finding.codeLocation || finding.location || '핵심 코드 정보가 없습니다.',
        ].join('\n')),
        isCodeBlock: true,
      },
      {
        label: '4) 취약점 해결 방안',
        value: sanitizeDisplayText(finding.remediation || '대응 방안 정보가 없습니다.'),
        isCodeBlock: false,
      },
      {
        label: '5) 패치 코드 예시',
        value: sanitizeDisplayText(finding.patchExample || '현재 코드:\n관련 코드가 없습니다.\n\n패치 예시 코드:\n구체적인 예시 코드가 제공되지 않았습니다.'),
        isCodeBlock: true,
      },
    ];

    return sections;
  }

  return String(finding?.description || '')
    .split('\n\n')
    .map((entry) => {
      const [rawLabel, ...rest] = entry.split(':');
      return {
        label: rawLabel?.trim() || '설명',
        value: sanitizeDisplayText(rest.join(':').trim() || entry),
      };
    });
}

function formatReportHeading(title) {
  const normalized = String(title || '').trim();
  if (!normalized) {
    return '분석 리포트';
  }

  return /리포트$/u.test(normalized) ? normalized : `${normalized} 분석 리포트`;
}

function buildFindingSignature(finding) {
  return [finding?.title, finding?.location, finding?.severity].filter(Boolean).join('::');
}

function getReportSectionTitle(report) {
  if (report?.resultMode === 'vulnerability') {
    return '취약점 분석';
  }

  if (Number(report?.findingsCount || 0) > 0) {
    return '보완 포인트';
  }

  return /제한 시간 안에 확정 결과를 만들지 못했습니다|추가 검토가 필요합니다|전체 결과를 끝까지 확정하지 못했습니다|전체 로직 검토를 끝내지 못했습니다/.test(String(report?.summary || ''))
    ? '추가 검토'
    : '취약점 분석';
}

function getReportFindingsLabel(report) {
  if (report?.resultMode === 'vulnerability') {
    return `취약점 ${Number(report?.findingsCount || 0)}개`;
  }

  return Number(report?.findingsCount || 0) > 0
    ? `보완 ${Number(report?.findingsCount || 0)}개`
    : '취약점 0개';
}

function buildReportShareText(report, origin = window.location.origin) {
  const lines = [
    `[Phase Vuln Coach] ${report.title}`,
    `분석 시각: ${report.createdAtLabel || report.createdAt || '-'}`,
    `유형: ${report.applicationType}`,
    `전체 심각도: ${report.overallSeverity}`,
    `요약: ${report.summary}`,
  ];

  if (report.findings.length) {
    lines.push(
      '',
      report.resultMode === 'vulnerability' ? '주요 취약점' : '주요 항목',
      ...report.findings.map((finding, index) => `${index + 1}. [${finding.severity}] ${finding.title} - ${finding.location || '위치 정보 없음'}`),
    );
  }

  if (report.shareEnabled && report.shareToken) {
    lines.push('', `공유 링크: ${origin}/shared/${report.shareToken}`);
  }

  return lines.join('\n');
}

async function copyToClipboard(value) {
  const text = String(value || '');
  if (!text) {
    throw new Error('복사할 내용이 없습니다.');
  }

  if (navigator.clipboard?.writeText && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }

  const textArea = document.createElement('textarea');
  textArea.value = text;
  textArea.setAttribute('readonly', 'true');
  textArea.style.position = 'fixed';
  textArea.style.top = '-9999px';
  textArea.style.left = '-9999px';

  document.body.appendChild(textArea);
  textArea.focus();
  textArea.select();
  textArea.setSelectionRange(0, text.length);

  const copied = document.execCommand('copy');
  document.body.removeChild(textArea);

  if (!copied) {
    throw new Error('클립보드 복사에 실패했습니다.');
  }
}

function downloadReport(report) {
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `${report.title.replace(/[^\w.-]+/g, '-').toLowerCase() || 'analysis-report'}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
}

function getTopFindingTitles(reports) {
  const counts = new Map();

  reports.forEach((report) => {
    report.findings.forEach((finding) => {
      const key = String(finding?.title || '').trim();
      if (!key) {
        return;
      }

      counts.set(key, (counts.get(key) || 0) + 1);
    });
  });

  return Array.from(counts.entries())
    .sort((left, right) => right[1] - left[1])
    .slice(0, 3);
}

function matchesSeverity(report, severity) {
  if (severity === 'all') {
    return true;
  }

  return report.overallSeverity === severity || report.findings.some((finding) => finding.severity === severity);
}

export default function AnalysisPage({ initialReports = [], preferences = null, github = null }) {
  const [reports, setReports] = useState(() => initialReports.map((report) => normalizeReportForDisplay(report)));
  const [activeReport, setActiveReport] = useState(null);
  const [pendingDeleteReport, setPendingDeleteReport] = useState(null);
  const [deletingReport, setDeletingReport] = useState(false);
  const [deletingReportId, setDeletingReportId] = useState(null);
  const [deletingAllReports, setDeletingAllReports] = useState(false);
  const [showDeleteAllConfirm, setShowDeleteAllConfirm] = useState(false);
  const [query, setQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [sortBy, setSortBy] = useState(preferences?.defaultAnalysisSort || 'latest');
  const [workspaceNotice, setWorkspaceNotice] = useState('');
  const [sharingReport, setSharingReport] = useState(false);

  useEffect(() => {
    if (!workspaceNotice) {
      return undefined;
    }

    const timer = window.setTimeout(() => setWorkspaceNotice(''), 3200);
    return () => window.clearTimeout(timer);
  }, [workspaceNotice]);

  const filteredReports = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();

    return reports
      .filter((report) => {
        if (!matchesSeverity(report, severityFilter)) {
          return false;
        }

        if (!normalizedQuery) {
          return true;
        }

        const haystack = [
          report.title,
          report.summary,
          report.applicationType,
          ...report.findings.map((finding) => [finding.title, finding.location, finding.detail].filter(Boolean).join(' ')),
        ].join(' ').toLowerCase();

        return haystack.includes(normalizedQuery);
      })
      .sort((left, right) => {
        if (sortBy === 'severity') {
          const severityDelta = getSeverityRank(right.overallSeverity) - getSeverityRank(left.overallSeverity);
          return severityDelta || new Date(right.createdAt).getTime() - new Date(left.createdAt).getTime();
        }

        if (sortBy === 'findings') {
          const findingDelta = Number(right.findingsCount || 0) - Number(left.findingsCount || 0);
          return findingDelta || new Date(right.createdAt).getTime() - new Date(left.createdAt).getTime();
        }

        return new Date(right.createdAt).getTime() - new Date(left.createdAt).getTime();
      });
  }, [query, reports, severityFilter, sortBy]);

  const severityCounts = useMemo(() => getSeverityCounts(reports), [reports]);
  const totalFindings = useMemo(
    () => reports.reduce((total, report) => total + Number(report.findingsCount || 0), 0),
    [reports],
  );
  const sharedReportsCount = useMemo(
    () => reports.filter((report) => report.shareEnabled).length,
    [reports],
  );
  const topFindingTitles = useMemo(() => getTopFindingTitles(reports), [reports]);

  function handleReportCreated(report) {
    if (!report) {
      return;
    }

    const normalizedReport = normalizeReportForDisplay(report);
    setReports((current) => [normalizedReport, ...current.filter((item) => item.id !== normalizedReport.id)].slice(0, 100));
    setActiveReport(normalizedReport);
    setWorkspaceNotice('새 분석 리포트를 추가했습니다.');
  }

  function removeReportFromWorkspace(reportId) {
    setReports((current) => current.filter((report) => report.id !== reportId));
    setActiveReport((current) => (current?.id === reportId ? null : current));
  }

  function updateReportInState(nextReport) {
    const normalizedReport = normalizeReportForDisplay(nextReport);
    setReports((current) => current.map((report) => (report.id === normalizedReport.id ? normalizedReport : report)));
    setActiveReport((current) => (current?.id === normalizedReport.id ? normalizedReport : current));
  }

  async function handleDeleteReport() {
    if (!pendingDeleteReport?.id || deletingReport) {
      return;
    }

    const reportToDelete = pendingDeleteReport;

    setDeletingReportId(reportToDelete.id);
    setDeletingReport(true);

    try {
      await fetchJson(`/api/analysis/reports/${reportToDelete.id}`, {
        method: 'DELETE',
      });
      removeReportFromWorkspace(reportToDelete.id);
      setWorkspaceNotice('분석 리포트를 삭제했습니다.');
    } catch (error) {
      if (error?.status === 404) {
        removeReportFromWorkspace(reportToDelete.id);
        setWorkspaceNotice('이미 삭제된 리포트라 목록에서 정리했습니다.');
        return;
      }

      setWorkspaceNotice(error.message || '분석 삭제에 실패했습니다.');
    } finally {
      setPendingDeleteReport(null);
      setDeletingReportId(null);
      setDeletingReport(false);
    }
  }

  async function handleDeleteReportFromList(report) {
    if (!report?.id || deletingReportId) {
      return;
    }

    setPendingDeleteReport(report);
  }

  function handleRequestDeleteActiveReport() {
    if (!activeReport?.id || deletingReport) {
      return;
    }

    setPendingDeleteReport(activeReport);
  }

  async function handleDeleteAllReports() {
    if (!reports.length || deletingAllReports) {
      return;
    }

    setDeletingAllReports(true);

    try {
      const payload = await fetchJson('/api/analysis/reports', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reportIds: reports.map((report) => report.id) }),
      });

      setReports([]);
      setActiveReport(null);
      setWorkspaceNotice(payload.message || '분석 리포트를 전체 삭제했습니다.');
    } catch (error) {
      setWorkspaceNotice(error.message || '전체 삭제에 실패했습니다.');
    } finally {
      setDeletingAllReports(false);
      setShowDeleteAllConfirm(false);
    }
  }

  async function handleCopyShare(report) {
    try {
      let shareUrl = '';

      if (!report.shareEnabled) {
        setSharingReport(true);
        const payload = await fetchJson(`/api/analysis/reports/${report.id}/share`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            enabled: true,
            origin: window.location.origin,
          }),
        });
        shareUrl = payload.shareUrl || '';
        if (payload.report) {
          updateReportInState(payload.report);
        }
      } else {
        shareUrl = `${window.location.origin}/shared/${report.shareToken}`;
      }

      await copyToClipboard(shareUrl || buildReportShareText(report));
      setWorkspaceNotice(shareUrl ? '공유 링크를 복사했습니다.' : '리포트 요약을 복사했습니다.');
    } catch (error) {
      setWorkspaceNotice(error.message || '공유 링크 복사에 실패했습니다.');
    } finally {
      setSharingReport(false);
    }
  }

  return (
    <div className={styles.pageWrapper}>
      <AppHeader />

      <main className={styles.analysisPage}>
        <PageVideoBackdrop className={styles.analysisBackdrop} />

        <div className={styles.analysisInner}>
          <p className={styles.eyebrow}>analysis workspace</p>

          <div className={styles.pageTitleRow}>
            <h1 className={styles.pageTitle}>취약점 분석 및 실습 환경 제공</h1>
            <div className={styles.pageLine} />
          </div>

          <p className={styles.pageDesc}>
            프로젝트 파일을 업로드하면 취약점 분석 결과를 확인하고,
            탐지된 문제에 맞는 실습 환경으로 바로 이어서 학습할 수 있습니다.
          </p>

          <div className={styles.workspaceStats}>
            <article className={styles.workspaceStatCard}>
              <span>누적 리포트</span>
              <strong>{reports.length}</strong>
              <p>분석 이력을 쌓고 다시 열어볼 수 있습니다.</p>
            </article>
            <article className={styles.workspaceStatCard}>
              <span>탐지 항목</span>
              <strong>{totalFindings}</strong>
              <p>high {severityCounts.high} / medium {severityCounts.medium} / low {severityCounts.low}</p>
            </article>
            <article className={styles.workspaceStatCard}>
              <span>공유 링크</span>
              <strong>{sharedReportsCount}</strong>
              <p>리포트를 팀원과 바로 공유할 수 있습니다.</p>
            </article>
          </div>

          <AnalysisUploadPanel onReportCreated={handleReportCreated} github={github} />

          <section className={styles.singleColumnSection}>
            <article className={styles.contentCard}>
              <div className={styles.cardHead}>
                <h3>분석 워크스페이스</h3>
                <div className={styles.cardHeadActions}>
                  <span>검색, 공유, 재분석을 한 곳에서 처리</span>
                  <button
                    type="button"
                    className={styles.dangerButton}
                    onClick={() => setShowDeleteAllConfirm(true)}
                    disabled={!reports.length || deletingAllReports}
                  >
                    {deletingAllReports ? '전체 삭제 중...' : '전체삭제'}
                  </button>
                </div>
              </div>

              <div className={styles.workspaceToolbar}>
                <label className={styles.toolbarField}>
                  <span>검색</span>
                  <input
                    className={styles.toolbarInput}
                    type="search"
                    value={query}
                    onChange={(event) => setQuery(event.target.value)}
                    placeholder="리포트명, 요약, 취약점명으로 찾기"
                  />
                </label>

                <label className={styles.toolbarField}>
                  <span>심각도</span>
                  <select className={styles.toolbarSelect} value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}>
                    <option value="all">전체</option>
                    <option value="high">high</option>
                    <option value="medium">medium</option>
                    <option value="low">low</option>
                  </select>
                </label>

                <label className={styles.toolbarField}>
                  <span>정렬</span>
                  <select className={styles.toolbarSelect} value={sortBy} onChange={(event) => setSortBy(event.target.value)}>
                    <option value="latest">최신순</option>
                    <option value="severity">위험도순</option>
                    <option value="findings">탐지 수순</option>
                  </select>
                </label>
              </div>

              {workspaceNotice ? <div className={styles.workspaceNotice}>{workspaceNotice}</div> : null}

              {topFindingTitles.length ? (
                <div className={styles.insightStrip}>
                  {topFindingTitles.map(([title, count]) => (
                    <div key={title} className={styles.miniChip}>
                      {title} {count}회
                    </div>
                  ))}
                </div>
              ) : null}

              {filteredReports.length ? (
                <>
                  <div className={styles.resultList}>
                    {filteredReports.map((report) => {
                      return (
                        <div key={report.id} className={styles.resultItem}>
                          <div className={styles.resultTop}>
                            <div>
                              <div className={styles.resultName}>{report.title}</div>
                              <div className={styles.resultMeta} suppressHydrationWarning>{report.createdAtLabel || report.createdAt || ''}</div>
                            </div>
                            <div className={`${styles.severityBadge} ${styles[report.overallSeverity]}`}>{report.overallSeverity}</div>
                          </div>

                          <div className={styles.resultText}>{report.summary}</div>

                          <div className={styles.resultBottom}>
                            <div className={styles.miniChip}>{report.applicationType}</div>
                            <div className={styles.miniChip}>{getReportFindingsLabel(report)}</div>
                            <div className={styles.miniChip}>원본 파일 {report.sourceFiles.length}개</div>
                            {report.shareEnabled ? <div className={styles.miniChip}>공유 중</div> : null}
                          </div>

                          <div className={styles.reportActionsRow}>
                            <button type="button" className={styles.inlineActionButton} onClick={() => setActiveReport(report)}>
                              상세 보기
                            </button>
                            <button type="button" className={styles.inlineActionButton} onClick={() => handleCopyShare(report)} disabled={sharingReport}>
                              링크 복사
                            </button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </>
              ) : (
                <div className={styles.emptyState}>
                  조건에 맞는 분석 리포트가 없습니다. 검색어나 필터를 바꾸거나 새 파일을 업로드해 보세요.
                </div>
              )}
            </article>
          </section>
        </div>
      </main>

      {activeReport ? (
        <div className={styles.reportOverlay}>
          <button
            type="button"
            className={styles.reportBackdrop}
            aria-label="리포트 닫기"
            onClick={() => setActiveReport(null)}
          />
          <div className={styles.reportModal} role="dialog" aria-modal="true">
            <div className={styles.reportHeader}>
              <div>
                <p className={styles.reportEyebrow}>analysis report</p>
                <h2 className={styles.reportTitle}>{formatReportHeading(activeReport.title)}</h2>
              </div>
              <button type="button" className={styles.reportClose} onClick={() => setActiveReport(null)}>
                닫기
              </button>
            </div>

            <div className={styles.reportUtilityBar}>
              <button type="button" className={styles.inlineActionButton} onClick={() => downloadReport(activeReport)}>
                JSON 다운로드
              </button>
              <button type="button" className={styles.inlineActionButton} onClick={() => handleCopyShare(activeReport)} disabled={sharingReport}>
                공유 링크 복사
              </button>
            </div>

            <section className={styles.reportSection}>
              <div className={styles.sectionHead}>
                <h3>구조 요약</h3>
                <span>{activeReport.applicationType}</span>
              </div>
              <p className={styles.reportParagraph}>{activeReport.applicationReport}</p>
            </section>

            <section className={styles.reportSection}>
              <div className={styles.sectionHead}>
                <h3>{getReportSectionTitle(activeReport)}</h3>
                <span suppressHydrationWarning>{activeReport.createdAtLabel || activeReport.createdAt || ''}</span>
              </div>
              <p className={styles.reportParagraph}>{activeReport.summary}</p>

              {activeReport.findings.length ? (
                <div className={styles.reportFindingList}>
                  {activeReport.findings.map((finding) => (
                    <article key={finding.id} className={styles.reportFinding}>
                      <div className={styles.resultTop}>
                        <div className={styles.reportFindingTitle}>{finding.title}</div>
                        <div className={`${styles.severityBadge} ${styles[finding.severity]}`}>{finding.severity}</div>
                      </div>
                      <div className={styles.reportFindingLocation}>{finding.location}</div>
                      <div className={styles.reportFindingSections}>
                        {getFindingSections(finding).map((section) => (
                          <div key={`${finding.id}-${section.label}`} className={styles.reportFindingSection}>
                            <strong className={styles.reportFindingLabel}>{section.label}</strong>
                            {section.isCodeBlock ? (
                              <pre className={styles.reportFindingCodeBlock}>{section.value}</pre>
                            ) : (
                              <p className={styles.reportFindingDescription}>{section.value}</p>
                            )}
                          </div>
                        ))}
                      </div>
                    </article>
                  ))}
                </div>
              ) : (
                <div className={styles.emptyState}>
                  {/제한 시간 안에 확정 결과를 만들지 못했습니다|추가 검토가 필요합니다|전체 결과를 끝까지 확정하지 못했습니다|전체 로직 검토를 끝내지 못했습니다/.test(String(activeReport?.summary || ''))
                    ? '심층 분석이 중단되어 확정 결과를 끝까지 만들지 못했습니다. 이 리포트는 추가 검토가 필요한 상태입니다.'
                    : '실행 가능한 코드 경로에서 확정된 취약점이 확인되지 않았습니다.'}
                </div>
              )}
            </section>

            <div className={styles.reportFooter}>
              <button
                type="button"
                className={styles.deleteReportButton}
                onClick={handleRequestDeleteActiveReport}
                disabled={deletingReport}
              >
                {deletingReport ? '삭제 중...' : '분석 삭제'}
              </button>
            </div>
          </div>
        </div>
      ) : null}

      {pendingDeleteReport ? (
        <div className={styles.reportOverlay}>
          <button
            type="button"
            className={styles.reportBackdrop}
            aria-label="분석 삭제 확인 닫기"
            onClick={() => {
              if (!deletingReport) {
                setPendingDeleteReport(null);
              }
            }}
          />
          <div className={`${styles.reportModal} ${styles.confirmModal}`} role="dialog" aria-modal="true">
            <div className={styles.reportHeader}>
              <div>
                <p className={styles.reportEyebrow}>delete report</p>
                <h2 className={styles.reportTitle}>이 분석을 삭제할까요?</h2>
              </div>
            </div>

            <p className={styles.reportParagraph}>
              `{pendingDeleteReport.title}` 리포트를 삭제합니다.
              삭제 후에는 되돌릴 수 없습니다.
            </p>

            <div className={styles.confirmActions}>
              <button
                type="button"
                className={styles.confirmCloseButton}
                onClick={() => setPendingDeleteReport(null)}
                disabled={deletingReport}
              >
                닫기
              </button>
              <button
                type="button"
                className={styles.deleteReportButton}
                onClick={handleDeleteReport}
                disabled={deletingReport}
              >
                {deletingReport ? '삭제 중...' : '삭제'}
              </button>
            </div>
          </div>
        </div>
      ) : null}

      {showDeleteAllConfirm ? (
        <div className={styles.reportOverlay}>
          <button
            type="button"
            className={styles.reportBackdrop}
            aria-label="전체삭제 확인 닫기"
            onClick={() => {
              if (!deletingAllReports) {
                setShowDeleteAllConfirm(false);
              }
            }}
          />
          <div className={`${styles.reportModal} ${styles.confirmModal}`} role="dialog" aria-modal="true">
            <div className={styles.reportHeader}>
              <div>
                <p className={styles.reportEyebrow}>delete all reports</p>
                <h2 className={styles.reportTitle}>전체삭제 할까요?</h2>
              </div>
            </div>

            <p className={styles.reportParagraph}>
              현재 분석 워크스페이스에 있는 리포트 {reports.length}개를 모두 삭제합니다.
              삭제 후에는 되돌릴 수 없습니다.
            </p>

            <div className={styles.confirmActions}>
              <button
                type="button"
                className={styles.confirmCloseButton}
                onClick={() => setShowDeleteAllConfirm(false)}
                disabled={deletingAllReports}
              >
                닫기
              </button>
              <button
                type="button"
                className={styles.deleteReportButton}
                onClick={handleDeleteAllReports}
                disabled={deletingAllReports}
              >
                {deletingAllReports ? '전체 삭제 중...' : '전체삭제'}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
