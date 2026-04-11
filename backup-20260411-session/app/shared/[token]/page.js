import AppHeader from '../../../components/AppHeader';
import PageVideoBackdrop from '../../../components/PageVideoBackdrop';
import styles from '../../../components/AnalysisPage.module.css';

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

function getFindingSections(finding) {
  return [
    {
      label: '원인',
      value: String(finding.explanation || '설명이 없습니다.').trim(),
    },
    {
      label: '공격 시나리오',
      value: String([finding.detail, finding.abuse].filter(Boolean).join(' ') || '악용 방식 정보가 없습니다.').trim(),
    },
    {
      label: '위치',
      value: String(finding.codeLocation || finding.location || '위치 정보가 없습니다.').trim(),
    },
    {
      label: '수정 방안',
      value: String(finding.remediation || '대응 방안 정보가 없습니다.').trim(),
    },
  ];
}

export default async function SharedReportPage({ params }) {
  const { findSharedAnalysisReportByToken } = await import('../../../lib/server/database');
  const resolvedParams = await params;
  const report = findSharedAnalysisReportByToken(resolvedParams?.token);

  return (
    <div className={styles.pageWrapper}>
      <AppHeader />
      <main className={styles.analysisPage}>
        <PageVideoBackdrop className={styles.analysisBackdrop} />
        <div className={styles.analysisInner}>
          <p className={styles.eyebrow}>shared analysis</p>
          <div className={styles.pageTitleRow}>
            <h1 className={styles.pageTitle}>
              {report ? `${report.title} 공유 리포트` : '공유 리포트를 찾을 수 없습니다'}
            </h1>
            <div className={styles.pageLine} />
          </div>

          {!report ? (
            <div className={styles.contentCard}>
              <div className={styles.emptyState}>
                공유 링크가 비활성화되었거나 존재하지 않습니다.
              </div>
            </div>
          ) : (
            <div className={styles.reportModal} style={{ position: 'relative', inset: 'auto', maxHeight: 'none', width: '100%' }}>
              <div className={styles.reportHeader}>
                <div>
                  <p className={styles.reportEyebrow}>public report</p>
                  <h2 className={styles.reportTitle}>{report.title}</h2>
                </div>
                <div className={`${styles.severityBadge} ${styles[report.overallSeverity]}`}>{report.overallSeverity}</div>
              </div>

              <section className={styles.reportSection}>
                <div className={styles.sectionHead}>
                  <h3>구조 요약</h3>
                  <span>{report.applicationType}</span>
                </div>
                <p className={styles.reportParagraph}>{report.applicationReport}</p>
              </section>

              <section className={styles.reportSection}>
                <div className={styles.sectionHead}>
                  <h3>{getReportSectionTitle(report)}</h3>
                  <span suppressHydrationWarning>{report.createdAtLabel || report.createdAt || ''}</span>
                </div>
                <p className={styles.reportParagraph}>{report.summary}</p>

                {report.findings.length ? (
                  <div className={styles.reportFindingList}>
                    {report.findings.map((finding) => (
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
                              <p className={styles.reportFindingDescription}>{section.value}</p>
                            </div>
                          ))}
                        </div>
                      </article>
                    ))}
                  </div>
                ) : (
                  <div className={styles.emptyState}>
                    {/제한 시간 안에 확정 결과를 만들지 못했습니다|추가 검토가 필요합니다|전체 결과를 끝까지 확정하지 못했습니다|전체 로직 검토를 끝내지 못했습니다/.test(String(report?.summary || ''))
                      ? '자동 분석이 아직 확정 취약점을 만들지 못했습니다. 요약 문구를 기준으로 추가 검토를 진행하면 됩니다.'
                      : '실행 가능한 코드 경로에서 확정된 취약점이 확인되지 않았습니다.'}
                  </div>
                )}
              </section>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
