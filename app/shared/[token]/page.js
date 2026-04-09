import AppHeader from '../../../components/AppHeader';
import PageVideoBackdrop from '../../../components/PageVideoBackdrop';
import styles from '../../../components/AnalysisPage.module.css';

function getFindingSections(finding) {
  return [
    {
      label: `${finding.title}${finding.title ? ' 취약점이란?' : ' 설명'}`,
      value: String(finding.explanation || '설명이 없습니다.').trim(),
    },
    {
      label: '어떤식으로 악용되는지',
      value: String([finding.detail, finding.abuse].filter(Boolean).join(' ') || '악용 방식 정보가 없습니다.').trim(),
    },
    {
      label: '코드의 위치',
      value: String(finding.codeLocation || finding.location || '위치 정보가 없습니다.').trim(),
    },
    {
      label: '취약점이 안터지기 위해선 어떻게 해야하는지',
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
                  <h3>애플리케이션 내용 분석</h3>
                  <span>{report.applicationType}</span>
                </div>
                <p className={styles.reportParagraph}>{report.applicationReport}</p>
              </section>

              <section className={styles.reportSection}>
                <div className={styles.sectionHead}>
                  <h3>분석 결과</h3>
                  <span suppressHydrationWarning>{report.createdAtLabel || report.createdAt || ''}</span>
                </div>
                <p className={styles.reportParagraph}>{report.summary}</p>

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
              </section>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
