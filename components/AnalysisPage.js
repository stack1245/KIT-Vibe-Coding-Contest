import AnalysisUploadPanel from './AnalysisUploadPanel';
import AppHeader from './AppHeader';
import PageVideoBackdrop from './PageVideoBackdrop';
import styles from './AnalysisPage.module.css';

export default function AnalysisPage() {
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

          <AnalysisUploadPanel />

          <section className={styles.subGrid}>
            <article className={styles.contentCard}>
              <div className={styles.cardHead}>
                <h3>최근 분석 결과</h3>
                <span>최근 실행 기준</span>
              </div>

              <div className={styles.resultList}>
                <div className={styles.resultItem}>
                  <div className={styles.resultTop}>
                    <div className={styles.resultName}>SQL Injection 가능성 탐지</div>
                    <div className={`${styles.severityBadge} ${styles.high}`}>high</div>
                  </div>
                  <div className={styles.resultText}>
                    사용자 입력값이 검증 없이 쿼리에 직접 포함될 수 있습니다.
                    파라미터 바인딩 또는 prepared statement로 분리하는 방식이 필요합니다.
                  </div>
                  <div className={styles.resultMeta}>src/api/userController.js · line 84 ~ 102</div>
                </div>

                <div className={styles.resultItem}>
                  <div className={styles.resultTop}>
                    <div className={styles.resultName}>하드코딩된 API Key 노출</div>
                    <div className={`${styles.severityBadge} ${styles.medium}`}>medium</div>
                  </div>
                  <div className={styles.resultText}>
                    민감한 키 값이 코드 안에 직접 포함되어 있습니다.
                    환경 변수 또는 별도 secret 관리 방식으로 분리하는 편이 안전합니다.
                  </div>
                  <div className={styles.resultMeta}>config/app.py · line 12</div>
                </div>

                <div className={styles.resultItem}>
                  <div className={styles.resultTop}>
                    <div className={styles.resultName}>입력 길이 검증 부족</div>
                    <div className={`${styles.severityBadge} ${styles.low}`}>low</div>
                  </div>
                  <div className={styles.resultText}>
                    특정 입력 지점에서 허용 길이 제한이 명확하지 않습니다.
                    예외 처리와 길이 검증을 추가하면 안정성이 좋아집니다.
                  </div>
                  <div className={styles.resultMeta}>forms/register.tsx · line 44 ~ 58</div>
                </div>
              </div>

              <div className={styles.resultBottom}>
                <div className={styles.miniChip}>총 12개 탐지</div>
                <div className={styles.miniChip}>high 3개</div>
                <div className={styles.miniChip}>medium 4개</div>
                <div className={styles.miniChip}>low 5개</div>
              </div>
            </article>

            <article className={styles.contentCard}>
              <div className={styles.cardHead}>
                <h3>샌드박스 환경</h3>
                <span>분석 후 자동 연결</span>
              </div>

              <div className={styles.sandboxList}>
                <div className={styles.sandboxItem}>
                  <h4>시스템 해킹 실습 환경</h4>
                  <p>
                    메모리 손상, 입력 처리 실수, 권한 상승 같은 취약점을
                    직접 재현해보는 실습 공간입니다.
                  </p>
                  <div className={styles.sandboxTags}>
                    <div className={styles.miniChip}>System</div>
                    <div className={styles.miniChip}>BOF</div>
                    <div className={styles.miniChip}>권한 상승</div>
                  </div>
                </div>

                <div className={styles.sandboxItem}>
                  <h4>안드로이드 실습 환경</h4>
                  <p>
                    저장소 노출, 잘못된 컴포넌트 설정, 인증 우회 같은
                    모바일 취약점을 단계별로 확인할 수 있습니다.
                  </p>
                  <div className={styles.sandboxTags}>
                    <div className={styles.miniChip}>Android</div>
                    <div className={styles.miniChip}>Intent</div>
                    <div className={styles.miniChip}>Storage</div>
                  </div>
                </div>

                <div className={styles.sandboxItem}>
                  <h4>웹 애플리케이션 실습 환경</h4>
                  <p>
                    SQL Injection, XSS, 인증/인가 문제처럼
                    분석 결과와 바로 연결되는 웹 취약점 실습 환경입니다.
                  </p>
                  <div className={styles.sandboxTags}>
                    <div className={styles.miniChip}>Web</div>
                    <div className={styles.miniChip}>SQLi</div>
                    <div className={styles.miniChip}>XSS</div>
                  </div>
                </div>
              </div>
            </article>
          </section>
        </div>
      </main>
    </div>
  );
}
