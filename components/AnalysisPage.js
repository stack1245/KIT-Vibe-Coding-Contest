import DashboardStyles from './DashboardStyles';
import styles from './AnalysisPage.module.css';

export default function AnalysisPage() {
  return (
    <div className="dashboard-page">
      <DashboardStyles />
      <main className="dashboard-shell">
        <header className="dashboard-head">
          <a className="dashboard-home" href="/">Phase Vuln Coach</a>
          <div className="dashboard-links">
            <a href="/dashboard">프로필 보기</a>
          </div>
        </header>

        <section className="dashboard-card">
          <p className="dashboard-eyebrow">Analysis</p>
          <h1>파일 분석 워크스페이스</h1>
          <p className="dashboard-subtext">정적 분석 기능을 붙이기 전 단계지만, 실제 제품 화면처럼 분석 흐름과 준비 상태를 한눈에 볼 수 있도록 정리했습니다.</p>

          <div className={styles.analysisHeroGrid}>
            <article className="dashboard-panel">
              <p className={styles.analysisBadge}>준비 중</p>
              <h2>분석 대상 업로드</h2>
              <p className="dashboard-panel-text">차기 단계에서 소스 코드 압축 파일, 개별 소스 파일, 저장소 연결 입력을 받아 정적 분석 요청을 실행할 예정입니다.</p>
              <div className={styles.analysisDropzoneBox}>
                <strong>Upload Zone</strong>
                <span>ZIP, JS, TS, PY, JAVA, CS 예정</span>
              </div>
            </article>

            <article className="dashboard-panel">
              <h2>분석 파이프라인</h2>
              <ul className={styles.analysisStepList}>
                <li><span>1</span><div><strong>입력 수집</strong><p>파일 업로드 또는 저장소 경로 연결</p></div></li>
                <li><span>2</span><div><strong>구문 및 패턴 분석</strong><p>언어별 룰과 취약점 패턴 매칭</p></div></li>
                <li><span>3</span><div><strong>위험도 분류</strong><p>영향도와 악용 가능성을 기반으로 우선순위 산정</p></div></li>
                <li><span>4</span><div><strong>패치 가이드 제안</strong><p>원인, 공격 시나리오, 수정 방향까지 결과화</p></div></li>
              </ul>
            </article>
          </div>

          <div className="dashboard-grid">
            <article className="dashboard-panel">
              <h2>지원 예정 입력 형식</h2>
              <div className={styles.analysisChipGroup}>
                <span className={styles.analysisChip}>GitHub Repository</span>
                <span className={styles.analysisChip}>ZIP Upload</span>
                <span className={styles.analysisChip}>Single File</span>
                <span className={styles.analysisChip}>Batch Scan</span>
              </div>
              <p className="dashboard-panel-text">프로젝트 단위 스캔과 개별 파일 빠른 점검을 모두 지원하는 방향으로 확장할 예정입니다.</p>
            </article>

            <article className="dashboard-panel">
              <h2>우선 적용 예정 진단 항목</h2>
              <ul className="dashboard-list">
                <li><span>입력 검증</span><strong>Injection 계열</strong></li>
                <li><span>인증/인가</span><strong>권한 우회 및 세션 처리</strong></li>
                <li><span>저장 데이터</span><strong>민감 정보 노출</strong></li>
                <li><span>구성 오류</span><strong>위험한 기본 설정</strong></li>
              </ul>
            </article>

            <article className="dashboard-panel">
              <h2>결과 화면 계획</h2>
              <p className="dashboard-panel-text">분석 결과는 취약점 목록, 심각도 필터, 코드 위치, 공격 시나리오, 수정 가이드, 히스토리 비교까지 이어지도록 구성할 예정입니다.</p>
              <div className="dashboard-actions">
                <a className="dashboard-button secondary" href="/dashboard">프로필로 돌아가기</a>
              </div>
            </article>

            <article className="dashboard-panel">
              <h2>현재 상태</h2>
              <p className="dashboard-panel-text">인증 보호, 화면 구조, 서비스 흐름 설명은 준비되어 있습니다. 다음 구현 단계는 실제 업로드 API와 분석 실행 엔진 연결입니다.</p>
            </article>
          </div>
        </section>
      </main>
    </div>
  );
}