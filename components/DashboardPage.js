'use client';

import { useMemo, useState } from 'react';
import AppHeader from './AppHeader';
import DashboardStyles from './DashboardStyles';
import PageVideoBackdrop from './PageVideoBackdrop';
import ConfirmDialog from './ui/ConfirmDialog';
import Toast from './ui/Toast';
import { loadAuthSession } from '../lib/client/auth-session';
import { fetchJson } from '../lib/client/fetch-json';

function formatAuthMethod(user) {
  if (user.authMethod === 'github') return 'GitHub';
  if (user.authMethod === 'hybrid') return '이메일 + GitHub';
  return '이메일';
}

function getSeverityTotals(reports) {
  return reports.reduce((counts, report) => {
    report.findings.forEach((finding) => {
      if (finding?.severity === 'high' || finding?.severity === 'medium' || finding?.severity === 'low') {
        counts[finding.severity] += 1;
      }
    });

    return counts;
  }, { high: 0, medium: 0, low: 0 });
}

function buildNotifications({ user, reports, jobs }) {
  const notifications = [];

  if (reports.length) {
    const latestReport = reports[0];
    notifications.push({
      id: `report-${latestReport.id}`,
      title: '최근 분석 결과가 준비되었습니다.',
      body: `${latestReport.title} 리포트에서 ${latestReport.findingsCount}개 항목을 확인할 수 있습니다.`,
      tone: latestReport.overallSeverity === 'high' ? 'danger' : 'neutral',
    });
  }

  if (jobs.some((job) => job.status === 'failed')) {
    notifications.push({
      id: 'job-failed',
      title: '실패한 분석 작업이 있습니다.',
      body: '분석 페이지에서 실패한 작업 메시지를 확인하고 재분석을 진행해보세요.',
      tone: 'danger',
    });
  }

  if (user.githubConnected) {
    notifications.push({
      id: 'github-connected',
      title: 'GitHub 연동이 활성화되어 있습니다.',
      body: '현재 계정은 이메일 로그인과 GitHub 로그인을 함께 사용할 수 있습니다.',
      tone: 'success',
    });
  }

  if (!reports.length) {
    notifications.push({
      id: 'empty-report',
      title: '아직 분석 이력이 없습니다.',
      body: '첫 파일을 업로드하면 대시보드 통계와 최근 활동이 자동으로 채워집니다.',
      tone: 'neutral',
    });
  }

  return notifications.slice(0, 4);
}

export default function DashboardPage({ user, config, reports = [], jobs = [], preferences }) {
  const [profileName, setProfileName] = useState(user.name || '');
  const [preferenceState, setPreferenceState] = useState({
    preferredLanding: preferences?.preferredLanding || '/dashboard',
    defaultAnalysisSort: preferences?.defaultAnalysisSort || 'latest',
    emailUpdates: Boolean(preferences?.emailUpdates),
    dashboardDigest: Boolean(preferences?.dashboardDigest),
  });
  const [savingProfile, setSavingProfile] = useState(false);
  const [savingPreferences, setSavingPreferences] = useState(false);
  const [toast, setToast] = useState({ message: '', type: 'success' });
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [disconnectOpen, setDisconnectOpen] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [disconnecting, setDisconnecting] = useState(false);
  const canDisconnectGithub = user.githubConnected && user.hasPassword;
  const severityTotals = useMemo(() => getSeverityTotals(reports), [reports]);
  const notifications = useMemo(() => buildNotifications({ user, reports, jobs }), [jobs, reports, user]);

  const githubMessage = useMemo(() => {
    if (!config.enabled) {
      return '현재 서버에 GitHub OAuth 설정이 없습니다.';
    }

    if (user.githubConnected) {
      if (!user.hasPassword) {
        return 'GitHub 단독 로그인 계정은 연결 해지를 할 수 없습니다.';
      }

      return '이 계정은 이미 GitHub와 연결되어 있으며 필요 시 연결 해지도 가능합니다.';
    }

    return '일반 회원가입 계정도 GitHub를 연결해 동일한 계정으로 사용할 수 있습니다.';
  }, [config.enabled, user.githubConnected, user.hasPassword]);

  async function handleDisconnectGithub() {
    setDisconnecting(true);

    try {
      await fetchJson('/api/auth/github-link', { method: 'DELETE' });
      setToast({ message: 'GitHub 계정 연결이 해지되었습니다.', type: 'success' });
      window.setTimeout(() => {
        window.location.reload();
      }, 700);
    } catch (error) {
      setToast({ message: error.message, type: 'error' });
      setDisconnecting(false);
    }
  }

  async function handleDeleteAccount() {
    setDeleting(true);

    try {
      await fetchJson('/api/auth/account', { method: 'DELETE' });
      setToast({ message: '회원탈퇴가 완료되었습니다.', type: 'success' });
      window.setTimeout(() => {
        window.location.href = '/';
      }, 700);
    } catch (error) {
      setToast({ message: error.message, type: 'error' });
      setDeleting(false);
    }
  }

  async function handleUpdateProfile(event) {
    event.preventDefault();
    setSavingProfile(true);

    try {
      const payload = await fetchJson('/api/auth/account', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ displayName: profileName }),
      });

      setProfileName(payload.user?.name || profileName);
      await loadAuthSession({ force: true });
      setToast({ message: '닉네임이 변경되었습니다.', type: 'success' });
      window.setTimeout(() => {
        window.location.reload();
      }, 450);
    } catch (error) {
      setToast({ message: error.message, type: 'error' });
      setSavingProfile(false);
    }
  }

  async function handleSavePreferences(event) {
    event.preventDefault();
    setSavingPreferences(true);

    try {
      await fetchJson('/api/auth/account', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ preferences: preferenceState }),
      });

      await loadAuthSession({ force: true });
      setToast({ message: '환경설정을 저장했습니다.', type: 'success' });
    } catch (error) {
      setToast({ message: error.message, type: 'error' });
    } finally {
      setSavingPreferences(false);
    }
  }

  return (
    <div className="dashboard-page">
      <DashboardStyles />
      <AppHeader />
      <PageVideoBackdrop className="dashboard-video-backdrop" />
      <main className="dashboard-shell">
        <section className="dashboard-card">
          <p className="dashboard-eyebrow">Account Overview</p>
          <h1>{profileName || user.login || '계정 정보'}</h1>
          <p className="dashboard-subtext">{user.email}</p>

          <div className="dashboard-stat-grid">
            <article className="dashboard-stat">
              <span>누적 분석 리포트</span>
              <strong>{reports.length}</strong>
              <p>최근 업로드부터 비교와 공유까지 이어서 관리할 수 있습니다.</p>
            </article>
            <article className="dashboard-stat">
              <span>누적 탐지 항목</span>
              <strong>{severityTotals.high + severityTotals.medium + severityTotals.low}</strong>
              <p>high {severityTotals.high} / medium {severityTotals.medium} / low {severityTotals.low}</p>
            </article>
            <article className="dashboard-stat">
              <span>최근 활동</span>
              <strong>{jobs.length}</strong>
              <p>분석 진행 이력과 완료 상태를 대시보드에서 바로 확인합니다.</p>
            </article>
          </div>

          <div className="dashboard-grid">
            <article className="dashboard-panel">
              <h2>인증 상태</h2>
              <ul className="dashboard-list">
                <li><span>현재 로그인 방식</span><strong>{formatAuthMethod(user)}</strong></li>
                <li><span>GitHub 연동 여부</span><strong>{user.githubConnected ? '연동됨' : '미연동'}</strong></li>
                <li><span>가입 시각</span><strong>{user.createdAtLabel || '-'}</strong></li>
              </ul>
            </article>

            <article className="dashboard-panel">
              <h2>프로필</h2>
              <form className="dashboard-form" onSubmit={handleUpdateProfile}>
                <label className="dashboard-field">
                  <span>닉네임</span>
                  <input
                    className="dashboard-input"
                    type="text"
                    maxLength={30}
                    value={profileName}
                    onChange={(event) => setProfileName(event.target.value)}
                    placeholder="닉네임을 입력하세요"
                  />
                </label>
                <div className="dashboard-actions">
                  <button
                    className="dashboard-button"
                    type="submit"
                    disabled={savingProfile || profileName.trim() === (user.name || '').trim()}
                  >
                    {savingProfile ? '저장 중...' : '닉네임 저장'}
                  </button>
                </div>
              </form>
            </article>

            <article className="dashboard-panel">
              <h2>개인 설정</h2>
              <form className="dashboard-form" onSubmit={handleSavePreferences}>
                <label className="dashboard-field">
                  <span>로그인 후 기본 이동</span>
                  <select
                    className="dashboard-input"
                    value={preferenceState.preferredLanding}
                    onChange={(event) => setPreferenceState((current) => ({ ...current, preferredLanding: event.target.value }))}
                  >
                    <option value="/dashboard">대시보드</option>
                    <option value="/analysis">분석 페이지</option>
                  </select>
                </label>

                <label className="dashboard-field">
                  <span>분석 기본 정렬</span>
                  <select
                    className="dashboard-input"
                    value={preferenceState.defaultAnalysisSort}
                    onChange={(event) => setPreferenceState((current) => ({ ...current, defaultAnalysisSort: event.target.value }))}
                  >
                    <option value="latest">최신순</option>
                    <option value="severity">위험도순</option>
                    <option value="findings">탐지 수순</option>
                  </select>
                </label>

                <label className="dashboard-check">
                  <input
                    type="checkbox"
                    checked={preferenceState.emailUpdates}
                    onChange={(event) => setPreferenceState((current) => ({ ...current, emailUpdates: event.target.checked }))}
                  />
                  <span>보안 업데이트 안내 수신</span>
                </label>

                <label className="dashboard-check">
                  <input
                    type="checkbox"
                    checked={preferenceState.dashboardDigest}
                    onChange={(event) => setPreferenceState((current) => ({ ...current, dashboardDigest: event.target.checked }))}
                  />
                  <span>대시보드 요약 카드 강조</span>
                </label>

                <div className="dashboard-actions">
                  <button className="dashboard-button" type="submit" disabled={savingPreferences}>
                    {savingPreferences ? '저장 중...' : '설정 저장'}
                  </button>
                </div>
              </form>
            </article>

            <article className="dashboard-panel">
              <h2>알림 센터</h2>
              <div className="dashboard-feed">
                {notifications.map((notification) => (
                  <div key={notification.id} className={`dashboard-feed-item ${notification.tone}`}>
                    <strong>{notification.title}</strong>
                    <p>{notification.body}</p>
                  </div>
                ))}
              </div>
            </article>

            <article className="dashboard-panel dashboard-panel-danger">
              <h2>계정 관리</h2>
              <p className="dashboard-panel-text">회원탈퇴를 진행하면 계정 정보와 연동 정보가 모두 삭제되며 복구할 수 없습니다.</p>
              <div className="dashboard-actions">
                <button className="dashboard-button danger" type="button" disabled={deleting} onClick={() => setConfirmOpen(true)}>회원탈퇴</button>
              </div>
            </article>

            <article className="dashboard-panel">
              <h2>연결 관리</h2>
              <p className="dashboard-panel-text">{githubMessage}</p>
              <div className="dashboard-actions">
                <button className="dashboard-button" type="button" disabled={!config.enabled || user.githubConnected} onClick={() => (window.location.href = config.linkUrl || '/auth/github?mode=link')}>GitHub 연동하기</button>
                <button className="dashboard-button disconnect" type="button" disabled={!canDisconnectGithub || disconnecting} onClick={() => setDisconnectOpen(true)}>{disconnecting ? '해지 중...' : 'GitHub 계정 해지'}</button>
                <a className="dashboard-button secondary" href="/analysis">파일 분석으로 이동</a>
              </div>
            </article>
          </div>
        </section>
      </main>

      <Toast message={toast.message} type={toast.type} />

      <ConfirmDialog
        open={confirmOpen}
        title="회원탈퇴"
        message="계정 정보와 연동 정보가 모두 삭제되며 복구할 수 없습니다."
        confirmLabel="탈퇴하기"
        onCancel={() => setConfirmOpen(false)}
        onConfirm={handleDeleteAccount}
      />

      <ConfirmDialog
        open={disconnectOpen}
        title="GitHub 연결 해지"
        message="현재 계정에서 GitHub 연동 정보를 제거합니다. 이후에는 이메일 로그인으로만 접근할 수 있습니다."
        confirmLabel="해지하기"
        onCancel={() => setDisconnectOpen(false)}
        onConfirm={handleDisconnectGithub}
      />
    </div>
  );
}
