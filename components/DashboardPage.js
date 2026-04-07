'use client';

import { useMemo, useState } from 'react';
import DashboardStyles from './DashboardStyles';
import ConfirmDialog from './ui/ConfirmDialog';
import Toast from './ui/Toast';
import { fetchJson } from '../lib/client/fetch-json';

function formatDate(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '-' : date.toLocaleString('ko-KR');
}

function formatAuthMethod(user) {
  if (user.authMethod === 'github') return 'GitHub';
  if (user.authMethod === 'hybrid') return '이메일 + GitHub';
  return '이메일';
}

export default function DashboardPage({ user, config }) {
  const [toast, setToast] = useState({ message: '', type: 'success' });
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const githubMessage = useMemo(() => {
    if (!config.enabled) {
      return '현재 서버에 GitHub OAuth 설정이 없습니다.';
    }

    if (user.githubConnected) {
      return '이 계정은 이미 GitHub와 연결되어 있습니다.';
    }

    return '일반 회원가입 계정도 GitHub를 연결해 동일한 계정으로 사용할 수 있습니다.';
  }, [config.enabled, user.githubConnected]);

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

  return (
    <div className="dashboard-page">
      <DashboardStyles />
      <main className="dashboard-shell">
        <header className="dashboard-head">
          <a className="dashboard-home" href="/">Phase Vuln Coach</a>
          <div className="dashboard-links">
            <a href="/analysis">파일 분석</a>
            {user.isAdmin ? <a href="/admin">관리자</a> : null}
          </div>
        </header>

        <section className="dashboard-card">
          <p className="dashboard-eyebrow">Account Overview</p>
          <h1>{user.name || user.login || '계정 정보'}</h1>
          <p className="dashboard-subtext">{user.email}</p>

          <div className="dashboard-grid">
            <article className="dashboard-panel">
              <h2>인증 상태</h2>
              <ul className="dashboard-list">
                <li><span>현재 로그인 방식</span><strong>{formatAuthMethod(user)}</strong></li>
                <li><span>GitHub 연동 여부</span><strong>{user.githubConnected ? '연동됨' : '미연동'}</strong></li>
                <li><span>가입 시각</span><strong>{formatDate(user.createdAt)}</strong></li>
              </ul>
            </article>

            <article className="dashboard-panel">
              <h2>연결 관리</h2>
              <p className="dashboard-panel-text">{githubMessage}</p>
              <div className="dashboard-actions">
                <button className="dashboard-button" type="button" disabled={!config.enabled || user.githubConnected} onClick={() => (window.location.href = config.linkUrl || '/auth/github?mode=link')}>GitHub 연동하기</button>
                <a className="dashboard-button secondary" href="/analysis">파일 분석으로 이동</a>
              </div>
            </article>

            <article className="dashboard-panel dashboard-panel-danger">
              <h2>계정 관리</h2>
              <p className="dashboard-panel-text">회원탈퇴를 진행하면 계정 정보와 연동 정보가 모두 삭제되며 복구할 수 없습니다.</p>
              <div className="dashboard-actions">
                <button className="dashboard-button danger" type="button" disabled={deleting} onClick={() => setConfirmOpen(true)}>회원탈퇴</button>
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
    </div>
  );
}