'use client';

import { useEffect, useState } from 'react';
import DashboardStyles from './DashboardStyles';
import ConfirmDialog from './ui/ConfirmDialog';
import Toast from './ui/Toast';
import { fetchJson } from '../lib/client/fetch-json';

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return '-';
  }

  const year = date.getFullYear();
  const month = date.getMonth() + 1;
  const day = date.getDate();
  const hours = date.getHours();
  const minutes = String(date.getMinutes()).padStart(2, '0');
  const seconds = String(date.getSeconds()).padStart(2, '0');
  const period = hours >= 12 ? '오후' : '오전';
  const displayHour = hours % 12 || 12;

  return `${year}. ${month}. ${day}. ${period} ${displayHour}:${minutes}:${seconds}`;
}

function formatAuthMethod(user) {
  if (user.authMethod === 'github') return 'GitHub';
  if (user.authMethod === 'hybrid') return '이메일 + GitHub';
  return '이메일';
}

export default function AdminPage() {
  const [users, setUsers] = useState([]);
  const [feedback, setFeedback] = useState('');
  const [toast, setToast] = useState({ message: '', type: 'success' });
  const [targetUserId, setTargetUserId] = useState(null);

  async function loadUsers() {
    try {
      setFeedback('');
      const payload = await fetchJson('/api/admin/users');
      setUsers(payload.users || []);
    } catch {
      window.location.href = '/dashboard';
    }
  }

  useEffect(() => {
    loadUsers();
  }, []);

  async function handleDeleteUser() {
    try {
      await fetchJson(`/api/admin/users/${targetUserId}`, { method: 'DELETE' });
      setFeedback('회원 계정을 삭제했습니다.');
      setToast({ message: '회원 계정을 삭제했습니다.', type: 'success' });
      setTargetUserId(null);
      await loadUsers();
    } catch (error) {
      setFeedback(error.message);
      setToast({ message: error.message, type: 'error' });
      setTargetUserId(null);
    }
  }

  return (
    <div className="dashboard-page">
      <DashboardStyles />
      <main className="dashboard-shell">
        <header className="dashboard-head">
          <a className="dashboard-home" href="/">Phase Vuln Coach</a>
          <div className="dashboard-links">
            <a href="/dashboard">대시보드</a>
            <a href="/analysis">파일 분석</a>
          </div>
        </header>

        <section className="dashboard-card">
          <p className="dashboard-eyebrow">Admin Console</p>
          <h1>회원정보 관리</h1>
          <p className="dashboard-subtext">가입한 회원 목록을 확인하고 필요한 경우 계정을 삭제할 수 있습니다.</p>

          <div className="dashboard-grid single">
            <article className="dashboard-panel">
              <div className="dashboard-actions admin-toolbar">
                <strong>회원 {users.length}명</strong>
                <button className="dashboard-button secondary" type="button" onClick={loadUsers}>새로고침</button>
              </div>
              <p className="dashboard-panel-text">{feedback}</p>
              <div className="admin-user-list">
                {users.length ? users.map((user) => (
                  <article key={user.id} className="admin-user-card">
                    <div>
                      <strong>{user.name}</strong>
                      <p>{user.email}</p>
                    </div>
                    <ul className="dashboard-list admin-user-meta">
                      <li><span>로그인 방식</span><strong>{formatAuthMethod(user)}</strong></li>
                      <li><span>GitHub</span><strong>{user.githubConnected ? '연동됨' : '미연동'}</strong></li>
                      <li><span>권한</span><strong>{user.isAdmin ? '관리자' : '일반 회원'}</strong></li>
                      <li><span>가입 시각</span><strong>{formatDate(user.createdAt)}</strong></li>
                    </ul>
                    <div className="dashboard-actions">
                      <button className="dashboard-button danger" type="button" onClick={() => setTargetUserId(user.id)}>회원 삭제</button>
                    </div>
                  </article>
                )) : <p className="dashboard-panel-text">등록된 회원이 없습니다.</p>}
              </div>
            </article>
          </div>
        </section>
      </main>

      <Toast message={toast.message} type={toast.type} />

      <ConfirmDialog
        open={Boolean(targetUserId)}
        title="회원 삭제"
        message="선택한 회원 계정을 삭제합니다. 이 작업은 되돌릴 수 없습니다."
        confirmLabel="삭제하기"
        onCancel={() => setTargetUserId(null)}
        onConfirm={handleDeleteUser}
      />
    </div>
  );
}
