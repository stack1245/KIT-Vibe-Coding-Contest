const adminUserList = document.getElementById('admin-user-list');
const adminFeedback = document.getElementById('admin-feedback');
const adminUserCount = document.getElementById('admin-user-count');
const adminRefreshButton = document.getElementById('admin-refresh-button');

function ensureUiChrome() {
  if (!document.getElementById('ui-toast')) {
    const toast = document.createElement('div');
    toast.id = 'ui-toast';
    toast.className = 'ui-toast';
    document.body.appendChild(toast);
  }

  if (!document.getElementById('ui-confirm')) {
    const modal = document.createElement('div');
    modal.id = 'ui-confirm';
    modal.className = 'ui-confirm';
    modal.hidden = true;
    modal.innerHTML = `
      <div class="ui-confirm-backdrop" data-ui-close></div>
      <div class="ui-confirm-card" role="dialog" aria-modal="true" aria-labelledby="ui-confirm-title">
        <p class="ui-confirm-eyebrow">확인 필요</p>
        <h2 id="ui-confirm-title" class="ui-confirm-title"></h2>
        <p id="ui-confirm-message" class="ui-confirm-message"></p>
        <div class="ui-confirm-actions">
          <button type="button" class="dashboard-button secondary" id="ui-confirm-cancel">취소</button>
          <button type="button" class="dashboard-button danger" id="ui-confirm-accept">확인</button>
        </div>
      </div>
    `;
    document.body.appendChild(modal);
  }
}

function showToast(message, type = 'info') {
  const toast = document.getElementById('ui-toast');
  if (!toast) return;

  toast.textContent = message;
  toast.className = `ui-toast is-visible ${type}`;

  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => {
    toast.className = 'ui-toast';
  }, 2600);
}

function confirmAction({ title, message, confirmText = '확인' }) {
  const modal = document.getElementById('ui-confirm');
  const titleElement = document.getElementById('ui-confirm-title');
  const messageElement = document.getElementById('ui-confirm-message');
  const acceptButton = document.getElementById('ui-confirm-accept');
  const cancelButton = document.getElementById('ui-confirm-cancel');

  if (!modal || !titleElement || !messageElement || !acceptButton || !cancelButton) {
    return Promise.resolve(false);
  }

  titleElement.textContent = title;
  messageElement.textContent = message;
  acceptButton.textContent = confirmText;
  modal.hidden = false;

  return new Promise((resolve) => {
    const close = (result) => {
      modal.hidden = true;
      acceptButton.removeEventListener('click', onAccept);
      cancelButton.removeEventListener('click', onCancel);
      modal.removeEventListener('click', onBackdrop);
      resolve(result);
    };

    const onAccept = () => close(true);
    const onCancel = () => close(false);
    const onBackdrop = (event) => {
      if (event.target.hasAttribute('data-ui-close')) {
        close(false);
      }
    };

    acceptButton.addEventListener('click', onAccept);
    cancelButton.addEventListener('click', onCancel);
    modal.addEventListener('click', onBackdrop);
  });
}

async function fetchJson(url, options) {
  const response = await fetch(url, { credentials: 'same-origin', ...options });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.message || '요청을 처리하지 못했습니다.');
  return payload;
}

function formatDate(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '-' : date.toLocaleString('ko-KR');
}

function formatAuthMethod(user) {
  if (user.authMethod === 'github') return 'GitHub';
  if (user.authMethod === 'hybrid') return '이메일 + GitHub';
  return '이메일';
}

function setFeedback(message) {
  adminFeedback.textContent = message || '';
}

function renderUsers(users) {
  adminUserCount.textContent = `회원 ${users.length}명`;

  if (!users.length) {
    adminUserList.innerHTML = '<p class="dashboard-panel-text">등록된 회원이 없습니다.</p>';
    return;
  }

  adminUserList.innerHTML = users.map((user) => `
    <article class="admin-user-card">
      <div>
        <strong>${user.name}</strong>
        <p>${user.email}</p>
      </div>
      <ul class="dashboard-list admin-user-meta">
        <li><span>로그인 방식</span><strong>${formatAuthMethod(user)}</strong></li>
        <li><span>GitHub</span><strong>${user.githubConnected ? '연동됨' : '미연동'}</strong></li>
        <li><span>권한</span><strong>${user.isAdmin ? '관리자' : '일반 회원'}</strong></li>
        <li><span>가입 시각</span><strong>${formatDate(user.createdAt)}</strong></li>
      </ul>
      <div class="dashboard-actions">
        <button class="dashboard-button danger" type="button" data-delete-user="${user.id}">회원 삭제</button>
      </div>
    </article>
  `).join('');

  adminUserList.querySelectorAll('[data-delete-user]').forEach((button) => {
    button.addEventListener('click', async () => {
      const userId = button.getAttribute('data-delete-user');
      const confirmed = await confirmAction({
        title: '회원 삭제',
        message: '선택한 회원 계정을 삭제합니다. 이 작업은 되돌릴 수 없습니다.',
        confirmText: '삭제하기',
      });
      if (!confirmed) return;

      try {
        await fetchJson(`/api/admin/users/${userId}`, { method: 'DELETE' });
        setFeedback('회원 계정을 삭제했습니다.');
        showToast('회원 계정을 삭제했습니다.', 'success');
        await loadUsers();
      } catch (error) {
        setFeedback(error.message);
        showToast(error.message, 'error');
      }
    });
  });
}

async function loadUsers() {
  try {
    ensureUiChrome();
    setFeedback('');
    const payload = await fetchJson('/api/admin/users');
    renderUsers(payload.users || []);
  } catch (_error) {
    window.location.href = '/dashboard';
  }
}

adminRefreshButton.addEventListener('click', loadUsers);

loadUsers();