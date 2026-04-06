const githubButton = document.getElementById('dashboard-github-button');
const deleteAccountButton = document.getElementById('dashboard-delete-account-button');
const adminLink = document.getElementById('dashboard-admin-link');
const nameElement = document.getElementById('dashboard-name');
const emailElement = document.getElementById('dashboard-email');
const authMethodElement = document.getElementById('dashboard-auth-method');
const githubStatusElement = document.getElementById('dashboard-github-status');
const createdAtElement = document.getElementById('dashboard-created-at');
const githubDescriptionElement = document.getElementById('dashboard-github-description');
const params = new URLSearchParams(window.location.search);

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

Promise.all([fetchJson('/api/auth/config'), fetchJson('/api/auth/session')])
  .then(([config, session]) => {
    ensureUiChrome();

    if (!session.authenticated || !session.user) {
      window.location.href = '/login#signin';
      return;
    }

    const user = session.user;
    nameElement.textContent = user.name || user.login || '계정';
    emailElement.textContent = user.email;
    authMethodElement.textContent = user.authMethod === 'github' ? 'GitHub' : user.authMethod === 'hybrid' ? '이메일 + GitHub' : '이메일';
    githubStatusElement.textContent = user.githubConnected ? '연동됨' : '미연동';
    createdAtElement.textContent = formatDate(user.createdAt);

    if (user.isAdmin) {
      adminLink.hidden = false;
    }

    deleteAccountButton.addEventListener('click', async () => {
      const confirmed = await confirmAction({
        title: '회원탈퇴',
        message: '계정 정보와 연동 정보가 모두 삭제되며 복구할 수 없습니다.',
        confirmText: '탈퇴하기',
      });

      if (!confirmed) return;

      deleteAccountButton.disabled = true;

      try {
        await fetchJson('/api/auth/account', { method: 'DELETE' });
        showToast('회원탈퇴가 완료되었습니다.', 'success');
        window.setTimeout(() => {
          window.location.href = '/';
        }, 700);
      } catch (error) {
        deleteAccountButton.disabled = false;
        showToast(error.message, 'error');
      }
    });

    if (!config.enabled) {
      githubButton.disabled = true;
      githubDescriptionElement.textContent = '현재 서버에 GitHub OAuth 설정이 없습니다.';
      return;
    }

    if (user.githubConnected) {
      githubButton.disabled = true;
      githubButton.textContent = 'GitHub 연동 완료';
      githubDescriptionElement.textContent = '이 계정은 이미 GitHub와 연결되어 있습니다.';
      return;
    }

    githubDescriptionElement.textContent = '일반 회원가입 계정도 GitHub를 연결해 동일한 계정으로 사용할 수 있습니다.';
    githubButton.addEventListener('click', () => {
      window.location.href = config.linkUrl || '/auth/github?mode=link';
    });

    if (params.get('auth') === 'link_success') {
      githubDescriptionElement.textContent = 'GitHub 연동이 완료되었습니다.';
    }
  })
  .catch(() => {
    window.location.href = '/login#signin';
  });