const copy = {
  signin: { githubLabel: 'GitHub로 로그인' },
  signup: { githubLabel: 'GitHub로 회원가입' },
};

const panels = { signin: document.getElementById('signin-panel'), signup: document.getElementById('signup-panel') };
const tabs = { signin: document.getElementById('signin-tab'), signup: document.getElementById('signup-tab') };
const feedback = document.getElementById('form-feedback');
const githubButton = document.getElementById('github-auth-button');
const githubButtonLabel = document.getElementById('github-button-label');
const githubAuthStatus = document.getElementById('github-auth-status');
const signupSendCodeButton = document.getElementById('signup-send-code');
const signupEmailInput = document.getElementById('signup-email');
const signupPasswordInput = document.getElementById('signup-password');
const signupConfirmPasswordInput = document.getElementById('signup-confirm-password');
const signupSubmitButton = panels.signup.querySelector('.submit-button');
const verificationModal = document.getElementById('verification-modal');
const verificationModalCode = document.getElementById('verification-modal-code');
const verificationConfirmButton = document.getElementById('verification-confirm-button');
const urlParams = new URLSearchParams(window.location.search);
let feedbackTimer;
let verifiedEmail = '';

function setFeedback(message, type = 'error') {
  window.clearTimeout(feedbackTimer);
  if (!message) {
    feedback.className = 'feedback-toast';
    feedback.textContent = '';
    return;
  }

  feedback.className = `feedback-toast is-visible ${type}`;
  feedback.textContent = message;
  feedbackTimer = window.setTimeout(() => setFeedback(''), 4200);
}

function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function isStrongPassword(value) {
  return /^(?=.*[A-Za-z])(?=.*\d).{8,}$/.test(value);
}

function serializeForm(form) {
  return Object.fromEntries(new FormData(form).entries());
}

function getSigninError(formData) {
  if (!formData.email || !formData.password) return '이메일과 비밀번호를 모두 입력해주세요.';
  if (!isValidEmail(formData.email)) return '올바른 이메일 형식을 입력해주세요.';
  return '';
}

function getSignupError(formData) {
  if (!formData.email || !formData.password || !formData.confirmPassword) {
    return '이메일과 비밀번호를 모두 입력해주세요.';
  }
  if (!isValidEmail(formData.email)) return '올바른 이메일 형식을 입력해주세요.';
  if (verifiedEmail !== formData.email.trim().toLowerCase()) return '이메일 인증을 먼저 완료해주세요.';
  if (!isStrongPassword(formData.password)) return '비밀번호는 영문과 숫자를 포함한 8자 이상이어야 합니다.';
  if (formData.password !== formData.confirmPassword) return '비밀번호와 비밀번호 확인이 일치하지 않습니다.';
  return '';
}

function setSignupReadyState(isVerified) {
  signupPasswordInput.disabled = !isVerified;
  signupConfirmPasswordInput.disabled = !isVerified;
  signupSubmitButton.disabled = !isVerified;
  signupEmailInput.readOnly = isVerified;
  signupSendCodeButton.textContent = isVerified ? '인증 완료' : '인증 요청';
}

function resetSignupVerification() {
  verifiedEmail = '';
  verificationModalCode.value = '';
  setSignupReadyState(false);
}

function openVerificationModal() {
  verificationModal.hidden = false;
  verificationModalCode.value = '';
  verificationModalCode.focus();
}

function closeVerificationModal() {
  verificationModal.hidden = true;
}

function getAuthMessage(key) {
  const messages = {
    auth_success: 'GitHub 로그인에 성공했습니다.',
    link_success: '현재 계정에 GitHub 연동이 완료되었습니다.',
    config_missing: '서버에 GitHub OAuth 설정이 없습니다. .env 값을 먼저 채워주세요.',
    invalid_state: '로그인 상태 검증에 실패했습니다. 다시 시도해주세요.',
    github_access_denied: 'GitHub 로그인이 취소되었습니다.',
    token_exchange_failed: 'GitHub 인증 토큰을 가져오지 못했습니다.',
    github_request_failed: 'GitHub 요청 처리 중 오류가 발생했습니다.',
    login_required: 'GitHub 연동을 하려면 먼저 이메일 계정으로 로그인해야 합니다.',
    github_already_linked: '이미 다른 계정에 연결된 GitHub 계정입니다.',
    github_not_linked: '같은 이메일의 일반 계정이 이미 있습니다. 먼저 이메일 로그인 후 GitHub를 연동하세요.',
    github_email_missing: 'GitHub 계정에서 확인 가능한 이메일을 가져오지 못했습니다.',
  };
  return messages[key] || '';
}

function showPanel(target, shouldFocus = false) {
  Object.entries(panels).forEach(([name, panel]) => {
    const active = name === target;
    panel.classList.toggle('is-active', active);
    panel.setAttribute('aria-hidden', String(!active));
    panel.hidden = !active;
  });

  Object.entries(tabs).forEach(([name, tab]) => {
    const active = name === target;
    tab.classList.toggle('is-active', active);
    tab.setAttribute('aria-selected', String(active));
  });

  githubButtonLabel.textContent = copy[target].githubLabel;
  window.location.hash = target;

  if (shouldFocus) {
    panels[target].querySelector('input')?.focus();
  }
}

async function fetchJson(url, options) {
  const response = await fetch(url, { credentials: 'same-origin', ...options });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.message || '요청을 처리하지 못했습니다.');
  return payload;
}

function syncAuthStatus(config, session) {
  if (!config.enabled) {
    githubButton.disabled = true;
    githubAuthStatus.textContent = 'GitHub 설정이 비어 있습니다.';
    return;
  }

  if (session.authenticated && session.user) {
    window.location.replace('/dashboard');
    return;
  }

  githubButton.disabled = false;
  const mode = window.location.hash === '#signup' ? 'signup' : 'signin';
  githubButtonLabel.textContent = copy[mode].githubLabel;
  githubAuthStatus.textContent = '이메일 인증 후 회원가입할 수 있습니다.';
}

async function requestVerificationCode() {
  const email = String(signupEmailInput.value || '').trim();

  if (!email) {
    setFeedback('인증 코드를 받을 이메일을 입력해주세요.', 'error');
    signupEmailInput.focus();
    return;
  }

  if (!isValidEmail(email)) {
    setFeedback('올바른 이메일 형식을 입력해주세요.', 'error');
    signupEmailInput.focus();
    return;
  }

  signupSendCodeButton.disabled = true;
  resetSignupVerification();

  try {
    await fetchJson('/api/auth/email-verification/request', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });

    setFeedback('인증 코드를 이메일로 전송했습니다.', 'success');
    openVerificationModal();
  } catch (error) {
    setFeedback(error.message, 'error');
  } finally {
    signupSendCodeButton.disabled = false;
  }
}

tabs.signin.addEventListener('click', () => showPanel('signin', true));
tabs.signup.addEventListener('click', () => showPanel('signup', true));

document.querySelectorAll('[data-switch]').forEach((link) => {
  link.addEventListener('click', (event) => {
    event.preventDefault();
    showPanel(link.dataset.switch, true);
  });
});

signupSendCodeButton?.addEventListener('click', requestVerificationCode);
signupEmailInput?.addEventListener('input', () => {
  if (verifiedEmail && verifiedEmail !== String(signupEmailInput.value || '').trim().toLowerCase()) {
    resetSignupVerification();
  }
});

verificationConfirmButton?.addEventListener('click', async () => {
  const email = String(signupEmailInput.value || '').trim();
  const code = String(verificationModalCode.value || '').trim();

  if (!/^\d{6}$/.test(code)) {
    setFeedback('인증 코드는 6자리 숫자여야 합니다.', 'error');
    verificationModalCode.focus();
    return;
  }

  verificationConfirmButton.disabled = true;

  try {
    await fetchJson('/api/auth/email-verification/confirm', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, code }),
    });

    verifiedEmail = email.toLowerCase();
    setSignupReadyState(true);
    closeVerificationModal();
    signupPasswordInput.focus();
    setFeedback('이메일 인증이 완료되었습니다. 비밀번호를 설정해주세요.', 'success');
  } catch (error) {
    closeVerificationModal();
    resetSignupVerification();
    setFeedback(`${error.message} 다시 인증을 요청해주세요.`, 'error');
  } finally {
    verificationConfirmButton.disabled = false;
  }
});

githubButton.addEventListener('click', () => {
  if (githubButton.disabled) return;

  const mode = window.location.hash === '#signup' ? 'signup' : 'signin';
  window.location.href = `/auth/github?mode=${mode}`;
});

panels.signin.addEventListener('submit', async (event) => {
  event.preventDefault();
  const formData = serializeForm(panels.signin);
  const errorMessage = getSigninError(formData);
  if (errorMessage) return setFeedback(errorMessage, 'error');

  try {
    await fetchJson('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(formData),
    });
    window.location.href = '/';
  } catch (error) {
    setFeedback(error.message, 'error');
  }
});

panels.signup.addEventListener('submit', async (event) => {
  event.preventDefault();
  const formData = serializeForm(panels.signup);
  const errorMessage = getSignupError(formData);
  if (errorMessage) return setFeedback(errorMessage, 'error');

  try {
    await fetchJson('/api/auth/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(formData),
    });
    window.location.href = '/dashboard';
  } catch (error) {
    setFeedback(error.message, 'error');
  }
});

window.addEventListener('hashchange', () => {
  showPanel(window.location.hash === '#signup' ? 'signup' : 'signin');
});

showPanel(window.location.hash === '#signup' ? 'signup' : 'signin');
setSignupReadyState(false);

Promise.all([fetchJson('/api/auth/config'), fetchJson('/api/auth/session')])
  .then(([config, session]) => {
    syncAuthStatus(config, session);
    if (urlParams.get('auth') === 'success') setFeedback(getAuthMessage('auth_success'), 'success');
    if (urlParams.get('auth') === 'link_success') setFeedback(getAuthMessage('link_success'), 'success');
    if (urlParams.get('error')) setFeedback(getAuthMessage(urlParams.get('error')), 'error');
  })
  .catch(() => {
    githubAuthStatus.textContent = '인증 상태를 불러오지 못했습니다.';
  });