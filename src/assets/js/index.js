const sections = Array.from(document.querySelectorAll('.section'));
const dots = Array.from(document.querySelectorAll('.section-dot'));
const brandHome = document.getElementById('brand-home');
const authNav = document.getElementById('auth-nav');
const siteToast = document.getElementById('site-toast');
let toastTimer;

function showToast(message, type = 'error') {
  if (!siteToast || !message) {
    return;
  }

  window.clearTimeout(toastTimer);
  siteToast.hidden = false;
  siteToast.textContent = message;
  siteToast.className = `site-toast is-visible is-${type}`;
  toastTimer = window.setTimeout(() => {
    siteToast.className = 'site-toast';
    siteToast.hidden = true;
  }, 3200);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => {
    const replacements = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
    return replacements[character] || character;
  });
}

async function loadSession() {
  const response = await fetch('/api/auth/session', { credentials: 'same-origin' });
  if (!response.ok) throw new Error('세션 정보를 불러오지 못했습니다.');
  return response.json();
}

async function logout() {
  const response = await fetch('/api/auth/logout', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
  });
  if (!response.ok) throw new Error('로그아웃에 실패했습니다.');
}

function renderAuthNav(sessionData) {
  if (!authNav) return;

  if (!sessionData.authenticated || !sessionData.user) {
    authNav.innerHTML = '<a class="auth-link" href="/login#signin">로그인</a><a class="auth-link" href="/login#signup">회원가입</a>';
    return;
  }

  const userName = escapeHtml(sessionData.user.name || sessionData.user.login || '계정');
  const avatarUrl = escapeHtml(sessionData.user.avatarUrl || '');
  const avatarMarkup = avatarUrl
    ? `<img src="${avatarUrl}" alt="${userName}" class="auth-avatar">`
    : `<span class="auth-avatar auth-avatar-fallback">${userName.charAt(0)}</span>`;

  authNav.innerHTML = `
    <div class="account-menu">
      <button type="button" class="account-trigger" id="account-trigger" aria-expanded="false">
        ${avatarMarkup}
        <span>${userName}</span>
      </button>
      <div class="account-dropdown" id="account-dropdown" hidden>
        <a class="account-dropdown-link" href="/dashboard">프로필 보기</a>
        <a class="account-dropdown-link" href="/analysis">파일 분석</a>
        ${sessionData.user.isAdmin ? '<a class="account-dropdown-link" href="/admin">관리자 페이지</a>' : ''}
        <button type="button" class="account-dropdown-link account-dropdown-button" id="logout-button">로그아웃</button>
      </div>
    </div>
  `;

  const trigger = document.getElementById('account-trigger');
  const dropdown = document.getElementById('account-dropdown');

  const closeDropdown = () => {
    dropdown.hidden = true;
    trigger.setAttribute('aria-expanded', 'false');
  };

  trigger?.addEventListener('click', (event) => {
    event.stopPropagation();
    const willOpen = dropdown.hidden;
    dropdown.hidden = !willOpen;
    trigger.setAttribute('aria-expanded', String(willOpen));
  });

  document.addEventListener('click', (event) => {
    if (!event.target.closest('.account-menu')) {
      closeDropdown();
    }
  });

  document.getElementById('logout-button')?.addEventListener('click', async () => {
    try {
      await logout();
      window.location.href = '/';
    } catch (error) {
      showToast(error.message, 'error');
    }
  });
}

async function initializeAuthNav() {
  try {
    renderAuthNav(await loadSession());
  } catch (_error) {
    renderAuthNav({ authenticated: false, user: null });
  }
}

function setActiveDot() {
  const middle = window.scrollY + window.innerHeight * 0.45;
  let activeIndex = 0;

  sections.forEach((section, index) => {
    const top = section.offsetTop;
    const bottom = top + section.offsetHeight;
    if (middle >= top && middle < bottom) activeIndex = index;
  });

  dots.forEach((dot, index) => dot.classList.toggle('active', index === activeIndex));
}

function observeRevealElements() {
  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (!entry.isIntersecting) return;
      entry.target.querySelectorAll('.reveal, .feature-animate').forEach((element) => {
        element.classList.add('visible');
      });
    });
  }, { threshold: 0.22 });

  sections.forEach((section) => observer.observe(section));
}

function bindSectionNavigation() {
  document.querySelectorAll('[data-section-target]').forEach((link) => {
    link.addEventListener('click', (event) => {
      event.preventDefault();
      document.querySelector(link.getAttribute('href'))?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });

  dots.forEach((dot, index) => {
    dot.addEventListener('click', () => {
      sections[index]?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });

  brandHome?.addEventListener('click', () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });
}

window.addEventListener('scroll', setActiveDot, { passive: true });
window.addEventListener('load', () => {
  initializeAuthNav();
  bindSectionNavigation();
  observeRevealElements();
  document.querySelectorAll('#hero .reveal').forEach((element) => element.classList.add('visible'));
  setActiveDot();
});