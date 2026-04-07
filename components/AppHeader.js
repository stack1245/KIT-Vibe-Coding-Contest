'use client';

import { useEffect, useMemo, useState } from 'react';
import styles from './AppHeader.module.css';

const sections = [
  { id: 'hero', label: '홈' },
  { id: 'feature', label: '서비스' },
  { id: 'ai', label: '소개' },
  { id: 'team', label: '개발자' },
];

function cx(...classNames) {
  return classNames.filter(Boolean).map((className) => styles[className]).join(' ');
}

export default function AppHeader() {
  const [session, setSession] = useState({ authenticated: false, user: null });
  const [dropdownOpen, setDropdownOpen] = useState(false);

  useEffect(() => {
    let ignore = false;

    fetch('/api/auth/session', { credentials: 'same-origin' })
      .then((response) => response.json())
      .then((payload) => {
        if (!ignore) {
          setSession(payload);
        }
      })
      .catch(() => {
        if (!ignore) {
          setSession({ authenticated: false, user: null });
        }
      });

    return () => {
      ignore = true;
    };
  }, []);

  const userName = useMemo(() => {
    return session.user?.name || session.user?.login || '계정';
  }, [session.user]);

  async function handleLogout() {
    try {
      await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' });
    } finally {
      window.location.href = '/';
    }
  }

  return (
    <header className={styles.topbar}>
      <div className={styles['topbar-left']}>
        <a className={styles.brand} href="/" aria-label="메인 페이지로 이동">
          <img src="/assets/images/phase-logo.png" alt="Phase Vuln Coach" className={styles['brand-logo-image']} />
        </a>

        <nav className={styles['menu-left']} aria-label="주요 메뉴">
          {sections.map((section) => (
            <a key={section.id} className={styles['menu-link']} href={`/#${section.id}`}>
              {section.label}
            </a>
          ))}
        </nav>
      </div>

      <nav className={styles['menu-right']} aria-label="인증 메뉴">
        {!session.authenticated || !session.user ? (
          <>
            <a className={styles['auth-link']} href="/login#signin">로그인</a>
            <a className={styles['auth-link']} href="/login#signup">회원가입</a>
          </>
        ) : (
          <div className={styles['account-menu']}>
            <button
              type="button"
              className={styles['account-trigger']}
              aria-expanded={dropdownOpen}
              onClick={() => setDropdownOpen((current) => !current)}
            >
              {session.user.avatarUrl ? (
                <img src={session.user.avatarUrl} alt={userName} className={styles['auth-avatar']} />
              ) : (
                <span className={cx('auth-avatar', 'auth-avatar-fallback')}>{userName.charAt(0)}</span>
              )}
              <span>{userName}</span>
            </button>

            {dropdownOpen ? (
              <div className={styles['account-dropdown']}>
                <a className={styles['account-dropdown-link']} href="/dashboard">프로필 보기</a>
                <a className={styles['account-dropdown-link']} href="/analysis">파일 분석</a>
                {session.user.isAdmin ? <a className={styles['account-dropdown-link']} href="/admin">관리자 페이지</a> : null}
                <button type="button" className={cx('account-dropdown-link', 'account-dropdown-button')} onClick={handleLogout}>
                  로그아웃
                </button>
              </div>
            ) : null}
          </div>
        )}
      </nav>
    </header>
  );
}