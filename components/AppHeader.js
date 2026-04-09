'use client';

import Link from 'next/link';
import { useMemo, useState } from 'react';
import { clearCachedAuthSession, useAuthSession } from '../lib/client/auth-session';
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
  const session = useAuthSession();
  const [dropdownOpen, setDropdownOpen] = useState(false);

  const userName = useMemo(() => {
    return session.user?.name || session.user?.login || '계정';
  }, [session.user]);

  async function handleLogout() {
    try {
      await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' });
    } finally {
      clearCachedAuthSession();
      window.location.href = '/';
    }
  }

  return (
    <header className={styles.topbar}>
      <div className={styles['topbar-left']}>
        <Link className={styles.brand} href="/" aria-label="메인 페이지로 이동">
          <img src="/assets/images/phase-logo.png" alt="Phase Vuln Coach" className={styles['brand-logo-image']} />
        </Link>

        <nav className={styles['menu-left']} aria-label="주요 메뉴">
          {sections.map((section) => (
            <Link key={section.id} className={styles['menu-link']} href={`/#${section.id}`}>
              {section.label}
            </Link>
          ))}
        </nav>
      </div>

      <nav className={styles['menu-right']} aria-label="인증 메뉴">
        {!session.authenticated || !session.user ? (
          <>
            <Link className={styles['auth-link']} href="/login#signin">로그인</Link>
            <Link className={styles['auth-link']} href="/login#signup">회원가입</Link>
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
                <Link className={styles['account-dropdown-link']} href="/dashboard">프로필 보기</Link>
                <Link className={styles['account-dropdown-link']} href="/analysis">파일 분석</Link>
                {session.user.isAdmin ? <Link className={styles['account-dropdown-link']} href="/admin">관리자 페이지</Link> : null}
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
