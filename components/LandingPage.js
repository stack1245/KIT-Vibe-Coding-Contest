'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import styles from './LandingPage.module.css';

const sections = [
  { id: 'hero', label: '홈' },
  { id: 'feature', label: '서비스' },
  { id: 'ai', label: '소개' },
  { id: 'team', label: '개발자' },
];

function cx(...classNames) {
  return classNames.filter(Boolean).map((className) => styles[className]).join(' ');
}

export default function LandingPage() {
  const [session, setSession] = useState({ authenticated: false, user: null });
  const [activeSection, setActiveSection] = useState(0);
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [toast, setToast] = useState('');
  const currentSectionRef = useRef(0);
  const isAnimatingRef = useRef(false);
  const goToSectionRef = useRef(() => {});
  const animationFrameRef = useRef(null);

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

    const onScroll = () => {
      const middle = window.scrollY + window.innerHeight * 0.45;
      let nextIndex = 0;

      sections.forEach((section, index) => {
        const element = document.getElementById(section.id);
        if (!element) {
          return;
        }

        const top = element.offsetTop;
        const bottom = top + element.offsetHeight;
        if (middle >= top && middle < bottom) {
          nextIndex = index;
        }
      });

      currentSectionRef.current = nextIndex;
      setActiveSection(nextIndex);
    };

    const easeInOutCubic = (time) => {
      return time < 0.5
        ? 4 * time * time * time
        : 1 - Math.pow(-2 * time + 2, 3) / 2;
    };

    const smoothScrollTo = (targetY, duration = 760) => {
      const startY = window.pageYOffset;
      const diff = targetY - startY;
      const startTime = performance.now();

      isAnimatingRef.current = true;

      const step = (currentTime) => {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const eased = easeInOutCubic(progress);

        window.scrollTo(0, startY + diff * eased);

        if (progress < 1) {
          animationFrameRef.current = window.requestAnimationFrame(step);
          return;
        }

        isAnimatingRef.current = false;
        animationFrameRef.current = null;
        onScroll();
      };

      animationFrameRef.current = window.requestAnimationFrame(step);
    };

    const goToSection = (index) => {
      const safeIndex = Math.max(0, Math.min(index, sections.length - 1));
      const element = document.getElementById(sections[safeIndex].id);

      if (!element) {
        return;
      }

      currentSectionRef.current = safeIndex;
      setActiveSection(safeIndex);
      smoothScrollTo(element.offsetTop);
    };

    goToSectionRef.current = goToSection;

    const handleWheelNavigation = (event) => {
      event.preventDefault();

      if (isAnimatingRef.current) {
        return;
      }

      if (event.deltaY > 35 && currentSectionRef.current < sections.length - 1) {
        goToSection(currentSectionRef.current + 1);
      } else if (event.deltaY < -35 && currentSectionRef.current > 0) {
        goToSection(currentSectionRef.current - 1);
      }
    };

    const handleKeyNavigation = (event) => {
      if (isAnimatingRef.current) {
        return;
      }

      if (event.key === 'ArrowDown' || event.key === 'PageDown' || event.key === ' ') {
        event.preventDefault();
        if (currentSectionRef.current < sections.length - 1) {
          goToSection(currentSectionRef.current + 1);
        }
      }

      if (event.key === 'ArrowUp' || event.key === 'PageUp') {
        event.preventDefault();
        if (currentSectionRef.current > 0) {
          goToSection(currentSectionRef.current - 1);
        }
      }

      if (event.key === 'Home') {
        event.preventDefault();
        goToSection(0);
      }
    };

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) {
            return;
          }

          entry.target.querySelectorAll(`.${styles.reveal}, .${styles['feature-animate']}`).forEach((element) => {
            element.classList.add(styles.visible);
          });
        });
      },
      { threshold: 0.22 }
    );

    sections.forEach((section) => {
      const element = document.getElementById(section.id);
      if (element) {
        observer.observe(element);
      }
    });

    document.querySelectorAll(`#hero .${styles.reveal}`).forEach((element) => {
      element.classList.add(styles.visible);
    });

    const handleWindowScroll = () => {
      if (!isAnimatingRef.current) {
        onScroll();
      }
    };

    window.addEventListener('scroll', handleWindowScroll, { passive: true });
    window.addEventListener('wheel', handleWheelNavigation, { passive: false });
    window.addEventListener('keydown', handleKeyNavigation);
    onScroll();

    return () => {
      ignore = true;
      goToSectionRef.current = () => {};
      if (animationFrameRef.current) {
        window.cancelAnimationFrame(animationFrameRef.current);
      }
      observer.disconnect();
      window.removeEventListener('scroll', handleWindowScroll);
      window.removeEventListener('wheel', handleWheelNavigation);
      window.removeEventListener('keydown', handleKeyNavigation);
    };
  }, []);

  useEffect(() => {
    if (!toast) {
      return undefined;
    }

    const timer = window.setTimeout(() => setToast(''), 3200);
    return () => window.clearTimeout(timer);
  }, [toast]);

  const userName = useMemo(() => {
    return session.user?.name || session.user?.login || '계정';
  }, [session.user]);

  async function handleLogout() {
    try {
      const response = await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload.message || '로그아웃에 실패했습니다.');
      }

      window.location.href = '/';
    } catch (error) {
      setToast(error.message);
    }
  }

  function scrollToSection(id) {
    const targetIndex = sections.findIndex((section) => section.id === id);
    if (targetIndex === -1 || isAnimatingRef.current) {
      return;
    }

    goToSectionRef.current(targetIndex);
  }

  return (
    <div className={styles['page-wrapper']}>
      <header className={styles.topbar}>
        <div className={styles['topbar-left']}>
          <button className={styles.brand} type="button" aria-label="맨 위로 이동" onClick={() => scrollToSection('hero')}>
            <img src="/assets/images/phase-logo.png" alt="Phase Vuln Coach" className={styles['brand-logo-image']} />
          </button>

          <nav className={styles['menu-left']} aria-label="주요 메뉴">
            {sections.map((section) => (
              <button key={section.id} type="button" className={cx('menu-link', 'menu-button')} onClick={() => scrollToSection(section.id)}>
                {section.label}
              </button>
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

      <aside className={styles['section-indicator']} aria-label="섹션 이동">
        {sections.map((section, index) => (
          <button
            key={section.id}
            className={cx('section-dot', index === activeSection && 'active')}
            type="button"
            aria-label={section.label}
            onClick={() => scrollToSection(section.id)}
          />
        ))}
      </aside>

      <main className={styles.sections}>
        <section className={cx('section', 'hero')} id="hero">
          <div className={styles['hero-video-wrap']}>
            <video className={styles['hero-video']} autoPlay muted loop playsInline>
              <source src="/assets/video/hero-background.mp4" type="video/mp4" />
            </video>
            <div className={styles['hero-dark-overlay']} />
            <div className={styles['hero-fade']} />
          </div>

          <div className={styles['hero-inner']}>
            <div className={styles['hero-content']}>
              <img src="/assets/images/phase-logo.png" alt="Phase logo" className={cx('hero-logo', 'reveal', 'from-bottom')} />
              <div className={cx('hero-subtitle', 'reveal', 'from-bottom')} style={{ transitionDelay: '0.1s' }}>
                Phase Vuln Coach
              </div>
              <p className={cx('hero-text', 'reveal', 'from-bottom')} style={{ transitionDelay: '0.22s' }}>
                현재 코드에 숨어있는 보안 취약점을 빠르게 탐지하고, 각 취약점이 왜 문제인지 공격 시나리오와 함께 알기 쉽게 설명해줍니다.
                거기서 끝이 아니라 안전한 코드 패치 방법까지 제안해주는, 개발자를 위한 취약점 코칭 및 탐지 플랫폼입니다!
              </p>
            </div>
          </div>
        </section>

        <section className={styles.section} id="feature">
          <div className={styles['feature-top']}>
            <p className={cx('eyebrow', 'reveal', 'from-left')}>What We do</p>
            <div className={styles['feature-title-row']}>
              <h2 className={cx('section-title', 'reveal', 'from-left')}>Phase Vuln Coach는 여러 분야의 취약점을 점검합니다</h2>
              <div className={cx('feature-line', 'reveal', 'from-right')} />
            </div>
          </div>

          <div className={styles['feature-cards']}>
            <article className={cx('feature-card', 'feature-animate', 'feature-stagger-1')}>
              <div className={styles['feature-icon']}>
                <img src="/assets/images/feature-system.png" alt="System Hacking" />
              </div>
              <h3>System Hacking</h3>
              <p>시스템 해킹 취약점 분석<br />메모리 손상, 실행 흐름 조작, 권한 상승 등</p>
            </article>

            <article className={cx('feature-card', 'feature-animate', 'feature-stagger-2')}>
              <div className={styles['feature-icon']}>
                <img src="/assets/images/feature-web.png" alt="Web Hacking" />
              </div>
              <h3>Web Hacking</h3>
              <p>웹 서비스 취약점 진단<br />입력 검증, 인증/인가, 세션, 서버 로직 분석</p>
            </article>

            <article className={cx('feature-card', 'feature-animate', 'feature-stagger-3')}>
              <div className={styles['feature-icon']}>
                <img src="/assets/images/feature-mobile.png" alt="Mobile Hacking" />
              </div>
              <h3>Mobile Hacking</h3>
              <p>모바일 앱 보안 점검<br />저장소, 통신, 코드 보호, 앱 동작 흐름 분석</p>
            </article>
          </div>
        </section>

        <section className={cx('section', 'ai-section')} id="ai">
          <div className={styles['ai-head']}>
            <h2 className={cx('ai-title', 'reveal', 'from-bottom')}>AI를 통해 더 빠르고 더 똑똑하게<br />사이버 보안 위협을 차단하세요.</h2>
            <p className={cx('ai-subtext', 'reveal', 'from-bottom')} style={{ transitionDelay: '0.12s' }}>
              보안 점검을 받았어도 그 위험을 놓치거나 심각한 타이밍에 문제를 발견하면 위험합니다.
              개발자가 보안 대응을 자연스럽게 익히고, 다음 코드에서는 같은 실수를 줄일 수 있도록 분석과 설명, 대응 방향까지 함께 제공합니다.
            </p>
          </div>

          <div className={styles['ai-grid']}>
            <div className={cx('ai-box', 'reveal', 'from-left')} />
            <div className={cx('ai-text-block', 'reveal', 'from-right')}>
              <strong>우리 페이즈 취약점 코치 애플리케이션은</strong><br />빠르고 실용적인 취약점 진단 결과를 제공하고,
              그에 맞는 개선 포인트와 학습 흐름까지 함께 제시합니다.
            </div>

            <div className={cx('ai-text-block', 'reveal', 'from-left')}>
              단순히 취약점을 찾는 데서 끝나는 것이 아니라, <strong>왜 위험한지</strong>, <strong>어떻게 고쳐야 하는지</strong>,
              <strong>앞으로 비슷한 실수를 어떻게 피할지</strong>까지 개발자 눈높이에 맞춰 정리해 줍니다.
            </div>
            <div className={cx('ai-box', 'reveal', 'from-right')} />
          </div>
        </section>

        <section className={cx('section', 'team-section')} id="team">
          <div className={styles['team-head']}>
            <p className={cx('eyebrow', 'reveal', 'from-bottom')}>Developer Team</p>
            <h2 className={cx('section-title', 'reveal', 'from-bottom')} style={{ marginBottom: 0 }}>개발자 소개</h2>
          </div>

          <div className={styles['team-list']}>
            <article className={cx('member', 'reveal', 'from-right', 'stagger-1')}>
              <img src="/assets/images/member-servelt.png" alt="Servelt" className={styles['member-photo']} />
              <div className={styles['member-info']}>
                <h3>Servelt</h3>
                <p>선린인터넷고등학교에서 선린 Phase 동아리 부장을 맡고있는 여현빈이라고 합니다! 주 분야는 System Hacking이며 RubiyaLab CTF팀에서 활동하고 있습니다!</p>
              </div>
            </article>

            <article className={cx('member', 'reveal', 'from-right', 'stagger-2')}>
              <img src="/assets/images/member-ll-rich.png" alt="lL_rich" className={styles['member-photo']} />
              <div className={styles['member-info']}>
                <h3>lL_rich</h3>
                <p>한세사이버보안고등학교에 다니고 있고, 네트워크를 뜯어보는 게 취미인 고등학생 lL_rich입니다.</p>
              </div>
            </article>

            <article className={cx('member', 'reveal', 'from-right', 'stagger-3')}>
              <img src="/assets/images/member-stack.png" alt="Stack" className={styles['member-photo']} />
              <div className={styles['member-info']}>
                <h3>Stack</h3>
                <p>선린인터넷고등학교에서 선린 Phase 동아리 부원인 탁도형이라고 합니다! 관심있는 분야는 Web/App Hacking입니다.</p>
              </div>
            </article>

            <article className={cx('member', 'reveal', 'from-right', 'stagger-4')}>
              <img src="/assets/images/member-dawneast.png" alt="Dawneast" className={styles['member-photo']} />
              <div className={styles['member-info']}>
                <h3>Dawneast</h3>
                <p>선린인터넷고등학교에서 선린 Phase 동아리 부원인 신동효라고 합니다! 관심있는 분야는 Web, System Hacking입니다.</p>
              </div>
            </article>
          </div>
        </section>
      </main>

      <div className={cx('site-toast', toast && 'is-visible', toast && 'is-error')} hidden={!toast} aria-live="polite">
        {toast}
      </div>
    </div>
  );
}