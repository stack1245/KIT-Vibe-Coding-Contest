'use client';

import { useEffect, useMemo, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { loadAuthSession, useAuthSession } from '../lib/client/auth-session';
import AppHeader from './AppHeader';
import PageVideoBackdrop from './PageVideoBackdrop';
import styles from './LoginPage.module.css';

const copy = {
  signin: { githubLabel: 'GitHub로 로그인' },
  signup: { githubLabel: 'GitHub로 회원가입' },
};

const initialResetForm = {
  email: '',
  code: '',
  password: '',
  confirmPassword: '',
};

function cx(...classNames) {
  return classNames.filter(Boolean).map((className) => styles[className]).join(' ');
}

export default function LoginPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const session = useAuthSession();
  const [tab, setTab] = useState('signin');
  const [feedback, setFeedback] = useState({ message: '', type: 'error' });
  const [githubEnabled, setGitHubEnabled] = useState(true);
  const [githubStatus, setGitHubStatus] = useState('');
  const [verifiedEmail, setVerifiedEmail] = useState('');
  const [verificationModalOpen, setVerificationModalOpen] = useState(false);
  const [resetModalOpen, setResetModalOpen] = useState(false);
  const [resetCodeSent, setResetCodeSent] = useState(false);
  const [signinForm, setSigninForm] = useState({ email: '', password: '' });
  const [signupForm, setSignupForm] = useState({ email: '', password: '', confirmPassword: '', code: '' });
  const [resetForm, setResetForm] = useState(initialResetForm);
  const [loading, setLoading] = useState({
    signin: false,
    signup: false,
    code: false,
    confirm: false,
    resetRequest: false,
    resetSubmit: false,
  });

  const githubLabel = useMemo(() => copy[tab].githubLabel, [tab]);
  const normalizedSignupEmail = signupForm.email.trim().toLowerCase();
  const signupReady = Boolean(verifiedEmail) && verifiedEmail === normalizedSignupEmail;
  const preferredLanding = session.preferences?.preferredLanding || '/dashboard';

  useEffect(() => {
    const hash = window.location.hash === '#signup' ? 'signup' : 'signin';
    setTab(hash);

    fetch('/api/auth/config', { credentials: 'same-origin' })
      .then((response) => response.json())
      .then((config) => {
        if (session.authenticated && session.user) {
          router.replace(preferredLanding);
          return;
        }

        if (!config.enabled) {
          setGitHubEnabled(false);
          setGitHubStatus('GitHub 설정이 비어 있습니다.');
        } else {
          setGitHubEnabled(true);
          setGitHubStatus('이메일 인증 후 회원가입할 수 있습니다.');
        }

        const auth = searchParams.get('auth');
        const error = searchParams.get('error');
        if (auth === 'success') setFeedback({ message: 'GitHub 로그인에 성공했습니다.', type: 'success' });
        if (auth === 'link_success') setFeedback({ message: '현재 계정에 GitHub 연동이 완료되었습니다.', type: 'success' });
        if (error) {
          const messages = {
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
          setFeedback({ message: messages[error] || '인증 처리 중 오류가 발생했습니다.', type: 'error' });
        }
      })
      .catch(() => {
        setGitHubStatus('인증 상태를 불러오지 못했습니다.');
      });
  }, [preferredLanding, router, searchParams, session.authenticated, session.user]);

  useEffect(() => {
    if (!feedback.message) {
      return undefined;
    }

    const timer = window.setTimeout(() => setFeedback({ message: '', type: 'error' }), 4200);
    return () => window.clearTimeout(timer);
  }, [feedback]);

  function updateTab(nextTab) {
    setTab(nextTab);
    window.location.hash = nextTab;
  }

  function setSignupField(key, value) {
    setSignupForm((current) => ({ ...current, [key]: value }));
    if (key === 'email' && verifiedEmail && verifiedEmail !== value.trim().toLowerCase()) {
      setVerifiedEmail('');
    }
  }

  function setResetField(key, value) {
    setResetForm((current) => ({ ...current, [key]: value }));
  }

  function openResetModal() {
    setResetCodeSent(false);
    setResetForm({ ...initialResetForm, email: signinForm.email.trim() });
    setResetModalOpen(true);
  }

  function closeResetModal() {
    setResetModalOpen(false);
    setResetCodeSent(false);
    setResetForm(initialResetForm);
  }

  function resetRequestedEmail() {
    setResetCodeSent(false);
    setResetForm((current) => ({
      ...current,
      code: '',
      password: '',
      confirmPassword: '',
    }));
  }

  async function fetchJson(url, options) {
    const response = await fetch(url, { credentials: 'same-origin', ...options });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.message || '요청을 처리하지 못했습니다.');
    }

    return payload;
  }

  async function requestVerificationCode() {
    const email = signupForm.email.trim();

    if (!email) {
      setFeedback({ message: '인증 코드를 받을 이메일을 입력해주세요.', type: 'error' });
      return;
    }

    setLoading((current) => ({ ...current, code: true }));
    setVerifiedEmail('');

    try {
      await fetchJson('/api/auth/email-verification/request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });

      setSignupForm((current) => ({ ...current, code: '' }));
      setVerificationModalOpen(true);
      setFeedback({ message: '인증 코드를 이메일로 전송했습니다.', type: 'success' });
    } catch (error) {
      setFeedback({ message: error.message, type: 'error' });
    } finally {
      setLoading((current) => ({ ...current, code: false }));
    }
  }

  async function confirmVerificationCode() {
    setLoading((current) => ({ ...current, confirm: true }));

    try {
      await fetchJson('/api/auth/email-verification/confirm', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: signupForm.email.trim(), code: signupForm.code.trim() }),
      });

      setVerifiedEmail(signupForm.email.trim().toLowerCase());
      setVerificationModalOpen(false);
      setFeedback({ message: '이메일 인증이 완료되었습니다. 비밀번호를 설정해주세요.', type: 'success' });
    } catch (error) {
      setVerificationModalOpen(false);
      setVerifiedEmail('');
      setFeedback({ message: `${error.message} 다시 인증을 요청해주세요.`, type: 'error' });
    } finally {
      setLoading((current) => ({ ...current, confirm: false }));
    }
  }

  async function requestPasswordResetCode() {
    const email = resetForm.email.trim();

    if (!email) {
      setFeedback({ message: '비밀번호를 재설정할 이메일을 입력해주세요.', type: 'error' });
      return;
    }

    setLoading((current) => ({ ...current, resetRequest: true }));
    setResetCodeSent(false);

    try {
      await fetchJson('/api/auth/password-reset/request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });

      setResetCodeSent(true);
      setResetForm((current) => ({
        ...current,
        email,
        code: '',
        password: '',
        confirmPassword: '',
      }));
      setFeedback({ message: '인증 코드를 이메일로 전송했습니다.', type: 'success' });
    } catch (error) {
      setFeedback({ message: error.message, type: 'error' });
    } finally {
      setLoading((current) => ({ ...current, resetRequest: false }));
    }
  }

  async function handleSignin(event) {
    event.preventDefault();
    setLoading((current) => ({ ...current, signin: true }));

    try {
      await fetchJson('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(signinForm),
      });

      const nextSession = await loadAuthSession({ force: true });
      router.push(nextSession.preferences?.preferredLanding || '/dashboard');
    } catch (error) {
      setFeedback({ message: error.message, type: 'error' });
    } finally {
      setLoading((current) => ({ ...current, signin: false }));
    }
  }

  async function handleSignup(event) {
    event.preventDefault();
    setLoading((current) => ({ ...current, signup: true }));

    try {
      await fetchJson('/api/auth/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: signupForm.email,
          password: signupForm.password,
          confirmPassword: signupForm.confirmPassword,
        }),
      });

      const nextSession = await loadAuthSession({ force: true });
      router.push(nextSession.preferences?.preferredLanding || '/dashboard');
    } catch (error) {
      setFeedback({ message: error.message, type: 'error' });
    } finally {
      setLoading((current) => ({ ...current, signup: false }));
    }
  }

  async function handlePasswordReset(event) {
    event.preventDefault();

    const email = resetForm.email.trim();

    setLoading((current) => ({ ...current, resetSubmit: true }));

    try {
      const payload = await fetchJson('/api/auth/password-reset/confirm', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email,
          code: resetForm.code.trim(),
          password: resetForm.password,
          confirmPassword: resetForm.confirmPassword,
        }),
      });

      setSigninForm((current) => ({ ...current, email, password: '' }));
      closeResetModal();
      setFeedback({ message: payload.message || '비밀번호를 재설정했습니다.', type: 'success' });
    } catch (error) {
      setFeedback({ message: error.message, type: 'error' });
    } finally {
      setLoading((current) => ({ ...current, resetSubmit: false }));
    }
  }

  return (
    <>
      <AppHeader />

      <div className={cx('feedback-toast', feedback.message && 'is-visible', feedback.message && feedback.type)} aria-live="polite">
        {feedback.message}
      </div>

      <div className={styles['auth-shell']}>
        <PageVideoBackdrop className={styles['auth-video-backdrop']} />
        <div className={styles['grid-overlay']} aria-hidden="true" />

        <main className={styles['auth-card']}>
          <header className={styles['auth-head']}>
            <div className={styles['tab-list']} role="tablist" aria-label="인증 화면 전환">
              <button className={cx('auth-tab', tab === 'signin' && 'is-active')} type="button" onClick={() => updateTab('signin')}>로그인</button>
              <button className={cx('auth-tab', tab === 'signup' && 'is-active')} type="button" onClick={() => updateTab('signup')}>회원가입</button>
            </div>
          </header>

          <section className={styles['oauth-area']} aria-label="간편 로그인">
            <button id="github-auth-button" className={styles['github-button']} type="button" disabled={!githubEnabled} onClick={() => (window.location.href = `/auth/github?mode=${tab}`)}>
              <svg aria-hidden="true" viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M12 .5C5.65.5.5 5.65.5 12c0 5.08 3.29 9.39 7.86 10.91.58.11.79-.25.79-.56 0-.27-.01-1.18-.02-2.14-3.2.7-3.88-1.36-3.88-1.36-.52-1.33-1.27-1.68-1.27-1.68-1.04-.71.08-.7.08-.7 1.15.08 1.75 1.18 1.75 1.18 1.02 1.75 2.67 1.24 3.32.95.1-.74.4-1.24.72-1.52-2.56-.29-5.26-1.28-5.26-5.69 0-1.26.45-2.29 1.18-3.1-.12-.29-.51-1.47.11-3.06 0 0 .96-.31 3.15 1.18a10.86 10.86 0 0 1 5.74 0c2.19-1.49 3.15-1.18 3.15-1.18.62 1.59.23 2.77.11 3.06.73.81 1.18 1.84 1.18 3.1 0 4.42-2.7 5.39-5.28 5.68.41.35.78 1.04.78 2.11 0 1.52-.01 2.75-.01 3.12 0 .31.21.68.8.56A11.5 11.5 0 0 0 23.5 12C23.5 5.65 18.35.5 12 .5Z" /></svg>
              <span>{githubLabel}</span>
            </button>

            <p className={styles['auth-status']}>{githubStatus}</p>
          </section>

          <form className={cx('auth-panel', tab === 'signin' && 'is-active')} onSubmit={handleSignin}>
            <div className={styles.fields}>
              <div className={styles.field}>
                <label htmlFor="signin-email">이메일</label>
                <input id="signin-email" type="email" autoComplete="email" placeholder="you@example.com" value={signinForm.email} onChange={(event) => setSigninForm((current) => ({ ...current, email: event.target.value }))} required />
              </div>

              <div className={styles.field}>
                <label htmlFor="signin-password">비밀번호</label>
                <input id="signin-password" type="password" autoComplete="current-password" placeholder="8자 이상 비밀번호" value={signinForm.password} onChange={(event) => setSigninForm((current) => ({ ...current, password: event.target.value }))} required />
              </div>

              <button className={styles['forgot-link']} type="button" onClick={openResetModal}>
                비밀번호를 잊으셨나요?
              </button>
            </div>

            <div className={styles['form-footer']}>
              <button className={styles['submit-button']} type="submit" disabled={loading.signin}>{loading.signin ? '로그인 중...' : '로그인'}</button>
              <p>아직 계정이 없나요? <button type="button" className={styles['text-link']} onClick={() => updateTab('signup')}>회원가입으로 이동</button></p>
            </div>
          </form>

          <form className={cx('auth-panel', tab === 'signup' && 'is-active')} onSubmit={handleSignup}>
            <div className={styles.fields}>
              <div className={styles.field}>
                <label htmlFor="signup-email">이메일</label>
                <div className={styles['inline-field']}>
                  <input id="signup-email" type="email" autoComplete="email" placeholder="you@example.com" value={signupForm.email} readOnly={signupReady} onChange={(event) => setSignupField('email', event.target.value)} required />
                  <button className={styles['inline-action-button']} type="button" onClick={requestVerificationCode} disabled={loading.code || signupReady}>{signupReady ? '인증 완료' : loading.code ? '요청 중...' : '인증 요청'}</button>
                </div>
              </div>

              <div className={styles.field}>
                <label htmlFor="signup-password">비밀번호</label>
                <input id="signup-password" type="password" autoComplete="new-password" placeholder="영문과 숫자를 포함한 8자 이상" value={signupForm.password} disabled={!signupReady} onChange={(event) => setSignupField('password', event.target.value)} required />
              </div>

              <div className={styles.field}>
                <label htmlFor="signup-confirm-password">비밀번호 확인</label>
                <input id="signup-confirm-password" type="password" autoComplete="new-password" placeholder="비밀번호를 한 번 더 입력하세요" value={signupForm.confirmPassword} disabled={!signupReady} onChange={(event) => setSignupField('confirmPassword', event.target.value)} required />
              </div>
            </div>

            <div className={styles['form-footer']}>
              <button className={styles['submit-button']} type="submit" disabled={!signupReady || loading.signup}>{loading.signup ? '가입 중...' : '회원가입'}</button>
              <p>이미 계정이 있나요? <button type="button" className={styles['text-link']} onClick={() => updateTab('signin')}>로그인으로 이동</button></p>
            </div>
          </form>
        </main>
      </div>

      {verificationModalOpen ? (
        <div className={styles['verification-modal']}>
          <div className={styles['verification-backdrop']} onClick={() => setVerificationModalOpen(false)} />
          <div className={styles['verification-dialog']} role="dialog" aria-modal="true" aria-labelledby="verification-title">
            <h2 id="verification-title">이메일 인증</h2>
            <input type="text" inputMode="numeric" autoComplete="one-time-code" maxLength={6} placeholder="6자리 인증 코드" value={signupForm.code} onChange={(event) => setSignupField('code', event.target.value)} />
            <button className={styles['submit-button']} type="button" onClick={confirmVerificationCode} disabled={loading.confirm}>{loading.confirm ? '확인 중...' : '확인'}</button>
          </div>
        </div>
      ) : null}

      {resetModalOpen ? (
        <div className={styles['verification-modal']}>
          <div className={styles['verification-backdrop']} onClick={closeResetModal} />
          <form className={styles['verification-dialog']} role="dialog" aria-modal="true" aria-labelledby="password-reset-title" onSubmit={handlePasswordReset}>
            <h2 id="password-reset-title">비밀번호 재설정</h2>
            <p className={styles['modal-description']}>이메일을 입력하면 계정이 있을 때 인증 코드를 보내드립니다.</p>

            <div className={styles.field}>
              <label htmlFor="reset-email">이메일</label>
              <div className={styles['inline-field']}>
                <input id="reset-email" type="email" autoComplete="email" placeholder="you@example.com" value={resetForm.email} readOnly={resetCodeSent} onChange={(event) => setResetField('email', event.target.value)} required />
                <button className={styles['inline-action-button']} type="button" onClick={resetCodeSent ? resetRequestedEmail : requestPasswordResetCode} disabled={loading.resetRequest}>
                  {resetCodeSent ? '이메일 변경' : loading.resetRequest ? '전송 중...' : '인증코드 보내기'}
                </button>
              </div>
            </div>

            {resetCodeSent ? (
              <>
                <p className={styles['modal-note']}>{resetForm.email} 로 받은 인증 코드와 새 비밀번호를 입력하세요.</p>

                <div className={styles.field}>
                  <label htmlFor="reset-code">인증 코드</label>
                  <input id="reset-code" type="text" inputMode="numeric" autoComplete="one-time-code" maxLength={6} placeholder="6자리 인증 코드" value={resetForm.code} onChange={(event) => setResetField('code', event.target.value)} required />
                </div>

                <div className={styles.field}>
                  <label htmlFor="reset-password">새 비밀번호</label>
                  <input id="reset-password" type="password" autoComplete="new-password" placeholder="영문과 숫자를 포함한 8자 이상" value={resetForm.password} onChange={(event) => setResetField('password', event.target.value)} required />
                </div>

                <div className={styles.field}>
                  <label htmlFor="reset-confirm-password">새 비밀번호 확인</label>
                  <input id="reset-confirm-password" type="password" autoComplete="new-password" placeholder="비밀번호를 한 번 더 입력하세요" value={resetForm.confirmPassword} onChange={(event) => setResetField('confirmPassword', event.target.value)} required />
                </div>
              </>
            ) : null}

            <div className={styles['modal-actions']}>
              <button className={styles['secondary-button']} type="button" onClick={closeResetModal}>닫기</button>
              {resetCodeSent ? (
                <button className={styles['submit-button']} type="submit" disabled={loading.resetSubmit}>
                  {loading.resetSubmit ? '변경 중...' : '비밀번호 변경'}
                </button>
              ) : null}
            </div>
          </form>
        </div>
      ) : null}
    </>
  );
}
