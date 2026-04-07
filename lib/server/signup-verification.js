import 'server-only';
import { SIGNUP_VERIFICATION_SESSION_TTL_MS } from './config';

export function clearSignupVerification(session) {
  return {
    ...session,
    signupVerification: null,
  };
}

export function createSignupVerifiedSession(session, email) {
  return {
    ...session,
    signupVerification: {
      email: String(email || '').trim().toLowerCase(),
      verifiedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + SIGNUP_VERIFICATION_SESSION_TTL_MS).toISOString(),
    },
  };
}

export function hasValidSignupVerification(session, email) {
  const signupVerification = session?.signupVerification;

  if (!signupVerification) {
    return { ok: false, reason: 'missing' };
  }

  if (signupVerification.email !== String(email || '').trim().toLowerCase()) {
    return { ok: false, reason: 'missing' };
  }

  if (!signupVerification.expiresAt || new Date(signupVerification.expiresAt).getTime() < Date.now()) {
    return { ok: false, reason: 'session_expired' };
  }

  return { ok: true };
}