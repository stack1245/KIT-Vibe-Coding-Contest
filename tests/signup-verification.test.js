import { describe, expect, it } from 'vitest';
import {
  clearSignupVerification,
  createSignupVerifiedSession,
  hasValidSignupVerification,
} from '../lib/server/signup-verification';

describe('signup verification session helpers', () => {
  it('normalizes the email and validates a matching verified session', () => {
    const session = createSignupVerifiedSession({ accountId: null }, 'User@Example.com');
    const result = hasValidSignupVerification(session, 'user@example.com');

    expect(result).toEqual({ ok: true });
  });

  it('clears the signup verification payload', () => {
    const session = createSignupVerifiedSession({ accountId: null }, 'user@example.com');
    const clearedSession = clearSignupVerification(session);

    expect(clearedSession.signupVerification).toBeNull();
    expect(hasValidSignupVerification(clearedSession, 'user@example.com')).toEqual({
      ok: false,
      reason: 'missing',
    });
  });
});