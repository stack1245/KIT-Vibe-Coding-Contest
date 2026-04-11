import { afterEach, describe, expect, it } from 'vitest';
import { SESSION_COOKIE_NAME } from '../lib/server/config';
import { commitSession, getSession } from '../lib/server/session';

const ENV_KEYS = ['NODE_ENV', 'SESSION_SECRET'];
const originalEnv = Object.fromEntries(ENV_KEYS.map((key) => [key, process.env[key]]));

function restoreEnv() {
  ENV_KEYS.forEach((key) => {
    if (typeof originalEnv[key] === 'undefined') {
      delete process.env[key];
      return;
    }

    process.env[key] = originalEnv[key];
  });
}

afterEach(() => {
  restoreEnv();
});

function createResponseRecorder() {
  let cookieValue = '';

  return {
    response: {
      cookies: {
        set({ value }) {
          cookieValue = String(value || '');
        },
      },
    },
    getCookieValue() {
      return cookieValue;
    },
  };
}

describe('session helpers', () => {
  it('uses an ephemeral secret outside production when SESSION_SECRET is missing', async () => {
    delete process.env.SESSION_SECRET;
    process.env.NODE_ENV = 'test';

    const recorder = createResponseRecorder();
    commitSession(recorder.response, { accountId: 42, authMethod: 'local' });

    const session = await getSession({
      headers: {
        get(name) {
          return String(name).toLowerCase() === 'cookie'
            ? `${SESSION_COOKIE_NAME}=${recorder.getCookieValue()}`
            : null;
        },
      },
    });

    expect(session.accountId).toBe(42);
    expect(session.authMethod).toBe('local');
  });

  it('fails fast in production when SESSION_SECRET is not configured', () => {
    delete process.env.SESSION_SECRET;
    process.env.NODE_ENV = 'production';

    const recorder = createResponseRecorder();
    expect(() => commitSession(recorder.response, { accountId: 7, authMethod: 'local' }))
      .toThrow('SESSION_SECRET must be configured in production');
  });
});
