import { afterEach, describe, expect, it } from 'vitest';
import { getAppOrigin, getGitHubConfig, getRequestAppOrigin } from '../lib/server/config';

const ENV_KEYS = ['APP_BASE_URL', 'GITHUB_REDIRECT_URI', 'GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET'];
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

function createRequest({ url, headers = {} }) {
  const normalizedHeaders = Object.fromEntries(
    Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]),
  );

  return {
    url,
    nextUrl: new URL(url),
    headers: {
      get(name) {
        return normalizedHeaders[String(name).toLowerCase()] || null;
      },
    },
  };
}

afterEach(() => {
  restoreEnv();
});

describe('config origin helpers', () => {
  it('prefers a non-loopback runtime origin over a localhost APP_BASE_URL', () => {
    process.env.APP_BASE_URL = 'http://localhost:3000/';

    expect(getAppOrigin('https://phase.example.com')).toBe('https://phase.example.com');
  });

  it('uses forwarded headers instead of an internal localhost request URL', () => {
    delete process.env.APP_BASE_URL;

    const request = createRequest({
      url: 'http://localhost:3000/auth/github/callback?code=test',
      headers: {
        host: 'localhost:3000',
        'x-forwarded-host': 'phase.example.com',
        'x-forwarded-proto': 'https',
      },
    });

    expect(getRequestAppOrigin(request)).toBe('https://phase.example.com');
  });

  it('derives the GitHub callback URL from the public origin when the configured redirect URI is localhost', () => {
    process.env.APP_BASE_URL = 'https://phase.example.com/';
    process.env.GITHUB_REDIRECT_URI = 'http://localhost:3000/auth/github/callback';
    process.env.GITHUB_CLIENT_ID = 'client-id';
    process.env.GITHUB_CLIENT_SECRET = 'client-secret';

    const request = createRequest({
      url: 'http://localhost:3000/auth/github',
      headers: {
        host: 'localhost:3000',
        'x-forwarded-host': 'phase.example.com',
        'x-forwarded-proto': 'https',
      },
    });

    expect(getGitHubConfig(request).redirectUri).toBe('https://phase.example.com/auth/github/callback');
  });

  it('keeps an explicitly configured public GitHub callback URL', () => {
    process.env.APP_BASE_URL = 'https://phase.example.com/';
    process.env.GITHUB_REDIRECT_URI = 'https://oauth.example.com/auth/github/callback';

    expect(getGitHubConfig('https://phase.example.com').redirectUri).toBe('https://oauth.example.com/auth/github/callback');
  });
});
