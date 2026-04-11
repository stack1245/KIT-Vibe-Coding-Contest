import { afterEach, describe, expect, it } from 'vitest';
import { decryptSecretValue, encryptSecretValue } from '../lib/server/secret-storage';

const ENV_KEYS = ['GITHUB_TOKEN_ENCRYPTION_KEY', 'SECRET_STORAGE_KEY', 'SESSION_SECRET'];
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

describe('secret storage helpers', () => {
  it('encrypts and decrypts token values when a key is configured', () => {
    process.env.GITHUB_TOKEN_ENCRYPTION_KEY = 'unit-test-key';

    const encrypted = encryptSecretValue('ghs_test_token');

    expect(encrypted).not.toBe('ghs_test_token');
    expect(encrypted.startsWith('enc:')).toBe(true);
    expect(decryptSecretValue(encrypted)).toBe('ghs_test_token');
  });

  it('keeps plain values readable when no encryption key is configured', () => {
    delete process.env.GITHUB_TOKEN_ENCRYPTION_KEY;
    delete process.env.SECRET_STORAGE_KEY;
    delete process.env.SESSION_SECRET;

    const stored = encryptSecretValue('ghs_plain_token');

    expect(stored).toBe('ghs_plain_token');
    expect(decryptSecretValue(stored)).toBe('ghs_plain_token');
  });
});
