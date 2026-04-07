import { describe, expect, it } from 'vitest';
import { consumeRateLimit } from '../lib/server/rate-limit';

describe('consumeRateLimit', () => {
  it('blocks requests after the configured limit within the same window', () => {
    const store = new Map();
    const first = consumeRateLimit({ key: 'login:127.0.0.1:test@example.com', limit: 2, windowMs: 1000, nowMs: 1000, store });
    const second = consumeRateLimit({ key: 'login:127.0.0.1:test@example.com', limit: 2, windowMs: 1000, nowMs: 1100, store });
    const third = consumeRateLimit({ key: 'login:127.0.0.1:test@example.com', limit: 2, windowMs: 1000, nowMs: 1200, store });

    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    expect(third.ok).toBe(false);
  });

  it('resets the counter after the window expires', () => {
    const store = new Map();

    consumeRateLimit({ key: 'signup:127.0.0.1:test@example.com', limit: 1, windowMs: 1000, nowMs: 1000, store });
    const resetResult = consumeRateLimit({ key: 'signup:127.0.0.1:test@example.com', limit: 1, windowMs: 1000, nowMs: 2001, store });

    expect(resetResult.ok).toBe(true);
  });
});