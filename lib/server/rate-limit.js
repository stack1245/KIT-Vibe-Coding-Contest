import 'server-only';
import { NextResponse } from 'next/server';

const globalRateLimitState = globalThis;

if (!globalRateLimitState.__phaseRateLimitStore) {
  globalRateLimitState.__phaseRateLimitStore = new Map();
}

const sharedStore = globalRateLimitState.__phaseRateLimitStore;

function cleanupExpiredEntries(store, nowMs) {
  for (const [key, entry] of store.entries()) {
    if (entry.resetAt <= nowMs) {
      store.delete(key);
    }
  }
}

export function getClientAddress(request) {
  const forwardedFor = request.headers.get('x-forwarded-for');
  if (forwardedFor) {
    return forwardedFor.split(',')[0].trim();
  }

  return request.headers.get('x-real-ip') || request.headers.get('cf-connecting-ip') || 'unknown';
}

export function consumeRateLimit({
  key,
  limit,
  windowMs,
  nowMs = Date.now(),
  store = sharedStore,
}) {
  cleanupExpiredEntries(store, nowMs);

  const current = store.get(key);

  if (!current || current.resetAt <= nowMs) {
    store.set(key, {
      count: 1,
      resetAt: nowMs + windowMs,
    });

    return {
      ok: true,
      remaining: Math.max(0, limit - 1),
      retryAfterMs: windowMs,
    };
  }

  if (current.count >= limit) {
    return {
      ok: false,
      remaining: 0,
      retryAfterMs: Math.max(1, current.resetAt - nowMs),
    };
  }

  current.count += 1;
  store.set(key, current);

  return {
    ok: true,
    remaining: Math.max(0, limit - current.count),
    retryAfterMs: Math.max(1, current.resetAt - nowMs),
  };
}

export function enforceRateLimit(request, { namespace, identifier = '', limit, windowMs, message }) {
  const clientAddress = getClientAddress(request);
  const rateLimitKey = [namespace, clientAddress, String(identifier || '').trim().toLowerCase()]
    .filter(Boolean)
    .join(':');
  const result = consumeRateLimit({
    key: rateLimitKey,
    limit,
    windowMs,
  });

  if (result.ok) {
    return null;
  }

  return NextResponse.json(
    { ok: false, message },
    {
      status: 429,
      headers: {
        'Retry-After': String(Math.max(1, Math.ceil(result.retryAfterMs / 1000))),
      },
    }
  );
}