'use client';

import { useEffect, useState } from 'react';
import { fetchJson } from './fetch-json';

const emptySession = { authenticated: false, user: null, preferences: null };

let cachedSession = null;
let inflightSessionPromise = null;
const sessionListeners = new Set();

function notifySessionListeners(session) {
  sessionListeners.forEach((listener) => {
    try {
      listener(session);
    } catch {
      // Ignore stale listeners.
    }
  });
}

function setCachedAuthSession(session) {
  cachedSession = session;
  notifySessionListeners(session);
  return session;
}

export function clearCachedAuthSession() {
  cachedSession = null;
  inflightSessionPromise = null;
  notifySessionListeners(emptySession);
}

export async function loadAuthSession({ force = false } = {}) {
  if (!force && cachedSession) {
    return cachedSession;
  }

  if (!force && inflightSessionPromise) {
    return inflightSessionPromise;
  }

  inflightSessionPromise = fetchJson('/api/auth/session')
    .then((payload) => {
      return setCachedAuthSession(payload);
    })
    .catch(() => {
      return setCachedAuthSession(emptySession);
    })
    .finally(() => {
      inflightSessionPromise = null;
    });

  return inflightSessionPromise;
}

export function useAuthSession() {
  const [session, setSession] = useState(cachedSession || emptySession);

  useEffect(() => {
    let ignore = false;
    const handleSessionChange = (payload) => {
      if (!ignore) {
        setSession(payload);
      }
    };

    sessionListeners.add(handleSessionChange);

    loadAuthSession().then((payload) => {
      if (!ignore) {
        setSession(payload);
      }
    });

    return () => {
      ignore = true;
      sessionListeners.delete(handleSessionChange);
    };
  }, []);

  return session;
}
