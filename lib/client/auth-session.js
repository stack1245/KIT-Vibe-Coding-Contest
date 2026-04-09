'use client';

import { useEffect, useState } from 'react';
import { fetchJson } from './fetch-json';

const emptySession = { authenticated: false, user: null, preferences: null };

let cachedSession = null;
let inflightSessionPromise = null;

export function clearCachedAuthSession() {
  cachedSession = null;
  inflightSessionPromise = null;
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
      cachedSession = payload;
      return payload;
    })
    .catch(() => {
      cachedSession = emptySession;
      return emptySession;
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

    loadAuthSession().then((payload) => {
      if (!ignore) {
        setSession(payload);
      }
    });

    return () => {
      ignore = true;
    };
  }, []);

  return session;
}
