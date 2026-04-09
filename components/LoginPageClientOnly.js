'use client';

import { useEffect, useState } from 'react';
import LoginPage from './LoginPage';

export default function LoginPageClientOnly() {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return null;
  }

  return <LoginPage />;
}
