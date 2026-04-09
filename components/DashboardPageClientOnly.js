'use client';

import { useEffect, useState } from 'react';
import DashboardPage from './DashboardPage';

export default function DashboardPageClientOnly(props) {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return null;
  }

  return <DashboardPage {...props} />;
}
