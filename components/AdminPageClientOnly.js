'use client';

import { useEffect, useState } from 'react';
import AdminPage from './AdminPage';

export default function AdminPageClientOnly(props) {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return null;
  }

  return <AdminPage {...props} />;
}
