'use client';

import { useEffect, useState } from 'react';
import AnalysisPage from './AnalysisPage';

export default function AnalysisPageClientOnly(props) {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return null;
  }

  return <AnalysisPage {...props} />;
}
