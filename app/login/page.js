import { redirect } from 'next/navigation';
import LoginPageClientOnly from '../../components/LoginPageClientOnly';
import { getUserPreferences } from '../../lib/server/database';
import { getSession } from '../../lib/server/session';
import { getSessionUser } from '../../lib/server/auth';

function sanitizeReturnTo(value) {
  const nextValue = String(value || '').trim();

  if (!nextValue.startsWith('/') || nextValue.startsWith('//')) {
    return '';
  }

  if (nextValue.startsWith('/auth/') || nextValue.startsWith('/api/')) {
    return '';
  }

  return nextValue;
}

export default async function LoginRoutePage({ searchParams }) {
  const resolvedSearchParams = await searchParams;
  const session = await getSession();
  const user = getSessionUser(session);
  const requestedReturnTo = sanitizeReturnTo(resolvedSearchParams?.returnTo);

  if (user) {
    redirect(requestedReturnTo || getUserPreferences(user.id).preferredLanding);
  }

  return <LoginPageClientOnly />;
}
