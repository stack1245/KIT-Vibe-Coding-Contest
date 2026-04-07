import { redirect } from 'next/navigation';
import LoginPage from '../../components/LoginPage';
import { getSession } from '../../lib/server/session';
import { getSessionUser } from '../../lib/server/auth';

export default async function LoginRoutePage() {
  const session = await getSession();
  const user = getSessionUser(session);

  if (user) {
    redirect('/dashboard');
  }

  return <LoginPage />;
}