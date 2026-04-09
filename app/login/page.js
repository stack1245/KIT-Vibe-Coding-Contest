import { redirect } from 'next/navigation';
import LoginPageClientOnly from '../../components/LoginPageClientOnly';
import { getUserPreferences } from '../../lib/server/database';
import { getSession } from '../../lib/server/session';
import { getSessionUser } from '../../lib/server/auth';

export default async function LoginRoutePage() {
  const session = await getSession();
  const user = getSessionUser(session);

  if (user) {
    redirect(getUserPreferences(user.id).preferredLanding);
  }

  return <LoginPageClientOnly />;
}
