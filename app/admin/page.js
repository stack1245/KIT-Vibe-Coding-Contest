import { redirect } from 'next/navigation';
import AdminPage from '../../components/AdminPage';
import { getSessionUser } from '../../lib/server/auth';
import { getSession } from '../../lib/server/session';

export default async function AdminRoutePage() {
  const session = await getSession();
  const user = getSessionUser(session);

  if (!user) {
    redirect('/login#signin');
  }

  if (!user.isAdmin) {
    redirect('/dashboard');
  }

  return <AdminPage />;
}