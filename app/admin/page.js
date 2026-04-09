import { redirect } from 'next/navigation';
import AdminPageClientOnly from '../../components/AdminPageClientOnly';
import { buildSessionUser, getSessionUser } from '../../lib/server/auth';
import { listUsers } from '../../lib/server/database';
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

  const initialUsers = listUsers().map((row) => buildSessionUser(row, row.auth_provider));

  return <AdminPageClientOnly initialUsers={initialUsers} />;
}
