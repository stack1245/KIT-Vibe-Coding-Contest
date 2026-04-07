import { redirect } from 'next/navigation';
import AnalysisPage from '../../components/AnalysisPage';
import { getSessionUser } from '../../lib/server/auth';
import { getSession } from '../../lib/server/session';

export default async function AnalysisRoutePage() {
  const session = await getSession();
  const user = getSessionUser(session);

  if (!user) {
    redirect('/login#signin');
  }

  return <AnalysisPage />;
}