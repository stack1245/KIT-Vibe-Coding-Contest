import { redirect } from 'next/navigation';
import DashboardPage from '../../components/DashboardPage';
import { getSessionUser } from '../../lib/server/auth';
import { getGitHubConfig, hasGitHubConfig } from '../../lib/server/config';
import { getSession } from '../../lib/server/session';

export default async function DashboardRoutePage() {
  const session = await getSession();
  const user = getSessionUser(session);

  if (!user) {
    redirect('/login#signin');
  }

  const config = getGitHubConfig();

  return (
    <DashboardPage
      user={user}
      config={{
        enabled: hasGitHubConfig(config),
        linkUrl: '/auth/github?mode=link',
      }}
    />
  );
}