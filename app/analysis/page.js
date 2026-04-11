import { redirect } from 'next/navigation';
import AnalysisPageClientOnly from '../../components/AnalysisPageClientOnly';

export default async function AnalysisRoutePage() {
  const [{ getSessionUser }, configModule, databaseModule, { getSession }] = await Promise.all([
    import('../../lib/server/auth'),
    import('../../lib/server/config'),
    import('../../lib/server/database'),
    import('../../lib/server/session'),
  ]);
  const session = await getSession();
  const user = getSessionUser(session);

  if (!user) {
    redirect('/login?returnTo=%2Fanalysis#signin');
  }

  const initialReports = databaseModule.listAnalysisReportsByUser(user.id, 100);
  const preferences = databaseModule.getUserPreferences(user.id);
  const githubConfig = configModule.getGitHubConfig();

  return (
    <AnalysisPageClientOnly
      initialReports={initialReports}
      preferences={preferences}
      github={{
        enabled: configModule.hasGitHubConfig(githubConfig),
        connected: Boolean(user.githubConnected),
        repoAccess: Boolean(user.githubRepoAccess),
        linkUrl: '/auth/github?mode=link&returnTo=%2Fanalysis',
      }}
    />
  );
}
