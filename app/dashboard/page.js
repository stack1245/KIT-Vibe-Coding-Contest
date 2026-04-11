import { redirect } from 'next/navigation';
import DashboardPageClientOnly from '../../components/DashboardPageClientOnly';
import { getSessionUser } from '../../lib/server/auth';
import { getGitHubConfig, hasGitHubConfig } from '../../lib/server/config';
import {
  getUserPreferences,
  listAnalysisReportsByUser,
  listRecentAnalysisJobsByUser,
} from '../../lib/server/database';
import { getSession } from '../../lib/server/session';

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return '-';
  }

  try {
    return new Intl.DateTimeFormat('ko-KR', {
      timeZone: 'Asia/Seoul',
      year: 'numeric',
      month: 'numeric',
      day: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
      second: '2-digit',
      hour12: true,
    }).format(date);
  } catch {
    return '-';
  }
}

export default async function DashboardRoutePage() {
  const session = await getSession();
  const user = getSessionUser(session);

  if (!user) {
    redirect('/login?returnTo=%2Fdashboard#signin');
  }

  const config = getGitHubConfig();
  const reports = listAnalysisReportsByUser(user.id, 12);
  const jobs = listRecentAnalysisJobsByUser(user.id, 10);
  const preferences = getUserPreferences(user.id);
  const dashboardUser = {
    ...user,
    createdAtLabel: formatDate(user.createdAt),
  };

  return (
    <DashboardPageClientOnly
      user={dashboardUser}
      reports={reports}
      jobs={jobs}
      preferences={preferences}
      config={{
        enabled: hasGitHubConfig(config),
        linkUrl: '/auth/github?mode=link&returnTo=%2Fdashboard',
      }}
    />
  );
}
