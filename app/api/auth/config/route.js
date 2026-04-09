import path from 'node:path';
import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';
export const revalidate = 0;
export const fetchCache = 'force-no-store';
export const runtime = 'nodejs';

export async function GET(request) {
  const [{ databaseFilePath }, configModule] = await Promise.all([
    import('../../../../lib/server/database'),
    import('../../../../lib/server/config'),
  ]);
  const config = configModule.getGitHubConfig(request);

  return NextResponse.json({
    enabled: configModule.hasGitHubConfig(config),
    provider: 'github',
    loginUrl: '/auth/github',
    linkUrl: '/auth/github?mode=link',
    database: path.basename(databaseFilePath),
    adminConfigured: configModule.getAdminEmails().length > 0,
    emailVerificationRequired: true,
    emailDeliveryConfigured: configModule.hasMailConfig(configModule.getMailConfig()),
  });
}
