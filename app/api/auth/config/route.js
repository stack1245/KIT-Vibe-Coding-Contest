import path from 'node:path';
import { NextResponse } from 'next/server';
import { databaseFilePath } from '../../../../lib/server/database';
import { getAdminEmails, getGitHubConfig, getMailConfig, hasGitHubConfig, hasMailConfig } from '../../../../lib/server/config';

export function GET(request) {
  const config = getGitHubConfig(request.nextUrl.origin);

  return NextResponse.json({
    enabled: hasGitHubConfig(config),
    provider: 'github',
    loginUrl: '/auth/github',
    linkUrl: '/auth/github?mode=link',
    database: path.basename(databaseFilePath),
    adminConfigured: getAdminEmails().length > 0,
    emailVerificationRequired: true,
    emailDeliveryConfigured: hasMailConfig(getMailConfig()),
  });
}