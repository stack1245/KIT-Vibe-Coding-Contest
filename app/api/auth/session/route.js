import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';
export const revalidate = 0;
export const fetchCache = 'force-no-store';
export const runtime = 'nodejs';

export async function GET(request) {
  request?.headers;
  const [{ getSessionUser }, { getUserPreferences }, { getSession }] = await Promise.all([
    import('../../../../lib/server/auth'),
    import('../../../../lib/server/database'),
    import('../../../../lib/server/session'),
  ]);
  const session = await getSession(request);
  const user = getSessionUser(session);

  if (!user) {
    return NextResponse.json({ authenticated: false, user: null, preferences: null });
  }

  return NextResponse.json({
    authenticated: true,
    user,
    preferences: getUserPreferences(user.id),
  });
}
