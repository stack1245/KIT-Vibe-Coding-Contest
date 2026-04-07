import { NextResponse } from 'next/server';
import { getSessionUser } from '../../../../lib/server/auth';
import { getSession } from '../../../../lib/server/session';

export async function GET() {
  const session = await getSession();
  const user = getSessionUser(session);

  if (!user) {
    return NextResponse.json({ authenticated: false, user: null });
  }

  return NextResponse.json({ authenticated: true, user });
}