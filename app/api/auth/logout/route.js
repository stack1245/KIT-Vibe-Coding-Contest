import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';
export const revalidate = 0;
export const fetchCache = 'force-no-store';
export const runtime = 'nodejs';

export async function POST() {
  const { clearSession } = await import('../../../../lib/server/session');
  return clearSession(NextResponse.json({ ok: true }));
}
