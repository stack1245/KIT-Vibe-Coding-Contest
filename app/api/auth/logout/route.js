import { NextResponse } from 'next/server';
import { clearSession } from '../../../../lib/server/session';

export function POST() {
  return clearSession(NextResponse.json({ ok: true }));
}