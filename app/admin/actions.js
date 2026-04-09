'use server';

import { buildSessionUser, getSessionUser } from '../../lib/server/auth';
import { deleteUserById, findUserById, listUsers } from '../../lib/server/database';
import { getSession } from '../../lib/server/session';

function requireAdmin(session) {
  const user = getSessionUser(session);

  if (!user) {
    throw new Error('로그인이 필요합니다.');
  }

  if (!user.isAdmin) {
    throw new Error('관리자 권한이 필요합니다.');
  }

  return user;
}

export async function listAdminUsersAction() {
  const session = await getSession();
  requireAdmin(session);

  return listUsers().map((row) => buildSessionUser(row, row.auth_provider));
}

export async function deleteAdminUserAction(targetUserId) {
  const session = await getSession();
  const user = requireAdmin(session);
  const targetId = Number(targetUserId);

  if (!Number.isInteger(targetId) || targetId <= 0) {
    throw new Error('올바르지 않은 회원 ID입니다.');
  }

  if (targetId === user.id) {
    throw new Error('본인 계정은 관리자 목록에서 삭제할 수 없습니다. 대시보드에서 회원탈퇴를 사용하세요.');
  }

  const targetUser = findUserById(targetId);
  if (!targetUser) {
    throw new Error('삭제할 회원을 찾지 못했습니다.');
  }

  if (!deleteUserById(targetId)) {
    throw new Error('회원 삭제에 실패했습니다.');
  }

  return { ok: true, deletedId: targetId };
}
