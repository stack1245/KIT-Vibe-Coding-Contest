export function buildFindingQuizKey(finding, index = 0) {
  const base = [
    String(finding?.id || '').trim(),
    String(finding?.title || '').trim(),
    String(finding?.location || '').trim(),
    String(finding?.severity || '').trim(),
    `idx-${Number(index) || 0}`,
  ]
    .filter(Boolean)
    .join('::')
    .toLowerCase();

  const normalized = base
    .replace(/[^a-z0-9가-힣]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 160);

  return normalized || `finding-${Number(index) + 1}`;
}

export function isQuizEligibleFinding(finding) {
  return String(finding?.severity || '').trim().toLowerCase() === 'high';
}

export function buildPhaseFlagFromHex(flagHex) {
  return `Phase{${String(flagHex || '').trim().toLowerCase()}}`;
}
