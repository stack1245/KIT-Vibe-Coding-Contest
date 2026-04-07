export async function fetchJson(url, options) {
  const response = await fetch(url, { credentials: 'same-origin', ...options });
  const payload = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(payload.message || '요청을 처리하지 못했습니다.');
  }

  return payload;
}