import 'server-only';

const GITHUB_API_ORIGIN = 'https://api.github.com';
const REPOSITORIES_PER_PAGE = 100;
const MAX_REPOSITORY_PAGES = 3;

export class GitHubRepositoryError extends Error {
  constructor(message, { statusCode = 500, code = 'github_repository_error' } = {}) {
    super(message);
    this.name = 'GitHubRepositoryError';
    this.statusCode = statusCode;
    this.code = code;
  }
}

function normalizeScopeSet(scopeText = '') {
  return new Set(
    String(scopeText || '')
      .split(/[,\s]+/)
      .map((value) => value.trim())
      .filter(Boolean)
  );
}

function buildGitHubHeaders(accessToken, accept = 'application/vnd.github+json') {
  return {
    Accept: accept,
    Authorization: `Bearer ${accessToken}`,
    'User-Agent': 'phase-vuln-coach',
    'X-GitHub-Api-Version': '2022-11-28',
  };
}

function getGitHubAccessToken(userRow) {
  return String(userRow?.github_access_token || '').trim();
}

function assertGitHubRepositoryAccess(userRow) {
  if (!userRow?.github_id) {
    throw new GitHubRepositoryError('GitHub 계정 연동이 필요합니다.', {
      statusCode: 400,
      code: 'github_not_linked',
    });
  }

  const accessToken = getGitHubAccessToken(userRow);
  if (!accessToken) {
    throw new GitHubRepositoryError('GitHub 저장소를 가져오려면 계정을 다시 연동해주세요.', {
      statusCode: 400,
      code: 'github_reauth_required',
    });
  }

  return accessToken;
}

async function fetchGitHubApi(resourcePath, { accessToken, accept } = {}) {
  const response = await fetch(`${GITHUB_API_ORIGIN}${resourcePath}`, {
    headers: buildGitHubHeaders(accessToken, accept),
    cache: 'no-store',
  });

  if (response.status === 401) {
    throw new GitHubRepositoryError('GitHub 인증이 만료되었습니다. 계정을 다시 연동해주세요.', {
      statusCode: 401,
      code: 'github_token_expired',
    });
  }

  if (response.status === 403) {
    throw new GitHubRepositoryError('GitHub 저장소 접근 권한이 부족합니다. 계정을 다시 연동해주세요.', {
      statusCode: 403,
      code: 'github_scope_insufficient',
    });
  }

  if (response.status === 404) {
    throw new GitHubRepositoryError('요청한 GitHub 저장소를 찾지 못했습니다.', {
      statusCode: 404,
      code: 'github_repository_not_found',
    });
  }

  if (!response.ok) {
    throw new GitHubRepositoryError('GitHub API 요청에 실패했습니다.', {
      statusCode: 502,
      code: 'github_api_failed',
    });
  }

  return response;
}

function normalizeRepositoryPayload(repository) {
  return {
    id: Number(repository.id),
    name: String(repository.name || ''),
    fullName: String(repository.full_name || ''),
    ownerLogin: String(repository.owner?.login || ''),
    private: Boolean(repository.private),
    defaultBranch: String(repository.default_branch || 'main'),
    htmlUrl: String(repository.html_url || ''),
    description: String(repository.description || ''),
    updatedAt: String(repository.updated_at || ''),
    pushedAt: String(repository.pushed_at || ''),
    size: Number(repository.size || 0),
    archived: Boolean(repository.archived),
    disabled: Boolean(repository.disabled),
    visibility: String(repository.visibility || (repository.private ? 'private' : 'public')),
  };
}

function sanitizeArchiveSegment(value, fallback) {
  return String(value || '')
    .trim()
    .replace(/[^a-zA-Z0-9._-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    || fallback;
}

export function hasGitHubRepositoryScope(scopeText = '') {
  const scopes = normalizeScopeSet(scopeText);
  return scopes.has('repo') || scopes.has('public_repo');
}

export function createRepositoryArchiveFileName(repository, ref = '') {
  const owner = sanitizeArchiveSegment(repository?.ownerLogin || repository?.fullName?.split('/')[0], 'owner');
  const name = sanitizeArchiveSegment(repository?.name || repository?.fullName?.split('/')[1], 'repository');
  const resolvedRef = sanitizeArchiveSegment(ref || repository?.defaultBranch || 'default', 'default');
  return `${owner}-${name}-${resolvedRef}.zip`;
}

export async function listGitHubRepositories(userRow) {
  const accessToken = assertGitHubRepositoryAccess(userRow);
  const repositories = [];

  for (let page = 1; page <= MAX_REPOSITORY_PAGES; page += 1) {
    const response = await fetchGitHubApi(
      `/user/repos?sort=updated&direction=desc&per_page=${REPOSITORIES_PER_PAGE}&page=${page}`,
      { accessToken }
    );
    const payload = await response.json();
    const pageRepositories = Array.isArray(payload) ? payload.map(normalizeRepositoryPayload) : [];

    repositories.push(...pageRepositories);

    if (pageRepositories.length < REPOSITORIES_PER_PAGE) {
      break;
    }
  }

  return {
    repositories,
    tokenScope: String(userRow?.github_token_scope || ''),
    hasRepositoryScope: hasGitHubRepositoryScope(userRow?.github_token_scope || ''),
  };
}

export async function fetchGitHubRepositoryArchive({ userRow, fullName, ref = '' }) {
  const accessToken = assertGitHubRepositoryAccess(userRow);
  const normalizedFullName = String(fullName || '').trim();

  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(normalizedFullName)) {
    throw new GitHubRepositoryError('가져올 GitHub 저장소 이름이 올바르지 않습니다.', {
      statusCode: 400,
      code: 'github_repository_invalid',
    });
  }

  const metadataResponse = await fetchGitHubApi(`/repos/${normalizedFullName}`, { accessToken });
  const repository = normalizeRepositoryPayload(await metadataResponse.json());
  const archiveRef = String(ref || repository.defaultBranch || '').trim() || repository.defaultBranch || 'main';

  const archiveResponse = await fetch(`${GITHUB_API_ORIGIN}/repos/${normalizedFullName}/zipball/${encodeURIComponent(archiveRef)}`, {
    headers: buildGitHubHeaders(accessToken, 'application/vnd.github+json'),
    cache: 'no-store',
    redirect: 'manual',
  });

  let downloadUrl = '';

  if ([301, 302, 303, 307, 308].includes(archiveResponse.status)) {
    downloadUrl = String(archiveResponse.headers.get('location') || '').trim();
  } else if (archiveResponse.ok) {
    downloadUrl = archiveResponse.url;
  } else if (archiveResponse.status === 404) {
    throw new GitHubRepositoryError('저장소 아카이브를 찾지 못했습니다.', {
      statusCode: 404,
      code: 'github_archive_not_found',
    });
  } else if (archiveResponse.status === 401) {
    throw new GitHubRepositoryError('GitHub 인증이 만료되었습니다. 계정을 다시 연동해주세요.', {
      statusCode: 401,
      code: 'github_token_expired',
    });
  } else if (archiveResponse.status === 403) {
    throw new GitHubRepositoryError('저장소 아카이브를 가져올 권한이 없습니다. 계정을 다시 연동해주세요.', {
      statusCode: 403,
      code: 'github_scope_insufficient',
    });
  } else {
    throw new GitHubRepositoryError('저장소 아카이브를 가져오지 못했습니다.', {
      statusCode: 502,
      code: 'github_archive_failed',
    });
  }

  if (!downloadUrl) {
    throw new GitHubRepositoryError('저장소 아카이브 다운로드 주소를 찾지 못했습니다.', {
      statusCode: 502,
      code: 'github_archive_redirect_missing',
    });
  }

  const downloadResponse = await fetch(downloadUrl, {
    cache: 'no-store',
    redirect: 'follow',
  });

  if (!downloadResponse.ok) {
    throw new GitHubRepositoryError('저장소 아카이브 다운로드에 실패했습니다.', {
      statusCode: 502,
      code: 'github_archive_download_failed',
    });
  }

  const buffer = Buffer.from(await downloadResponse.arrayBuffer());

  return {
    repository,
    ref: archiveRef,
    fileName: createRepositoryArchiveFileName(repository, archiveRef),
    contentType: String(downloadResponse.headers.get('content-type') || 'application/zip'),
    buffer,
  };
}
