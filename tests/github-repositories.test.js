import { describe, expect, it } from 'vitest';
import {
  createRepositoryArchiveFileName,
  hasGitHubRepositoryScope,
} from '../lib/server/github-repositories';

describe('github repositories helpers', () => {
  it('detects repository access scopes from GitHub scope strings', () => {
    expect(hasGitHubRepositoryScope('read:user user:email repo')).toBe(true);
    expect(hasGitHubRepositoryScope('read:user,public_repo')).toBe(true);
    expect(hasGitHubRepositoryScope('read:user user:email')).toBe(false);
  });

  it('builds a stable archive file name for imported repositories', () => {
    expect(
      createRepositoryArchiveFileName(
        {
          ownerLogin: 'openai-labs',
          name: 'phase vuln coach',
          defaultBranch: 'main',
        },
        'feature/github import'
      )
    ).toBe('openai-labs-phase-vuln-coach-feature-github-import.zip');
  });
});
