import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  buildRuleBasedAnalysisReport,
  normalizeCodexReport,
  prepareCodexAnalysisWorkspace,
  selectPreferredAnalysisReport,
} from '../lib/server/analysis-report';

const tempDirectories = [];

function createTempDir() {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'phase-analysis-test-'));
  tempDirectories.push(tempDir);
  return tempDir;
}

function writeTarOctal(buffer, offset, length, value) {
  const octal = value.toString(8).padStart(length - 1, '0');
  buffer.write(`${octal}\0`, offset, length, 'ascii');
}

function createSingleFileTar(archivePath, entryName, content) {
  const contentBuffer = Buffer.from(content, 'utf8');
  const header = Buffer.alloc(512, 0);

  header.write(entryName, 0, Math.min(Buffer.byteLength(entryName), 100), 'ascii');
  writeTarOctal(header, 100, 8, 0o644);
  writeTarOctal(header, 108, 8, 0);
  writeTarOctal(header, 116, 8, 0);
  writeTarOctal(header, 124, 12, contentBuffer.length);
  writeTarOctal(header, 136, 12, Math.floor(Date.now() / 1000));
  header.fill(0x20, 148, 156);
  header.write('0', 156, 1, 'ascii');
  header.write('ustar', 257, 5, 'ascii');
  header.write('00', 263, 2, 'ascii');

  let checksum = 0;
  for (const byte of header) {
    checksum += byte;
  }
  writeTarOctal(header, 148, 8, checksum);

  const contentPadding = Buffer.alloc((512 - (contentBuffer.length % 512)) % 512, 0);
  const trailer = Buffer.alloc(1024, 0);

  fs.writeFileSync(archivePath, Buffer.concat([header, contentBuffer, contentPadding, trailer]));
}

afterEach(() => {
  while (tempDirectories.length > 0) {
    const tempDir = tempDirectories.pop();
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

describe('analysis report helpers', () => {
  it('extracts archive uploads into the Codex workspace', async () => {
    const tempDir = createTempDir();
    const archivePath = path.join(tempDir, 'sample.tar');
    createSingleFileTar(archivePath, 'app.js', 'console.log("hello");\n');

    const { workspaceRoot, manifest } = await prepareCodexAnalysisWorkspace([
      {
        originalName: 'sample.tar',
        absolutePath: archivePath,
      },
    ]);

    tempDirectories.push(workspaceRoot);

    expect(manifest).toHaveLength(1);
    expect(manifest[0].archive).toBe(true);
    expect(manifest[0].storedPath).toBeTruthy();
    expect(manifest[0].extractedPath).toBeTruthy();
    expect(fs.existsSync(path.join(workspaceRoot, manifest[0].storedPath))).toBe(true);
    expect(fs.existsSync(path.join(workspaceRoot, manifest[0].extractedPath, 'app.js'))).toBe(true);
  });

  it('finds SQL injection from direct query concatenation', () => {
    const code = `
app.get('/users', (req, res) => {
  const id = req.query.id;
  return db.query("SELECT * FROM users WHERE id = " + req.query.id);
});
`.trim();

    const report = buildRuleBasedAnalysisReport({
      contexts: [
        {
          sourceFile: 'server.js',
          kind: 'text',
          text: code,
          fullText: code,
        },
      ],
      sourceFiles: [
        {
          originalName: 'server.js',
          relativePath: 'server.js',
          size: code.length,
        },
      ],
    });

    expect(report.resultMode).toBe('vulnerability');
    expect(report.findings[0].title).toBe('SQL Injection');
  });

  it('finds insecure default secrets in runtime session code', () => {
    const code = `
import crypto from 'node:crypto';

function getSessionSecret() {
  return process.env.SESSION_SECRET || 'change-this-session-secret';
}

export function sign(value) {
  return crypto.createHmac('sha256', getSessionSecret()).update(value).digest('base64url');
}
`.trim();

    const report = buildRuleBasedAnalysisReport({
      contexts: [
        {
          sourceFile: 'lib/server/session.js',
          kind: 'text',
          text: code,
          fullText: code,
          evidenceRole: 'runtime-source',
          runtimeEligible: true,
        },
      ],
      sourceFiles: [
        {
          originalName: 'session.js',
          relativePath: 'lib/server/session.js',
          size: code.length,
        },
      ],
    });

    expect(report.resultMode).toBe('vulnerability');
    expect(report.findings.some((finding) => finding.title === 'Insecure Default Secret')).toBe(true);
  });

  it('finds host header poisoning when forwarded headers drive redirect urls without a trust gate', () => {
    const code = `
function normalizeOrigin(value) {
  return value;
}

function getRequestAppOrigin(request) {
  const host = request.headers.get('x-forwarded-host') || request.headers.get('host');
  const protocol = request.headers.get('x-forwarded-proto') || 'https';
  return normalizeOrigin(\`\${protocol}://\${host}\`);
}

export function getGitHubConfig(request) {
  const origin = getRequestAppOrigin(request);
  return {
    redirectUri: \`\${origin}/auth/github/callback\`,
  };
}
`.trim();

    const report = buildRuleBasedAnalysisReport({
      contexts: [
        {
          sourceFile: 'lib/server/config.js',
          kind: 'text',
          text: code,
          fullText: code,
          evidenceRole: 'runtime-source',
          runtimeEligible: true,
        },
      ],
      sourceFiles: [
        {
          originalName: 'config.js',
          relativePath: 'lib/server/config.js',
          size: code.length,
        },
      ],
    });

    expect(report.resultMode).toBe('vulnerability');
    expect(report.findings.some((finding) => finding.title === 'Host Header Poisoning')).toBe(true);
  });

  it('does not flag host header poisoning when forwarded headers are explicitly gated', () => {
    const code = `
function shouldTrustProxyHeaders() {
  return String(process.env.TRUST_PROXY_HEADERS || 'false') === 'true';
}

function getRequestAppOrigin(request) {
  const host = request.headers.get('x-forwarded-host') || request.headers.get('host');
  const protocol = request.headers.get('x-forwarded-proto') || 'https';
  const trustedHeaderOrigin = shouldTrustProxyHeaders() ? \`\${protocol}://\${host}\` : '';
  return process.env.APP_BASE_URL || trustedHeaderOrigin;
}

export function getGitHubConfig(request) {
  return { redirectUri: \`\${getRequestAppOrigin(request)}/auth/github/callback\` };
}
`.trim();

    const report = buildRuleBasedAnalysisReport({
      contexts: [
        {
          sourceFile: 'lib/server/config.js',
          kind: 'text',
          text: code,
          fullText: code,
          evidenceRole: 'runtime-source',
          runtimeEligible: true,
        },
      ],
      sourceFiles: [
        {
          originalName: 'config.js',
          relativePath: 'lib/server/config.js',
          size: code.length,
        },
      ],
    });

    expect(report.findings.some((finding) => finding.title === 'Host Header Poisoning')).toBe(false);
  });

  it('treats code-like txt files as runtime source when they contain real executable logic', () => {
    const code = `
const express = require('express');
const app = express();

app.get('/users', (req, res) => {
  return db.query("SELECT * FROM users WHERE id = " + req.query.id);
});
`.trim();

    const report = buildRuleBasedAnalysisReport({
      contexts: [
        {
          sourceFile: 'src/runtime-source.txt',
          kind: 'text',
          text: code,
          fullText: code,
        },
      ],
      sourceFiles: [
        {
          originalName: 'runtime-source.txt',
          relativePath: 'src/runtime-source.txt',
          size: code.length,
        },
      ],
    });

    expect(report.resultMode).toBe('vulnerability');
    expect(report.findings.some((finding) => finding.title === 'SQL Injection')).toBe(true);
  });

  it('treats markdown source dumps as runtime source when code blocks dominate the file', () => {
    const markdownSourceDump = `
# Exported source dump

\`\`\`js
const express = require('express');
const app = express();

app.get('/users', (req, res) => {
  const unsafe = req.query.id;
  return db.query("SELECT * FROM users WHERE id = " + unsafe);
});

app.listen(3000);
\`\`\`
`.trim();

    const report = buildRuleBasedAnalysisReport({
      contexts: [
        {
          sourceFile: 'dump/source.md',
          kind: 'text',
          text: markdownSourceDump,
          fullText: markdownSourceDump,
        },
      ],
      sourceFiles: [
        {
          originalName: 'source.md',
          relativePath: 'dump/source.md',
          size: markdownSourceDump.length,
        },
      ],
    });

    expect(report.resultMode).toBe('vulnerability');
    expect(report.findings.some((finding) => finding.title === 'SQL Injection')).toBe(true);
  });

  it('does not treat documentation and tests as vulnerability evidence', () => {
    const readme = `
# Example Security Notes

- SQL Injection example: SELECT * FROM users WHERE id = " + req.query.id
- Command Injection example: system(user_input)
- Buffer Overflow example: strcpy(buf, input)
`.trim();
    const testFile = `
describe('config', () => {
  it('uses sample secret', () => {
    process.env.API_SECRET = 'client-secret';
    expect(process.env.API_SECRET).toBe('client-secret');
  });
});
`.trim();

    const report = buildRuleBasedAnalysisReport({
      contexts: [
        {
          sourceFile: 'README.md',
          kind: 'text',
          text: readme,
          fullText: readme,
        },
        {
          sourceFile: 'tests/config.test.js',
          kind: 'text',
          text: testFile,
          fullText: testFile,
        },
      ],
      sourceFiles: [
        {
          originalName: 'README.md',
          relativePath: 'README.md',
          size: readme.length,
        },
        {
          originalName: 'config.test.js',
          relativePath: 'tests/config.test.js',
          size: testFile.length,
        },
      ],
    });

    expect(report.resultMode).toBe('recommendation');
    expect(report.findings.some((finding) => /sql injection|command injection|buffer overflow|hardcoded secret/i.test(finding.title))).toBe(false);
  });

  it('keeps verified rule-based vulnerabilities when deep Codex only returns recommendations', () => {
    const preferredReport = selectPreferredAnalysisReport({
      normalizedCodexReport: {
        resultMode: 'recommendation',
        findings: [
          {
            title: '입력 검증',
            severity: 'medium',
          },
        ],
      },
      ruleBasedReport: {
        resultMode: 'vulnerability',
        findings: [
          {
            title: 'SQL Injection',
            severity: 'high',
          },
        ],
      },
    });

    expect(preferredReport.resultMode).toBe('vulnerability');
    expect(preferredReport.findings[0].title).toBe('SQL Injection');
  });

  it('softens definitive no-vulnerability summaries when normalized recommendations lose their anchors', () => {
    const report = normalizeCodexReport({
      title: 'API 요청을 처리하는 서비스',
      applicationType: 'API 요청을 처리하는',
      applicationReport: 'Express 기반 API 서비스다.',
      resultMode: 'recommendation',
      summary: '실행 가능한 코드 경로에서 확정된 취약점이 확인되지 않았습니다.',
      findings: [
        {
          title: '입력 검증',
          severity: 'medium',
          location: 'ghost.js:12',
          codeLocation: 'const payload = input;',
          explanation: '설명',
          detail: '세부 설명',
          remediation: '검증을 추가한다.',
        },
      ],
    }, [
      {
        originalName: 'server.js',
        relativePath: 'server.js',
        size: 42,
      },
    ], []);

    expect(report.resultMode).toBe('recommendation');
    expect(report.findings).toHaveLength(0);
    expect(report.summary).toBe('자동 분석에서 확정 취약점을 끝까지 입증하지 못해 추가 검토가 필요합니다.');
  });

  it('keeps multi-step attack scenarios intact when normalizing Codex vulnerabilities', () => {
    const code = `
const express = require('express');
const app = express();

app.get('/users', (req, res) => {
  const id = req.query.id;
  return db.query("SELECT * FROM users WHERE id = " + id);
});
`.trim();

    const report = normalizeCodexReport({
      title: 'API 요청을 처리하는 서비스',
      applicationType: 'API 요청을 처리하는',
      applicationReport: 'Express 기반 API 서비스다.',
      resultMode: 'vulnerability',
      summary: 'SQL Injection이 확인된다.',
      findings: [
        {
          title: 'SQL Injection',
          severity: 'high',
          location: 'server.js:5',
          codeLocation: 'return db.query("SELECT * FROM users WHERE id = " + id);',
          explanation: 'req.query.id가 문자열 결합으로 SQL 쿼리에 들어가 검증 없이 실행된다.',
          detail: '1) 공격자가 id 파라미터에 SQL 구문을 넣는다. 2) 애플리케이션이 이를 문자열 결합으로 SELECT 문에 삽입한다. 3) 데이터베이스가 조작된 WHERE 절을 실행하면서 인증 우회나 전체 조회가 가능해진다.',
          remediation: 'prepared statement를 사용한다.',
          poc: 'GET /users?id=1 OR 1=1',
        },
      ],
    }, [
      {
        originalName: 'server.js',
        relativePath: 'server.js',
        size: code.length,
      },
    ], [
      {
        sourceFile: 'server.js',
        kind: 'text',
        text: code,
        fullText: code,
        evidenceRole: 'runtime-source',
        runtimeEligible: true,
      },
    ]);

    expect(report.resultMode).toBe('vulnerability');
    expect(report.findings[0].detail).toContain('1)');
    expect(report.findings[0].detail).toContain('2)');
    expect(report.findings[0].detail).toContain('3)');
  });

  it('writes applicationReport as a service description instead of code-analysis text', () => {
    const code = `
const express = require('express');
const app = express();

app.post('/login', (req, res) => {
  return res.json({ ok: true, token: 'sample' });
});

app.get('/files/:id', (req, res) => {
  return res.download(req.params.id);
});
`.trim();

    const report = buildRuleBasedAnalysisReport({
      contexts: [
        {
          sourceFile: 'server.js',
          kind: 'text',
          text: code,
          fullText: code,
        },
      ],
      sourceFiles: [
        {
          originalName: 'server.js',
          relativePath: 'server.js',
          size: code.length,
        },
      ],
    });

    expect(report.applicationReport).toContain('이 서비스는');
    expect(report.applicationReport).toMatch(/사용자|외부 시스템/);
    expect(report.applicationReport).not.toMatch(/로직|구조|흐름|분석|코드/);
  });

  it('rewrites Codex applicationReport into a service-facing description', () => {
    const code = `
const express = require('express');
const app = express();

app.post('/login', (req, res) => {
  return res.json({ ok: true, token: 'sample' });
});
`.trim();

    const report = normalizeCodexReport({
      title: 'API 요청을 처리하는 서비스',
      applicationType: 'API 요청을 처리하는',
      applicationReport: '이 코드는 Express 기반 라우팅 로직과 인증 처리 구조를 포함한다.',
      resultMode: 'recommendation',
      summary: '발견된 취약점 : 추가 검토 필요',
      findings: [],
    }, [
      {
        originalName: 'server.js',
        relativePath: 'server.js',
        size: code.length,
      },
    ], [
      {
        sourceFile: 'server.js',
        kind: 'text',
        text: code,
        fullText: code,
      },
    ]);

    expect(report.applicationReport).toContain('이 서비스는');
    expect(report.applicationReport).toMatch(/사용자|외부 시스템/);
    expect(report.applicationReport).not.toMatch(/코드|로직|구조|분석/);
  });
});
