import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  buildFileContexts,
  buildCodexUnifiedAnalysisPrompt,
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
  createTarArchive(archivePath, [{ entryName, content }]);
}

function createTarArchive(archivePath, entries) {
  const buffers = [];

  entries.forEach(({ entryName, content }) => {
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
    buffers.push(header, contentBuffer, contentPadding);
  });

  buffers.push(Buffer.alloc(1024, 0));
  fs.writeFileSync(archivePath, Buffer.concat(buffers));
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

  it('finds host header poisoning when request.nextUrl.origin is used for GitHub callback urls before any trusted-origin gate', () => {
    const code = `
function shouldTrustProxyHeaders() {
  return String(process.env.TRUST_PROXY_HEADERS || 'false').trim().toLowerCase() === 'true';
}

function getRequestAppOrigin(request) {
  const headerOrigin = 'https://' + (request.headers.get('x-forwarded-host') || request.headers.get('host'));
  const requestOrigin = request.nextUrl.origin || request.url;
  const trustedHeaderOrigin = shouldTrustProxyHeaders() ? headerOrigin : '';

  if (requestOrigin && !requestOrigin.includes('localhost')) {
    return requestOrigin;
  }

  return trustedHeaderOrigin || 'http://localhost:3000';
}

export function getGitHubConfig(request) {
  const appOrigin = getRequestAppOrigin(request);
  return {
    redirectUri: \`\${appOrigin}/auth/github/callback\`,
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

    expect(report.findings.some((finding) => finding.title === 'Host Header Poisoning')).toBe(true);
  });

  it('finds host header poisoning in the current config-style GitHub callback origin flow', () => {
    const code = `
function shouldTrustProxyHeaders() {
  return String(process.env.TRUST_PROXY_HEADERS || 'false').trim().toLowerCase() === 'true';
}

function normalizeOrigin(value = '') {
  return value;
}

function getHeaderOrigin(request) {
  const host = request.headers.get('x-forwarded-host') || request.headers.get('host');
  const protocol = request.headers.get('x-forwarded-proto') || 'https';
  return normalizeOrigin(\`\${protocol}://\${host}\`);
}

export function getRequestAppOrigin(request) {
  const configuredOrigin = normalizeOrigin(process.env.APP_BASE_URL);
  const headerOrigin = getHeaderOrigin(request);
  const requestOrigin = normalizeOrigin(request?.nextUrl?.origin || request?.url || '');
  const trustedHeaderOrigin = shouldTrustProxyHeaders() ? headerOrigin : '';

  if (requestOrigin && !requestOrigin.includes('localhost')) {
    return requestOrigin;
  }

  if (trustedHeaderOrigin && !trustedHeaderOrigin.includes('localhost')) {
    return trustedHeaderOrigin;
  }

  return configuredOrigin || requestOrigin || trustedHeaderOrigin || 'http://localhost:3000';
}

export function getGitHubConfig(request) {
  const appOrigin = getRequestAppOrigin(request);
  return {
    redirectUri: \`\${appOrigin}/auth/github/callback\`,
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
      includeRecommendations: false,
    });

    expect(report?.findings?.some((finding) => finding.title === 'Host Header Poisoning')).toBe(true);
  });

  it('finds host header poisoning in the current repository GitHub origin flow', () => {
    const files = [
      'lib/server/config.js',
      'app/auth/github/route.js',
      'app/auth/github/callback/route.js',
      'lib/server/session.js',
    ];

    const contexts = files.map((file) => {
      const text = fs.readFileSync(path.join(process.cwd(), file), 'utf8');
      return {
        sourceFile: file,
        kind: 'text',
        text,
        fullText: text,
        evidenceRole: 'runtime-source',
        runtimeEligible: true,
      };
    });

    const sourceFiles = files.map((file) => ({
      originalName: path.basename(file),
      relativePath: file,
      size: fs.statSync(path.join(process.cwd(), file)).size,
    }));

    const report = buildRuleBasedAnalysisReport({
      contexts,
      sourceFiles,
      includeRecommendations: false,
    });

    expect(report?.resultMode).toBe('vulnerability');
    const finding = report?.findings?.find((item) => item.title === 'Host Header Poisoning');
    expect(Boolean(finding)).toBe(true);
    expect(finding?.explanation).toContain('getRequestAppOrigin()');
    expect(finding?.explanation).toContain('GitHub OAuth redirectUri');
    expect(finding?.detail).toContain('getGitHubConfig()');
    expect(finding?.detail).toContain('app/auth/github/callback/route.js');
    expect(finding?.patchExample).toContain('APP_BASE_URL');
    expect(finding?.patchExample).toContain('GitHub OAuth');
  });

  it('finds host header poisoning from the current repository when uploaded as an archive', async () => {
    const tempDir = createTempDir();
    const archivePath = path.join(tempDir, 'repo-snapshot.tar');
    const files = [
      'lib/server/config.js',
      'app/auth/github/route.js',
      'app/auth/github/callback/route.js',
      'lib/server/session.js',
    ];

    createTarArchive(
      archivePath,
      files.map((relativePath) => ({
        entryName: relativePath,
        content: fs.readFileSync(path.join(process.cwd(), relativePath), 'utf8'),
      })),
    );

    const contexts = await buildFileContexts([
      {
        originalName: 'repo-snapshot.tar',
        absolutePath: archivePath,
      },
    ]);

    const configContext = contexts.find((context) => /lib\/server\/config\.js$/i.test(context.sourceFile));
    expect(configContext).toBeTruthy();
    expect(configContext?.evidenceRole).toBe('runtime-source');
    expect(configContext?.runtimeEligible).toBe(true);

    const report = buildRuleBasedAnalysisReport({
      contexts,
      sourceFiles: [
        {
          originalName: 'repo-snapshot.tar',
          relativePath: 'repo-snapshot.tar',
          size: fs.statSync(archivePath).size,
        },
      ],
      includeRecommendations: false,
    });

    expect(report?.resultMode).toBe('vulnerability');
    expect(report?.findings?.some((finding) => finding.title === 'Host Header Poisoning')).toBe(true);
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

  it('prefers rule-based vulnerabilities over Codex recommendations', () => {
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
    expect(report.summary).toBe('두 차례 취약점 탐색에서 확정 취약점을 입증하지 못해 보안적으로 보완하면 좋은 점을 정리했습니다.');
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

    expect(report.title).toMatch(/(서비스|솔루션) 리포트$/);
    expect(report.applicationReport).toContain('이 서비스는');
    expect(report.applicationReport.split('.').filter(Boolean).length).toBeGreaterThanOrEqual(2);
    expect(report.applicationReport).toMatch(/엔드포인트|함수/);
    expect(report.applicationReport).not.toMatch(/구조 복원|분석 결과/);
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

    expect(report.title).toBe('백엔드 API 서비스 리포트');
    expect(report.applicationReport).toContain('이 서비스는');
    expect(report.applicationReport.split('.').filter(Boolean).length).toBeGreaterThanOrEqual(2);
    expect(report.applicationReport).toMatch(/엔드포인트|함수/);
    expect(report.applicationReport).not.toMatch(/구조 복원|분석 결과/);
  });

  it('keeps a service-type application label from the Codex report instead of re-inferencing a logic label', () => {
    const toolingText = `
const APP_TYPE_RULES = [
  { type: '메뉴 입력을 받아 상태를 변경하는', patterns: [/menu/, /choice/, /stdin/] },
];

const SERVICE_TYPE_RULES = [
  { type: '코드 업로드와 GitHub 저장소 취약점 분석 웹 서비스', patterns: [/github/, /upload/, /analysis/] },
];
`.trim();

    const report = normalizeCodexReport({
      title: '코드 보안 점검 솔루션 리포트',
      applicationType: '코드 업로드와 GitHub 저장소 취약점 분석 웹 서비스',
      applicationReport: '사용자는 코드를 올리고 결과를 본다. 개발자 관점에서는 업로드와 리포트 생성 엔드포인트가 분석을 수행한다.',
      resultMode: 'recommendation',
      summary: '보안 조언이 필요합니다.',
      findings: [],
    }, [
      {
        originalName: 'analysis-report.js',
        relativePath: 'lib/server/analysis-report.js',
        size: toolingText.length,
      },
    ], [
      {
        sourceFile: 'lib/server/analysis-report.js',
        kind: 'text',
        text: toolingText,
        fullText: toolingText,
        evidenceRole: 'runtime-source',
        runtimeEligible: true,
      },
    ]);

    expect(report.applicationType).toBe('코드 업로드와 GitHub 저장소 취약점 분석 웹 서비스');
    expect(report.title).toBe('코드 보안 점검 솔루션 리포트');
  });

  it('builds a single Codex prompt that performs full analysis and report writing in one run', () => {
    const manifest = [
      {
        originalName: 'sample.js',
        storedPath: '01-sample.js',
        extractedPath: '',
        archive: false,
      },
    ];

    const prompt = buildCodexUnifiedAnalysisPrompt({
      manifest,
      runtimeFileHints: ['01-sample.js'],
    });

    expect(prompt).toContain('This workflow has only two stages');
    expect(prompt).toContain('Perform the vulnerability search in two internal sweeps inside this same run');
    expect(prompt).toContain('runtimeFileHints');
    expect(prompt).toContain('Do not rely on a vulnerability checklist or static signature table');
    expect(prompt).toContain('Good examples: "모바일 쇼핑 서비스 리포트", "영상 처리 솔루션 리포트", "코드 보안 점검 솔루션 리포트"');
    expect(prompt).toContain('Avoid logic-labeled titles such as "메뉴 기반 네이티브 프로그램..."');
  });

  it('does not report XSS for static dangerouslySetInnerHTML cleanup code', () => {
    const code = `
const extensionHydrationCleanup = \`
(() => {
  const marker = 'browser-extension-cleanup';
  console.log(marker);
})();
\`;

export default function RootLayout({ children }) {
  return (
    <html lang="ko">
      <head>
        <script dangerouslySetInnerHTML={{ __html: extensionHydrationCleanup }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
`.trim();

    const report = buildRuleBasedAnalysisReport({
      contexts: [
        {
          sourceFile: 'app/layout.js',
          kind: 'text',
          text: code,
          fullText: code,
          evidenceRole: 'runtime-source',
          runtimeEligible: true,
        },
      ],
      sourceFiles: [
        {
          originalName: 'layout.js',
          relativePath: 'app/layout.js',
          size: code.length,
        },
      ],
    });

    expect(report.findings.some((finding) => finding.title === 'XSS')).toBe(false);
  });

  it('does not describe SQL-backed services as menu-driven just because SELECT appears in code', () => {
    const code = `
const express = require('express');
const app = express();

app.get('/users', (req, res) => {
  return db.query('SELECT id, email FROM users');
});
`.trim();

    const report = buildRuleBasedAnalysisReport({
      contexts: [
        {
          sourceFile: 'server.js',
          kind: 'text',
          text: code,
          fullText: code,
          evidenceRole: 'runtime-source',
          runtimeEligible: true,
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

    expect(report.applicationType).not.toBe('메뉴 입력을 받아 상태를 변경하는');
    expect(report.applicationReport).not.toContain('메뉴나 입력창을 통해 항목을 조회하거나 생성, 수정, 삭제할 수 있다');
  });

  it('can disable generic rule-based recommendations when only vulnerability backstop behavior is desired', () => {
    const code = `
export function noop() {
  return 'ok';
}
`.trim();

    const report = buildRuleBasedAnalysisReport({
      contexts: [
        {
          sourceFile: 'noop.js',
          kind: 'text',
          text: code,
          fullText: code,
          evidenceRole: 'runtime-source',
          runtimeEligible: true,
        },
      ],
      sourceFiles: [
        {
          originalName: 'noop.js',
          relativePath: 'noop.js',
          size: code.length,
        },
      ],
      includeRecommendations: false,
    });

    expect(report).toBeNull();
  });

  it('uses project-wide locations for generic recommendation backstops', () => {
    const code = `
export function noop() {
  return 'ok';
}
`.trim();

    const report = buildRuleBasedAnalysisReport({
      contexts: [
        {
          sourceFile: 'noop.js',
          kind: 'text',
          text: code,
          fullText: code,
          evidenceRole: 'runtime-source',
          runtimeEligible: true,
        },
      ],
      sourceFiles: [
        {
          originalName: 'noop.js',
          relativePath: 'noop.js',
          size: code.length,
        },
      ],
    });

    expect(report.resultMode).toBe('recommendation');
    expect(report.findings[0].location).toContain('프로젝트 전반');
  });

  it('formats findings with a short vulnerability title and patch example section', () => {
    const code = `
app.get('/users', (req, res) => {
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
          evidenceRole: 'runtime-source',
          runtimeEligible: true,
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

    expect(report.findings[0].title).toBe('SQL Injection');
    expect(report.findings[0].explanation).toContain('SQL Injection은 공격자 입력이 SQL 쿼리의');
    expect(report.findings[0].patchExample).toContain('현재 코드:');
    expect(report.findings[0].patchExample).toContain('패치 예시 코드:');
    expect(report.findings[0].description).toContain('1) 취약점 설명');
    expect(report.findings[0].description).toContain('파일 경로:\nserver.js:');
    expect(report.findings[0].description).toContain('핵심 코드:\n');
    expect(report.findings[0].description).toContain('5) 패치 코드 예시');
  });
});
