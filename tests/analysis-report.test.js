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

  it('prefers verified rule-based vulnerabilities over recommendation-only Codex output', () => {
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
