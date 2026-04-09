import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  buildRuleBasedAnalysisReport,
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
});
