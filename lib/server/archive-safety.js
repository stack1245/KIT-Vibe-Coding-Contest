import 'server-only';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

function readPositiveNumberEnv(name, fallbackValue) {
  const parsed = Number(process.env[name] || fallbackValue);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallbackValue;
}

export const MAX_SAFE_ARCHIVE_ENTRY_COUNT = readPositiveNumberEnv('MAX_SAFE_ARCHIVE_ENTRY_COUNT', 2000);
export const MAX_SAFE_ARCHIVE_TOTAL_UNCOMPRESSED_BYTES = readPositiveNumberEnv(
  'MAX_SAFE_ARCHIVE_TOTAL_UNCOMPRESSED_BYTES',
  512 * 1024 * 1024,
);

export function normalizeArchiveEntryPath(value = '') {
  return String(value || '')
    .replace(/\\/g, '/')
    .trim();
}

export function isUnsafeArchiveEntryPath(entryName = '') {
  const normalized = normalizeArchiveEntryPath(entryName);
  if (!normalized) {
    return false;
  }

  if (normalized.startsWith('/') || /^[A-Za-z]:\//.test(normalized)) {
    return true;
  }

  return normalized.split('/').some((segment) => segment === '..');
}

export function collectUnsafeArchiveEntries(entries = []) {
  return Array.from(new Set(
    entries
      .map((entry) => normalizeArchiveEntryPath(entry))
      .filter((entry) => entry && isUnsafeArchiveEntryPath(entry)),
  ));
}

function parseZipFootprint(stdout) {
  const lines = String(stdout || '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);
  const summaryLine = [...lines].reverse().find((line) => /\bfiles?$/.test(line));

  if (summaryLine) {
    const match = summaryLine.match(/^(\d+)\s+.*?\s+(\d+)\s+files?$/);
    if (match) {
      return {
        totalUncompressedBytes: Number(match[1]),
        entryCount: Number(match[2]),
      };
    }
  }

  return lines.reduce((accumulator, line) => {
    const match = line.match(/^(\d+)\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}\s+.+$/);
    if (!match) {
      return accumulator;
    }

    accumulator.totalUncompressedBytes += Number(match[1]);
    accumulator.entryCount += 1;
    return accumulator;
  }, {
    totalUncompressedBytes: 0,
    entryCount: 0,
  });
}

function parseTarFootprint(stdout) {
  return String(stdout || '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .reduce((accumulator, line) => {
      const parts = line.split(/\s+/);
      if (parts.length < 6 || !/^\d+$/.test(parts[2])) {
        return accumulator;
      }

      accumulator.totalUncompressedBytes += Number(parts[2]);
      accumulator.entryCount += 1;
      return accumulator;
    }, {
      totalUncompressedBytes: 0,
      entryCount: 0,
    });
}

export async function inspectArchiveFootprint(
  filePath,
  extension,
  {
    zipArchiveExtensions = [],
    timeoutMs = 15000,
    maxBuffer = 2 * 1024 * 1024,
  } = {},
) {
  if (zipArchiveExtensions.includes(extension)) {
    const { stdout } = await execFileAsync('unzip', ['-l', filePath], {
      timeout: timeoutMs,
      maxBuffer,
    });
    return parseZipFootprint(stdout);
  }

  const { stdout } = await execFileAsync('tar', ['-tvf', filePath], {
    timeout: timeoutMs,
    maxBuffer,
  });
  return parseTarFootprint(stdout);
}

export function getArchiveSafetyIssues({
  entries = [],
  entryCount = 0,
  totalUncompressedBytes = 0,
  maxEntries = MAX_SAFE_ARCHIVE_ENTRY_COUNT,
  maxTotalBytes = MAX_SAFE_ARCHIVE_TOTAL_UNCOMPRESSED_BYTES,
} = {}) {
  const issues = [];
  const unsafeEntries = collectUnsafeArchiveEntries(entries);

  if (unsafeEntries.length) {
    issues.push(`unsafe-path:${unsafeEntries.slice(0, 3).join(', ')}`);
  }

  if (entryCount > maxEntries) {
    issues.push(`entry-count:${entryCount}`);
  }

  if (totalUncompressedBytes > maxTotalBytes) {
    issues.push(`total-size:${totalUncompressedBytes}`);
  }

  return issues;
}
