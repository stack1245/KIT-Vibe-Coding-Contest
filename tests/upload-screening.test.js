import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { afterEach, describe, expect, it } from 'vitest';
import {
  getUploadFileSizeErrorMessage,
  normalizeStoredUploadRelativePath,
  saveUploadedFile,
  screenUploadedFile,
  UPLOAD_MAX_FILE_BYTES,
  UPLOAD_ROOT_DIR,
} from '../lib/server/upload-screening';

const createdFiles = [];

function createStoredZipBuffer(entries) {
  const localParts = [];
  const centralParts = [];
  let offset = 0;

  entries.forEach(({ name, content }) => {
    const nameBuffer = Buffer.from(name, 'utf8');
    const contentBuffer = Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8');
    const crc32 = zlib.crc32(contentBuffer) >>> 0;

    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(0, 6);
    localHeader.writeUInt16LE(0, 8);
    localHeader.writeUInt16LE(0, 10);
    localHeader.writeUInt16LE(0, 12);
    localHeader.writeUInt32LE(crc32, 14);
    localHeader.writeUInt32LE(contentBuffer.length, 18);
    localHeader.writeUInt32LE(contentBuffer.length, 22);
    localHeader.writeUInt16LE(nameBuffer.length, 26);
    localHeader.writeUInt16LE(0, 28);

    localParts.push(localHeader, nameBuffer, contentBuffer);

    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE(20, 4);
    centralHeader.writeUInt16LE(20, 6);
    centralHeader.writeUInt16LE(0, 8);
    centralHeader.writeUInt16LE(0, 10);
    centralHeader.writeUInt16LE(0, 12);
    centralHeader.writeUInt16LE(0, 14);
    centralHeader.writeUInt32LE(crc32, 16);
    centralHeader.writeUInt32LE(contentBuffer.length, 20);
    centralHeader.writeUInt32LE(contentBuffer.length, 24);
    centralHeader.writeUInt16LE(nameBuffer.length, 28);
    centralHeader.writeUInt16LE(0, 30);
    centralHeader.writeUInt16LE(0, 32);
    centralHeader.writeUInt16LE(0, 34);
    centralHeader.writeUInt16LE(0, 36);
    centralHeader.writeUInt32LE(0, 38);
    centralHeader.writeUInt32LE(offset, 42);

    centralParts.push(centralHeader, nameBuffer);
    offset += localHeader.length + nameBuffer.length + contentBuffer.length;
  });

  const centralDirectory = Buffer.concat(centralParts);
  const localSection = Buffer.concat(localParts);
  const endOfCentralDirectory = Buffer.alloc(22);
  endOfCentralDirectory.writeUInt32LE(0x06054b50, 0);
  endOfCentralDirectory.writeUInt16LE(0, 4);
  endOfCentralDirectory.writeUInt16LE(0, 6);
  endOfCentralDirectory.writeUInt16LE(entries.length, 8);
  endOfCentralDirectory.writeUInt16LE(entries.length, 10);
  endOfCentralDirectory.writeUInt32LE(centralDirectory.length, 12);
  endOfCentralDirectory.writeUInt32LE(localSection.length, 16);
  endOfCentralDirectory.writeUInt16LE(0, 20);

  return Buffer.concat([localSection, centralDirectory, endOfCentralDirectory]);
}

afterEach(() => {
  while (createdFiles.length > 0) {
    const filePath = createdFiles.pop();
    fs.rmSync(filePath, { recursive: true, force: true });
  }
});

describe('upload path normalization', () => {
  it('normalizes legacy stored paths with an upload prefix', () => {
    expect(normalizeStoredUploadRelativePath('upload/user-19/sample.zip')).toBe('user-19/sample.zip');
  });

  it('keeps already-normalized stored paths unchanged', () => {
    expect(normalizeStoredUploadRelativePath('user-19/sample.zip')).toBe('user-19/sample.zip');
  });

  it('stores uploaded files relative to the upload root', async () => {
    const result = await saveUploadedFile({
      userId: 777,
      originalName: 'sample.zip',
      file: {
        async arrayBuffer() {
          return new TextEncoder().encode('demo').buffer;
        },
      },
    });

    createdFiles.push(path.dirname(result.absolutePath));
    createdFiles.push(result.absolutePath);

    expect(result.relativePath.startsWith('upload/')).toBe(false);
    expect(result.relativePath.startsWith(`user-777/`)).toBe(true);
    expect(result.absolutePath).toBe(path.join(UPLOAD_ROOT_DIR, result.relativePath));
  });

  it('accepts readable jar uploads even when only manifest evidence is available', async () => {
    const jarBuffer = createStoredZipBuffer([
      {
        name: 'META-INF/MANIFEST.MF',
        content: 'Manifest-Version: 1.0\nMain-Class: example.Main\n\n',
      },
    ]);

    const result = await screenUploadedFile({
      fileName: 'plugin.jar',
      contentType: 'application/java-archive',
      previewBuffer: jarBuffer.subarray(0, 32 * 1024),
      file: {
        size: jarBuffer.length,
        async arrayBuffer() {
          return jarBuffer;
        },
      },
    });

    expect(result.accepted).toBe(true);
    expect(result.category).toBe('jar');
    expect(result.reason).toContain('JAR');
  });

  it('rejects archives with unsafe parent-directory entries', async () => {
    const zipBuffer = createStoredZipBuffer([
      {
        name: '../escape.txt',
        content: 'owned',
      },
    ]);

    const result = await screenUploadedFile({
      fileName: 'unsafe.zip',
      contentType: 'application/zip',
      previewBuffer: zipBuffer.subarray(0, 32 * 1024),
      file: {
        size: zipBuffer.length,
        async arrayBuffer() {
          return zipBuffer;
        },
      },
    });

    expect(result.accepted).toBe(false);
    expect(result.category).toBe('unsafe-archive');
  });

  it('rejects oversize uploads before reading the full body', async () => {
    const result = await screenUploadedFile({
      fileName: 'oversize.zip',
      contentType: 'application/zip',
      previewBuffer: Buffer.alloc(0),
      file: {
        size: Number(UPLOAD_MAX_FILE_BYTES + 1n),
        async arrayBuffer() {
          throw new Error('arrayBuffer should not be called');
        },
      },
    });

    expect(result.accepted).toBe(false);
    expect(result.reason).toBe(getUploadFileSizeErrorMessage(UPLOAD_MAX_FILE_BYTES + 1n));
  });

  it('refuses to persist files larger than the single-upload limit', async () => {
    await expect(saveUploadedFile({
      userId: 777,
      originalName: 'too-large.zip',
      file: {
        size: Number(UPLOAD_MAX_FILE_BYTES + 1n),
        async arrayBuffer() {
          throw new Error('arrayBuffer should not be called');
        },
      },
    })).rejects.toThrow(getUploadFileSizeErrorMessage(UPLOAD_MAX_FILE_BYTES + 1n));
  });
});
