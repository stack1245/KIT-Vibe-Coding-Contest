import 'server-only';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

export const UPLOAD_ROOT_DIR = path.join(process.cwd(), 'upload');
export const UPLOAD_TOTAL_LIMIT_BYTES = 10n * 1024n * 1024n * 1024n * 1024n;
export const UPLOAD_CAPACITY_ERROR_MESSAGE = '현재 사용자 요청량이 너무 많습니다. 나중에 다시 시도해주세요';

const PREVIEW_BYTE_LIMIT = 32 * 1024;
const CODEX_PREVIEW_CHAR_LIMIT = 4000;
const ARCHIVE_LISTING_TIMEOUT_MS = 15000;
const ARCHIVE_ENTRY_LIMIT = 2000;
const ARCHIVE_PREVIEW_FILE_LIMIT = 8;
const ARCHIVE_PREVIEW_BYTE_LIMIT = 12 * 1024;
const BINARY_PREVIEW_FILE_LIMIT = 4;
const execFileAsync = promisify(execFile);
const REVIEWABLE_BINARY_EXTENSIONS = new Set([
  '.exe',
  '.dll',
  '.so',
  '.dylib',
  '.bin',
  '.elf',
  '.o',
  '.out',
  '.com',
  '.class',
  '.dex',
  '.wasm',
]);
const HARD_REJECT_EXTENSIONS = new Set([
  '.msi',
  '.dmg',
  '.pkg',
  '.deb',
  '.rpm',
  '.iso',
  '.img',
  '.scr',
  '.ps1',
  '.bat',
  '.cmd',
  '.vbs',
]);
const TEXT_SOURCE_EXTENSIONS = new Set([
  '.js',
  '.jsx',
  '.ts',
  '.tsx',
  '.mjs',
  '.cjs',
  '.py',
  '.java',
  '.kt',
  '.kts',
  '.swift',
  '.dart',
  '.go',
  '.rb',
  '.php',
  '.cs',
  '.cpp',
  '.cc',
  '.c',
  '.h',
  '.hpp',
  '.rs',
  '.scala',
  '.html',
  '.css',
  '.scss',
  '.sass',
  '.less',
  '.vue',
  '.svelte',
  '.astro',
  '.json',
  '.yml',
  '.yaml',
  '.xml',
  '.sql',
  '.toml',
  '.env',
  '.ini',
  '.properties',
  '.gradle',
]);
const LOGIC_SOURCE_EXTENSIONS = new Set([
  '.js',
  '.jsx',
  '.ts',
  '.tsx',
  '.mjs',
  '.cjs',
  '.py',
  '.java',
  '.kt',
  '.kts',
  '.swift',
  '.dart',
  '.go',
  '.rb',
  '.php',
  '.cs',
  '.cpp',
  '.cc',
  '.c',
  '.h',
  '.hpp',
  '.rs',
  '.scala',
  '.sql',
  '.sh',
]);
const STYLE_EXTENSIONS = new Set([
  '.css',
  '.scss',
  '.sass',
  '.less',
]);
const MARKUP_EXTENSIONS = new Set([
  '.html',
  '.htm',
  '.xml',
]);
const PROJECT_FILENAMES = new Set([
  'package.json',
  'package-lock.json',
  'pnpm-lock.yaml',
  'yarn.lock',
  'makefile',
  'cmakelists.txt',
  'meson.build',
  'build.ninja',
  'next.config.js',
  'next.config.mjs',
  'vite.config.js',
  'vite.config.ts',
  'angular.json',
  'nuxt.config.ts',
  'nuxt.config.js',
  'composer.json',
  'requirements.txt',
  'pyproject.toml',
  'manage.py',
  'pom.xml',
  'build.gradle',
  'build.gradle.kts',
  'settings.gradle',
  'settings.gradle.kts',
  'androidmanifest.xml',
  'pubspec.yaml',
  'cargo.toml',
  'gemfile',
  'go.mod',
  'dockerfile',
  'docker-compose.yml',
  'docker-compose.yaml',
  '.env',
  '.env.local',
  '.env.production',
  '.env.development',
  'appsettings.json',
]);
const APP_MARKERS = [
  { regex: /^\s*#include\s+<[\w./-]+>/m, signal: 'C/C++ source' },
  { regex: /\bint\s+main\s*\(|\bvoid\s+main\s*\(/, signal: 'Native entrypoint' },
  { regex: /\bmalloc\s*\(|\bfree\s*\(|\bstrcpy\s*\(|\bgets\s*\(|\bprintf\s*\(/, signal: 'Native memory/input handling' },
  { regex: /\bctf\b|\bchall(?:enge)?\b|\bpwn\b|\bheap\b|\bfsop\b|\bformat string\b|\buse-after-free\b|\bdouble free\b/i, signal: 'CTF or exploit challenge' },
  { regex: /\bnext(?:\/|\.)|\bfrom ['"]next\b|\bnextconfig\b/i, signal: 'Next.js' },
  { regex: /\breact\b|\bjsx\b|\btsx\b|\buseState\b|\buseEffect\b/i, signal: 'React' },
  { regex: /\bvue\b|\bcreateApp\b|\bdefineComponent\b/i, signal: 'Vue' },
  { regex: /\bsvelte\b|\bonMount\b/i, signal: 'Svelte' },
  { regex: /\bexpress\b|\brouter\.(get|post|put|delete)\b|\bapp\.(get|post|put|delete)\b/i, signal: 'Express' },
  { regex: /\bnestjs\b|@Controller\(|@Injectable\(/i, signal: 'NestJS' },
  { regex: /\bdjango\b|\burlpatterns\b|\bmodels\.Model\b/i, signal: 'Django' },
  { regex: /\bflask\b|\bfastapi\b|@app\.(get|post|put|delete)\(/i, signal: 'Python web app' },
  { regex: /\bspring\b|@RestController|@RequestMapping|SpringApplication/i, signal: 'Spring' },
  { regex: /\blaravel\b|\bRoute::(get|post|put|delete)\b/i, signal: 'Laravel' },
  { regex: /\breact-native\b|\bexpo\b/i, signal: 'React Native' },
  { regex: /\bflutter\b|\bMaterialApp\b|\bCupertinoApp\b/i, signal: 'Flutter' },
  { regex: /\bSwiftUI\b|\bUIKit\b|\bUIViewController\b/i, signal: 'iOS app' },
  { regex: /\bandroidx\b|\bActivity\b|\bFragment\b|\bsetContentView\b/i, signal: 'Android app' },
];
const GENERIC_CODE_MARKERS = [
  /\b(import|export)\b/,
  /\bfunction\s+\w+\s*\(/,
  /\bclass\s+\w+/,
  /\bconst\s+\w+\s*=/,
  /\bdef\s+\w+\s*\(/,
  /^\s*#include\s+<[\w./-]+>/m,
  /\bint\s+main\s*\(/,
  /\bchar\s+\*?\w+\s*(?:\[.*\])?\s*=/,
  /\bpublic\s+class\s+\w+/,
  /\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b/,
  /<html\b|<body\b|<script\b/i,
];
const RUNTIME_LOGIC_MARKERS = [
  /\b(fetch|axios|XMLHttpRequest)\b/,
  /\brouter\.(get|post|put|delete)\b|\bapp\.(get|post|put|delete)\b/i,
  /\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b/,
  /\bmalloc\s*\(|\bfree\s*\(|\bstrcpy\s*\(|\bmemcpy\s*\(/,
  /\bexecve?\s*\(|\bsystem\s*\(/,
  /\bsubprocess\b|\bos\.system\b/,
  /@(?:Get|Post|Put|Delete|RequestMapping)\b/,
  /\buseState\b|\buseReducer\b|\bonSubmit\b|\bonClick\b/,
  /\b<input\b|\b<form\b|\btextarea\b|\bcontenteditable\b/i,
  /\bpassword\b|\bauth\b|\bsession\b|\btoken\b|\bjwt\b/i,
];
const PRESENTATION_ONLY_PATTERNS = [
  /\b(background|color|font-size|margin|padding|display|align-items|justify-content|grid-template-columns)\s*:/i,
  /className\s*=\s*["'{][^"'}`]+["'}]/,
  /<div\b|<section\b|<header\b|<footer\b|<main\b/i,
];
const SUSPICIOUS_TEXT_PATTERNS = [
  /powershell(?:\.exe)?\s+-enc/i,
  /invoke-expression|\biex\b/i,
  /frombase64string\s*\(/i,
  /certutil(?:\.exe)?\s+-urlcache/i,
  /mshta(?:\.exe)?\b/i,
  /regsvr32(?:\.exe)?\b/i,
  /rundll32(?:\.exe)?\b/i,
  /curl\s+[^|\n]+?\|\s*(?:sh|bash)/i,
  /wget\s+[^|\n]+?\|\s*(?:sh|bash)/i,
  /nc\s+-e\b/i,
];
const ARCHIVE_EXTENSIONS = ['.zip', '.jar', '.apk', '.xapk', '.ipa', '.tar', '.tgz', '.tar.gz', '.txz', '.tar.xz'];
const ZIP_ARCHIVE_EXTENSIONS = new Set(['.zip', '.jar', '.apk', '.xapk', '.ipa']);
const ASSET_EXTENSIONS = new Set([
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.webp',
  '.svg',
  '.ico',
  '.mp3',
  '.wav',
  '.ogg',
  '.mp4',
  '.mov',
  '.avi',
  '.ttf',
  '.otf',
  '.woff',
  '.woff2',
  '.map',
  '.fbx',
  '.obj',
  '.blend',
  '.unity',
  '.umap',
  '.uasset',
  '.tmx',
  '.tsx',
]);
const TRIVIAL_BINARY_PATTERNS = [
  /\b(__libc_start_main|__cxa_finalize|_start|main|stdin|stdout|stderr)\b/i,
  /\b(printf|puts|putchar|perror|read|write|fgets|fputs|getchar|exit|abort|memset|memcmp)\b/i,
];
const BINARY_RISK_PATTERNS = [
  { regex: /\b(gets|strcpy|strcat|sprintf|vsprintf|scanf|sscanf|fscanf|vfscanf)\b/i, signal: '위험한 문자열/입력 함수' },
  { regex: /\b(memcpy|memmove|strncpy|strncat|snprintf|vsnprintf)\b/i, signal: '버퍼 조작 함수' },
  { regex: /\b(read|recv|recvfrom|fgets|getdelim|getline)\b/i, signal: '외부 입력 처리' },
  { regex: /\b(malloc|calloc|realloc|free|new|delete|mmap|munmap|VirtualAlloc|HeapAlloc)\b/i, signal: '동적 메모리 처리' },
  { regex: /\b(system|popen|execve?|CreateProcess|ShellExecute|WinExec)\b/i, signal: '명령 실행 경로' },
  { regex: /\b(dlopen|LoadLibrary|GetProcAddress|dlsym)\b/i, signal: '동적 로딩' },
  { regex: /\b(open|openat|fopen|freopen|CreateFile|ReadFile|WriteFile|unlink|remove|rename)\b/i, signal: '파일 시스템 접근' },
];
const BINARY_LOGIC_PATTERNS = [
  { regex: /\b(socket|bind|listen|accept|connect|send|sendto|recv|recvfrom|select|poll|epoll|kqueue)\b/i, signal: '네트워크/IPC 로직' },
  { regex: /\b(http|https|request|response|header|cookie|session|jwt|token|oauth|login|auth|passwd|password)\b/i, signal: '인증/프로토콜 로직' },
  { regex: /\b(sqlite|mysql|postgres|redis|mongo|database|query|select\s+.+from|insert\s+into)\b/i, signal: '데이터 저장/조회 로직' },
  { regex: /\b(json|xml|yaml|toml|protobuf|serialize|deserialize|marshal|unmarshal|parse|parser|decode|encode)\b/i, signal: '파싱/직렬화 로직' },
  { regex: /\b(zip|tar|gzip|inflate|deflate|archive|extract|unpack|upload|download)\b/i, signal: '파일 포맷/압축 처리' },
  { regex: /\b(SSL_|TLS_|BIO_|EVP_|AES_|RSA_|crypto|certificate|x509)\b/i, signal: '암호화/보안 로직' },
  { regex: /\b(menu|choice|command|option|usage:|input:|name:|password:|flag|challenge|score)\b/i, signal: '사용자 상호작용 로직' },
  { regex: /\b(AndroidManifest|Activity|Fragment|Intent|JNI_OnLoad|DexClassLoader)\b/i, signal: '모바일 앱 로직' },
  { regex: /\b(Servlet|JSP|Spring|Controller|RequestMapping|Route|router\.|express|django|flask|fastapi)\b/i, signal: '서비스/백엔드 로직' },
];
const BINARY_PROFILE_RULES = [
  {
    id: 'network-service',
    category: 'service-binary',
    accepted: true,
    minScore: 2,
    reason: '네트워크 요청, 인증, 세션, 라우팅 같은 서비스 로직이 보여 취약점 검토 가치가 있습니다.',
    patterns: [
      /\b(socket|bind|listen|accept|connect|recv|send|http|https|request|response)\b/i,
      /\b(login|auth|token|jwt|cookie|session|header)\b/i,
      /\b(route|handler|controller|endpoint|server)\b/i,
    ],
  },
  {
    id: 'file-parser',
    category: 'parser-binary',
    accepted: true,
    minScore: 2,
    reason: '파일 포맷, 파싱, 직렬화 또는 압축 처리 로직이 보여 취약점 분석 대상이 될 수 있습니다.',
    patterns: [
      /\b(parse|parser|decode|encode|deserialize|serialize|tokenize|lexer|marshal|unmarshal)\b/i,
      /\b(json|xml|yaml|toml|protobuf|sqlite|archive|zip|tar|gzip|inflate|deflate)\b/i,
      /\b(import|export|open|load|save|extract|unpack)\b/i,
    ],
  },
  {
    id: 'stateful-cli',
    category: 'stateful-program',
    accepted: true,
    minScore: 2,
    reason: '상태를 만들고 수정하는 네이티브 프로그램 로직이 보여 취약점 분석이나 조언이 가능합니다.',
    patterns: [
      /\b(add|create|new|edit|update|delete|remove|show|list|view|read)_(note|memo|item|entry|record|msg|message|chunk|user|account)\b/i,
      /\b(note|memo|item|entry|record|chunk|message|account|user)\b/i,
      /\b(index|idx|size|length|content|title|name|menu|choice|select)\b/i,
    ],
  },
  {
    id: 'reverse-challenge',
    category: 'reverse-target',
    accepted: true,
    minScore: 2,
    reason: '리버싱 또는 pwnable 과제 성격의 프로그램 로직이 보여 분석 가치가 있습니다.',
    patterns: [
      /\b(ctf|challenge|dreamhack|pwn|flag|win|sigaction|signal|alarm|seccomp|ptrace)\b/i,
      /\b(shell|\/bin\/sh|execve|system)\b/i,
      /\b(menu|choice|guess|key|secret|password|input)\b/i,
    ],
  },
  {
    id: 'mobile-app',
    category: 'mobile-binary',
    accepted: true,
    minScore: 2,
    reason: '모바일 앱 또는 런타임 로직 신호가 보여 분석 대상으로 볼 수 있습니다.',
    patterns: [
      /\b(AndroidManifest|Activity|Fragment|Intent|DexClassLoader|JNI_OnLoad)\b/i,
      /\b(UIKit|SwiftUI|UIViewController|NSBundle|CFBundle)\b/i,
      /\b(sqlite|sharedpreferences|room|contentprovider)\b/i,
    ],
  },
  {
    id: 'simple-stdio',
    category: 'simple-stdio-binary',
    accepted: false,
    minScore: 2,
    reason: '기본 입출력 위주의 단순 실행 파일로 보여 취약점 리포트나 실질적인 조언을 만들 근거가 부족합니다.',
    patterns: [
      /\b(read|scanf|getchar|printf|puts|putchar|fgets)\b/i,
      /\b(signal:|input:|name:|number:|menu:|choice:|enter)\b/i,
      /\b(main|usage:)\b/i,
    ],
  },
];

function getScreeningMode() {
  const mode = String(process.env.UPLOAD_SCREENING_MODE || 'hybrid').trim().toLowerCase();

  if (mode === 'codex' || mode === 'rules') {
    return mode;
  }

  return 'hybrid';
}

function isLikelyBinary(buffer) {
  if (!buffer.length) {
    return false;
  }

  let suspiciousByteCount = 0;

  for (const value of buffer) {
    if (value === 0) {
      return true;
    }

    if (value < 7 || (value > 14 && value < 32 && value !== 9 && value !== 10 && value !== 13)) {
      suspiciousByteCount += 1;
    }
  }

  return suspiciousByteCount / buffer.length > 0.2;
}

function decodePreview(buffer) {
  return buffer.toString('utf8').replace(/\u0000/g, '').trim();
}

function normalizeFileName(fileName) {
  return String(fileName || '').split(/[\\/]/).pop() || 'upload.txt';
}

export function sanitizeFileName(fileName) {
  const normalized = normalizeFileName(fileName);
  return normalized
    .replace(/[^a-zA-Z0-9._-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 120) || 'upload.txt';
}

function getFileExtension(fileName) {
  return path.extname(normalizeFileName(fileName)).toLowerCase();
}

function matchesArchiveExtension(fileName) {
  const lowered = normalizeFileName(fileName).toLowerCase();
  return ARCHIVE_EXTENSIONS.find((extension) => lowered.endsWith(extension)) || '';
}

function collectProgramSignals(fileName, previewText) {
  const loweredName = normalizeFileName(fileName).toLowerCase();
  const signals = [];

  if (PROJECT_FILENAMES.has(loweredName)) {
    signals.push(`프로젝트 파일(${loweredName})`);
  }

  if (TEXT_SOURCE_EXTENSIONS.has(getFileExtension(fileName))) {
    signals.push(`소스 확장자(${getFileExtension(fileName) || loweredName})`);
  }

  APP_MARKERS.forEach(({ regex, signal }) => {
    if (regex.test(previewText)) {
      signals.push(signal);
    }
  });

  return Array.from(new Set(signals));
}

function hasGenericCodeShape(previewText) {
  return GENERIC_CODE_MARKERS.some((pattern) => pattern.test(previewText));
}

function detectSuspiciousPatterns(previewText) {
  return SUSPICIOUS_TEXT_PATTERNS.filter((pattern) => pattern.test(previewText));
}

function hasRuntimeLogic(previewText) {
  return RUNTIME_LOGIC_MARKERS.some((pattern) => pattern.test(previewText));
}

function isLikelyPresentationOnly({ fileName, previewText }) {
  const extension = getFileExtension(fileName);

  if (STYLE_EXTENSIONS.has(extension)) {
    return true;
  }

  if (!MARKUP_EXTENSIONS.has(extension) && !['.jsx', '.tsx', '.vue', '.svelte', '.astro'].includes(extension)) {
    return false;
  }

  const presentationSignals = PRESENTATION_ONLY_PATTERNS.some((pattern) => pattern.test(previewText));
  return presentationSignals && !hasRuntimeLogic(previewText);
}

function collectArchiveSignals(entryNames) {
  const signals = [];

  entryNames.forEach((entryName) => {
    const baseName = path.posix.basename(String(entryName || '').toLowerCase());

    if (PROJECT_FILENAMES.has(baseName)) {
      signals.push(`프로젝트 파일(${baseName})`);
    }

    const extension = path.extname(baseName).toLowerCase();
    if (TEXT_SOURCE_EXTENSIONS.has(extension)) {
      signals.push(`소스 확장자(${extension})`);
    }
  });

  return Array.from(new Set(signals));
}

function collectPatternSignals(text, patterns) {
  return patterns
    .filter(({ regex }) => regex.test(text))
    .map(({ signal }) => signal);
}

function inferBinaryProgramProfile(evidenceText) {
  const scoredProfiles = BINARY_PROFILE_RULES
    .map((rule) => {
      const score = rule.patterns.reduce((count, pattern) => count + (pattern.test(evidenceText) ? 1 : 0), 0);
      return { ...rule, score };
    })
    .filter((rule) => rule.score >= rule.minScore)
    .sort((left, right) => right.score - left.score);

  return scoredProfiles[0] || null;
}

function collectInterestingDisassemblyLines(disassemblyText) {
  const lines = String(disassemblyText || '')
    .split('\n')
    .map((line) => line.trimEnd());

  if (!lines.length) {
    return [];
  }

  const selected = [];
  let currentLabel = '';
  let previousBlank = true;

  for (const line of lines) {
    const trimmed = line.trim();

    if (!trimmed) {
      previousBlank = true;
      continue;
    }

    if (/^[0-9a-f]+ <[^>]+>:$/.test(trimmed)) {
      currentLabel = trimmed;
      if (!selected.includes(trimmed)) {
        selected.push(trimmed);
      }
      previousBlank = false;
      continue;
    }

    if (/:\s+(call|jmp|je|jne|jg|jge|jl|jle|ja|jb|cmp|test|lea|movzx|movsx|syscall)\b/i.test(trimmed)) {
      if (currentLabel && selected[selected.length - 1] !== currentLabel) {
        selected.push(currentLabel);
      }
      selected.push(trimmed);
      previousBlank = false;
      if (selected.length >= 180) {
        break;
      }
      continue;
    }

    if (previousBlank && /^[0-9a-f]+:/.test(trimmed) && selected.length < 80) {
      if (currentLabel && selected[selected.length - 1] !== currentLabel) {
        selected.push(currentLabel);
      }
      selected.push(trimmed);
      previousBlank = false;
    }
  }

  return selected.slice(0, 180);
}

function hasArchiveSuspiciousEntries(entryNames) {
  return entryNames.some((entryName) => HARD_REJECT_EXTENSIONS.has(path.extname(String(entryName || '')).toLowerCase()));
}

function analyzeArchiveEntries(entryNames) {
  const summary = {
    logicFiles: 0,
    styleFiles: 0,
    markupFiles: 0,
    assetFiles: 0,
    projectFiles: 0,
  };

  entryNames.forEach((entryName) => {
    const baseName = path.posix.basename(String(entryName || '').toLowerCase());
    const extension = path.extname(baseName).toLowerCase();

    if (PROJECT_FILENAMES.has(baseName)) {
      summary.projectFiles += 1;
    }

    if (LOGIC_SOURCE_EXTENSIONS.has(extension)) {
      summary.logicFiles += 1;
      return;
    }

    if (STYLE_EXTENSIONS.has(extension)) {
      summary.styleFiles += 1;
      return;
    }

    if (MARKUP_EXTENSIONS.has(extension) || ['.jsx', '.tsx', '.vue', '.svelte', '.astro'].includes(extension)) {
      summary.markupFiles += 1;
      return;
    }

    if (ASSET_EXTENSIONS.has(extension)) {
      summary.assetFiles += 1;
    }
  });

  return summary;
}

function shouldInspectArchiveEntry(entryName) {
  const normalized = String(entryName || '').trim();

  if (!normalized || normalized.endsWith('/')) {
    return false;
  }

  const baseName = path.posix.basename(normalized).toLowerCase();
  const extension = path.extname(baseName).toLowerCase();

  if (ASSET_EXTENSIONS.has(extension)) {
    return false;
  }

  if (PROJECT_FILENAMES.has(baseName) || TEXT_SOURCE_EXTENSIONS.has(extension)) {
    return true;
  }

  return extension === '' && /dockerfile|makefile|readme|flag|run|start|server|main|app|chall|solve/i.test(baseName);
}

function shouldInspectArchiveBinaryEntry(entryName) {
  const normalized = String(entryName || '').trim();

  if (!normalized || normalized.endsWith('/')) {
    return false;
  }

  const baseName = path.posix.basename(normalized).toLowerCase();
  const extension = path.extname(baseName).toLowerCase();

  if (ASSET_EXTENSIONS.has(extension) || HARD_REJECT_EXTENSIONS.has(extension)) {
    return false;
  }

  return REVIEWABLE_BINARY_EXTENSIONS.has(extension) || extension === '';
}

async function listArchiveEntries(archivePath, archiveExtension) {
  if (ZIP_ARCHIVE_EXTENSIONS.has(archiveExtension)) {
    const { stdout } = await execFileAsync('unzip', ['-Z1', archivePath], {
      timeout: ARCHIVE_LISTING_TIMEOUT_MS,
      maxBuffer: 1024 * 1024,
    });

    return stdout.split('\n').map((line) => line.trim()).filter(Boolean).slice(0, ARCHIVE_ENTRY_LIMIT);
  }

  const { stdout } = await execFileAsync('tar', ['-tf', archivePath], {
    timeout: ARCHIVE_LISTING_TIMEOUT_MS,
    maxBuffer: 1024 * 1024,
  });

  return stdout.split('\n').map((line) => line.trim()).filter(Boolean).slice(0, ARCHIVE_ENTRY_LIMIT);
}

async function readArchiveEntryPreview(archivePath, archiveExtension, entryName) {
  if (ZIP_ARCHIVE_EXTENSIONS.has(archiveExtension)) {
    const { stdout } = await execFileAsync('unzip', ['-p', archivePath, entryName], {
      timeout: ARCHIVE_LISTING_TIMEOUT_MS,
      maxBuffer: ARCHIVE_PREVIEW_BYTE_LIMIT * 4,
      encoding: 'buffer',
    });

    return Buffer.from(stdout).subarray(0, ARCHIVE_PREVIEW_BYTE_LIMIT);
  }

  const { stdout } = await execFileAsync('tar', ['-xOf', archivePath, entryName], {
    timeout: ARCHIVE_LISTING_TIMEOUT_MS,
    maxBuffer: ARCHIVE_PREVIEW_BYTE_LIMIT * 4,
    encoding: 'buffer',
  });

  return Buffer.from(stdout).subarray(0, ARCHIVE_PREVIEW_BYTE_LIMIT);
}

async function extractArchiveEntryToFile(archivePath, archiveExtension, entryName, outputPath) {
  await new Promise((resolve, reject) => {
    const child = ZIP_ARCHIVE_EXTENSIONS.has(archiveExtension)
      ? spawn('unzip', ['-p', archivePath, entryName], { stdio: ['ignore', 'pipe', 'pipe'] })
      : spawn('tar', ['-xOf', archivePath, entryName], { stdio: ['ignore', 'pipe', 'pipe'] });
    const outputStream = fs.createWriteStream(outputPath);
    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      reject(new Error('archive-extract-timeout'));
    }, ARCHIVE_LISTING_TIMEOUT_MS);
    let stderr = '';

    child.stdout.pipe(outputStream);
    child.stderr.on('data', (chunk) => {
      stderr += String(chunk);
    });

    child.on('error', (error) => {
      clearTimeout(timer);
      outputStream.destroy();
      reject(error);
    });

    outputStream.on('error', (error) => {
      clearTimeout(timer);
      child.kill('SIGTERM');
      reject(error);
    });

    child.on('close', (code) => {
      clearTimeout(timer);

      if (code === 0) {
        resolve();
        return;
      }

      reject(new Error(stderr || `archive-extract-${code}`));
    });
  });
}

function isElfDescription(description) {
  return /\bELF\b/i.test(description);
}

function isPeDescription(description) {
  return /\bPE32\b|\bPE32\+\b|\bfor MS Windows\b|\bMS[- ]Windows\b/i.test(description);
}

function isJavaClassDescription(description) {
  return /\bcompiled Java class data\b/i.test(description);
}

function isDexDescription(description) {
  return /\bDalvik dex file\b|\bAndroid dex\b/i.test(description);
}

function isWasmDescription(description) {
  return /\bWebAssembly\b|\bwasm\b/i.test(description);
}

function isMachODescription(description) {
  return /\bMach-O\b/i.test(description);
}

function getBinaryKind(description) {
  if (isElfDescription(description)) return 'ELF';
  if (isPeDescription(description)) return 'PE';
  if (isJavaClassDescription(description)) return 'JavaClass';
  if (isDexDescription(description)) return 'DEX';
  if (isWasmDescription(description)) return 'WASM';
  if (isMachODescription(description)) return 'MachO';
  return '';
}

async function inspectBinaryPath({ displayName, tempPath }) {
  try {
    const { stdout: fileStdout } = await execFileAsync('file', ['-b', tempPath], {
      timeout: ARCHIVE_LISTING_TIMEOUT_MS,
      maxBuffer: 128 * 1024,
    });
    const fileDescription = String(fileStdout || '').trim();
    const binaryKind = getBinaryKind(fileDescription);

    if (!binaryKind) {
      return null;
    }

    const blocks = [
      `BINARY FILE: ${displayName}`,
      `TYPE: ${fileDescription}`,
    ];
    const symbolSamples = [];
    const symbolNames = [];
    const stringSamples = [];
    const disassemblySamples = [];

    try {
      const { stdout } = await execFileAsync('objdump', ['-f', tempPath], {
        timeout: ARCHIVE_LISTING_TIMEOUT_MS,
        maxBuffer: 512 * 1024,
      });
      if (stdout) {
        blocks.push(`OBJDUMP HEADER:\n${String(stdout).trim().slice(0, 3000)}`);
      }
    } catch {}

    try {
      const { stdout } = await execFileAsync('objdump', ['-d', '-M', 'intel', '--no-show-raw-insn', tempPath], {
        timeout: ARCHIVE_LISTING_TIMEOUT_MS,
        maxBuffer: 2 * 1024 * 1024,
      });
      const interestingLines = collectInterestingDisassemblyLines(stdout);

      if (interestingLines.length) {
        disassemblySamples.push(...interestingLines);
        blocks.push(`DISASSEMBLY SAMPLE:\n${interestingLines.join('\n').slice(0, 5000)}`);
      }
    } catch {}

    try {
      if (binaryKind === 'ELF') {
        const { stdout } = await execFileAsync('readelf', ['-h', tempPath], {
          timeout: ARCHIVE_LISTING_TIMEOUT_MS,
          maxBuffer: 512 * 1024,
        });
        if (stdout) {
          blocks.push(`READELF HEADER:\n${String(stdout).trim().slice(0, 3000)}`);
        }

        const { stdout: symbolStdout } = await execFileAsync('readelf', ['-Ws', tempPath], {
          timeout: ARCHIVE_LISTING_TIMEOUT_MS,
          maxBuffer: 1024 * 1024,
        });
        const symbolLines = String(symbolStdout || '')
          .split('\n')
          .map((line) => line.trim())
          .filter(Boolean)
          .filter((line) => /\bFUNC\b|\bOBJECT\b/.test(line))
          .slice(0, 120);

        if (symbolLines.length) {
          symbolSamples.push(...symbolLines);
          symbolNames.push(...symbolLines.map((line) => line.split(/\s+/).at(-1) || '').filter(Boolean));
          blocks.push(`ELF SYMBOLS:\n${symbolLines.join('\n').slice(0, 3500)}`);
        }
      } else if (binaryKind === 'PE') {
        const { stdout } = await execFileAsync('objdump', ['-p', tempPath], {
          timeout: ARCHIVE_LISTING_TIMEOUT_MS,
          maxBuffer: 512 * 1024,
        });
        if (stdout) {
          blocks.push(`PE HEADER:\n${String(stdout).trim().slice(0, 3000)}`);
        }

        const importLines = String(stdout || '')
          .split('\n')
          .map((line) => line.trim())
          .filter(Boolean)
          .filter((line) => /DLL Name:|Hint\/Ord|[A-Za-z0-9_]+\.dll/i.test(line))
          .slice(0, 120);

        if (importLines.length) {
          symbolSamples.push(...importLines);
          symbolNames.push(
            ...importLines
              .map((line) => line.replace(/^.*\]\s*/, '').replace(/^DLL Name:\s*/i, '').trim())
              .filter(Boolean)
          );
        }
      }
    } catch {}

    try {
      const { stdout } = await execFileAsync('strings', ['-n', '6', tempPath], {
        timeout: ARCHIVE_LISTING_TIMEOUT_MS,
        maxBuffer: 1024 * 1024,
      });
      const lines = String(stdout || '')
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean)
        .filter((line) => line.length <= 200)
        .slice(0, 80);

      if (lines.length) {
        stringSamples.push(...lines);
        blocks.push(`STRINGS SAMPLE:\n${lines.join('\n')}`);
      }
    } catch {}

    const evidenceText = blocks.join('\n\n');
    const classificationText = [
      ...symbolNames,
      ...stringSamples,
      ...disassemblySamples,
    ].join('\n');
    const riskSignals = collectPatternSignals(classificationText, BINARY_RISK_PATTERNS);
    const logicSignals = collectPatternSignals(classificationText, BINARY_LOGIC_PATTERNS);
    const strongLogicSignals = logicSignals.filter((signal) => signal !== '사용자 상호작용 로직');
    const inferredProfile = inferBinaryProgramProfile(classificationText);
    const suspiciousSignals = detectSuspiciousPatterns(classificationText).map((pattern) => pattern.toString());
    const trivialMatches = TRIVIAL_BINARY_PATTERNS.filter((pattern) => pattern.test(classificationText)).map((pattern) => pattern.toString());
    const uniqueSignals = Array.from(new Set([
      ...riskSignals,
      ...logicSignals,
      ...(inferredProfile ? [inferredProfile.id] : []),
    ]));
    const hasMeaningfulLogic = strongLogicSignals.length >= 1;
    const hasStrongRiskSurface = riskSignals.length >= 3 || (riskSignals.length >= 1 && hasMeaningfulLogic);
    const isTrivialBinary = !hasMeaningfulLogic
      && !hasStrongRiskSurface
      && inferredProfile?.id !== 'reverse-challenge'
      && suspiciousSignals.length === 0
      && trivialMatches.length > 0;

    if (isTrivialBinary) {
      return {
        accepted: false,
        category: 'trivial-binary',
        reason: `${binaryKind} 바이너리이지만 기본 입출력/런타임 심볼 정도만 보여 취약점 분석 리포트나 조언을 만들 근거가 부족합니다.`,
        source: 'rules',
        hardReject: false,
        confidence: 'high',
        previewText: evidenceText.slice(0, 12000),
        signals: [`${binaryKind} binary`, ...uniqueSignals],
      };
    }

    if (inferredProfile && !inferredProfile.accepted) {
      return {
        accepted: false,
        category: inferredProfile.category,
        reason: inferredProfile.reason,
        source: 'rules',
        hardReject: false,
        confidence: 'high',
        previewText: evidenceText.slice(0, 12000),
        signals: [`${binaryKind} binary`, ...uniqueSignals],
      };
    }

    const profileSupportsAcceptance = Boolean(inferredProfile?.accepted);

    if (!profileSupportsAcceptance) {
      return {
        accepted: false,
        category: 'unclassified-binary',
        reason: `${binaryKind} 바이너리 덤프에서 이 파일이 구체적으로 어떤 프로그램인지 충분히 특정하지 못했습니다. 기본 입출력이나 일부 위험 함수만으로는 분석 가치가 있다고 보지 않습니다.`,
        source: 'rules',
        hardReject: false,
        confidence: 'high',
        previewText: evidenceText.slice(0, 12000),
        signals: [`${binaryKind} binary`, ...uniqueSignals],
        suspiciousSignals,
        symbolSamples: symbolSamples.slice(0, 60),
      };
    }

    const accepted = true;

    return {
      accepted,
      category: inferredProfile.category,
      reason: inferredProfile.reason,
      source: 'rules',
      hardReject: false,
      confidence: 'high',
      previewText: evidenceText.slice(0, 12000),
      signals: [`${binaryKind} binary`, ...uniqueSignals],
      suspiciousSignals,
      symbolSamples: symbolSamples.slice(0, 60),
    };
  } catch {
    return null;
  }
}

async function inspectBinaryFile({ fileName, file }) {
  if (!file) {
    return null;
  }

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'phase-upload-binary-'));
  const tempPath = path.join(tempDir, sanitizeFileName(fileName));

  try {
    fs.writeFileSync(tempPath, Buffer.from(await file.arrayBuffer()));
    return await inspectBinaryPath({ displayName: fileName, tempPath });
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

async function collectArchivePreviewText(archivePath, archiveExtension, entryNames) {
  const previewEntries = entryNames.filter(shouldInspectArchiveEntry).slice(0, ARCHIVE_PREVIEW_FILE_LIMIT);
  const blocks = [];

  for (const entryName of previewEntries) {
    try {
      const previewBuffer = await readArchiveEntryPreview(archivePath, archiveExtension, entryName);

      if (!previewBuffer.length || isLikelyBinary(previewBuffer)) {
        continue;
      }

      const previewText = decodePreview(previewBuffer);

      if (!previewText) {
        continue;
      }

      blocks.push(`FILE: ${entryName}\n${previewText.slice(0, 1200)}`);
    } catch {
      continue;
    }
  }

  return blocks.join('\n\n');
}

async function collectArchiveBinaryPreview(archivePath, archiveExtension, entryNames) {
  const binaryEntries = entryNames.filter(shouldInspectArchiveBinaryEntry).slice(0, BINARY_PREVIEW_FILE_LIMIT);
  const blocks = [];

  for (const entryName of binaryEntries) {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'phase-archive-binary-'));
    const tempPath = path.join(tempDir, sanitizeFileName(entryName));

    try {
      await extractArchiveEntryToFile(archivePath, archiveExtension, entryName, tempPath);
      const result = await inspectBinaryPath({ displayName: entryName, tempPath });

      if (!result?.previewText) {
        continue;
      }

      blocks.push(result.previewText);
    } catch {
      continue;
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  }

  return blocks.join('\n\n');
}

async function inspectArchiveFile({ fileName, file }) {
  const archiveExtension = matchesArchiveExtension(fileName);

  if (!archiveExtension || !file) {
    return null;
  }

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'phase-upload-archive-'));
  const tempPath = path.join(tempDir, sanitizeFileName(fileName));

  try {
    fs.writeFileSync(tempPath, Buffer.from(await file.arrayBuffer()));
    const entryNames = await listArchiveEntries(tempPath, archiveExtension);

    if (!entryNames.length) {
      return {
        accepted: false,
        category: 'empty-archive',
        reason: '압축 파일 내부에 분석 가능한 파일이 없습니다.',
        source: 'rules',
        hardReject: true,
      };
    }

    const signals = collectArchiveSignals(entryNames);
    const previewText = await collectArchivePreviewText(tempPath, archiveExtension, entryNames);
    const binaryPreviewText = await collectArchiveBinaryPreview(tempPath, archiveExtension, entryNames);
    const entrySummary = analyzeArchiveEntries(entryNames);
    const hasLogic = entrySummary.logicFiles > 0
      || entrySummary.projectFiles > 0
      || hasRuntimeLogic(previewText)
      || Boolean(binaryPreviewText);
    const presentationOnly = !hasLogic
      && entrySummary.assetFiles >= 0
      && (entrySummary.styleFiles > 0 || entrySummary.markupFiles > 0);

    if (!signals.length && !previewText && !binaryPreviewText) {
      return {
        accepted: false,
        category: 'not-an-app-archive',
        reason: '압축 파일 내부에서 취약점 분석에 의미 있는 소스 코드나 프로젝트 파일을 찾지 못했습니다.',
        source: 'rules',
        hardReject: false,
        confidence: 'high',
        previewText: entryNames.slice(0, 200).join('\n'),
        signals: [],
      };
    }

    if (presentationOnly) {
      return {
        accepted: false,
        category: 'presentation-only-archive',
        reason: '압축 파일이 프론트 자산이나 마크업 위주로 보이며 취약점 리포트가 나올 만한 로직이 부족합니다.',
        source: 'rules',
        hardReject: false,
        confidence: 'high',
        previewText,
        signals,
      };
    }

    if (hasArchiveSuspiciousEntries(entryNames) && !signals.length && !previewText && !binaryPreviewText) {
      return {
        accepted: false,
        category: 'suspicious-archive',
        reason: '압축 파일 내부에 실행 파일이 포함되어 있어 업로드를 차단했습니다.',
        source: 'rules',
        hardReject: true,
      };
    }

    return {
      accepted: hasLogic,
      category: hasLogic ? 'analysis-archive-candidate' : 'uncertain-archive',
      reason: hasLogic
        ? '압축 파일 내부에서 취약점 분석 후보가 될 수 있는 소스 또는 프로젝트 구성을 확인했습니다.'
        : '압축 파일 내부에 코드가 일부 있으나, 실제 취약점 분석 가치가 충분한지는 추가 판단이 필요합니다.',
      source: 'rules',
      hardReject: false,
      confidence: hasLogic ? 'high' : 'low',
      previewText: [
        'ARCHIVE ENTRIES:',
        entryNames.slice(0, 200).join('\n'),
        '',
        'ARCHIVE PREVIEW:',
        previewText,
        '',
        'ARCHIVE BINARY PREVIEW:',
        binaryPreviewText,
      ].join('\n'),
      signals,
    };
  } catch {
    return {
      accepted: false,
      category: 'unreadable-archive',
      reason: '압축 파일 목록을 읽지 못해 업로드를 차단했습니다.',
      source: 'rules',
      hardReject: true,
    };
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

async function buildHeuristicScreeningResult({ fileName, previewBuffer, file }) {
  const extension = getFileExtension(fileName);
  const safeFileName = normalizeFileName(fileName);

  if (!safeFileName) {
    return {
      accepted: false,
      category: 'invalid',
      reason: '파일 이름을 확인할 수 없어 업로드를 중단했습니다.',
      source: 'rules',
      hardReject: true,
    };
  }

  if (HARD_REJECT_EXTENSIONS.has(extension)) {
    return {
      accepted: false,
      category: 'suspicious',
      reason: '실행 파일 또는 설치 패키지는 분석 대상 업로드에서 제외합니다.',
      source: 'rules',
      hardReject: true,
      confidence: 'high',
    };
  }

  if (!previewBuffer.length) {
    return {
      accepted: false,
      category: 'empty',
      reason: '비어 있는 파일은 업로드할 수 없습니다.',
      source: 'rules',
      hardReject: true,
      confidence: 'high',
    };
  }

  if (isLikelyBinary(previewBuffer)) {
    const binaryInspection = await inspectBinaryFile({ fileName, file });

    if (binaryInspection) {
      return binaryInspection;
    }

    return {
      accepted: false,
      category: 'binary',
      reason: '텍스트 기반 소스 파일이 아니어서 분석 대상에서 제외했습니다.',
      source: 'rules',
      hardReject: true,
      confidence: 'high',
    };
  }

  const previewText = decodePreview(previewBuffer);
  const suspiciousMatches = detectSuspiciousPatterns(previewText);

  if (suspiciousMatches.length >= 2) {
    return {
      accepted: false,
      category: 'suspicious',
      reason: '악성 스크립트 또는 드로퍼로 보이는 패턴이 감지돼 업로드를 차단했습니다.',
      source: 'rules',
      hardReject: true,
      confidence: 'high',
      suspiciousSignals: suspiciousMatches.map((pattern) => pattern.toString()),
    };
  }

  const signals = collectProgramSignals(fileName, previewText);
  const genericCodeShape = hasGenericCodeShape(previewText);
  const hasLogic = LOGIC_SOURCE_EXTENSIONS.has(extension) || hasRuntimeLogic(previewText);
  const presentationOnly = isLikelyPresentationOnly({ fileName, previewText });
  const accepted = signals.length > 0 || genericCodeShape;

  if (presentationOnly) {
    return {
      accepted: false,
      category: 'presentation-only',
      reason: '스타일이나 마크업 위주 파일로 보이며 취약점 리포트가 나올 만한 로직이 부족합니다.',
      source: 'rules',
      hardReject: false,
      confidence: 'high',
      signals,
      previewText,
    };
  }

  return {
    accepted: accepted || hasLogic,
    category: accepted || hasLogic ? 'application-source' : 'not-an-app',
    reason: accepted || hasLogic
      ? '웹 또는 앱 분석 대상으로 볼 수 있는 소스 코드/설정 파일로 판단했습니다.'
      : '웹 또는 앱 소스 코드로 볼 근거가 부족해 업로드하지 않았습니다.',
    source: 'rules',
    hardReject: false,
    confidence: accepted || hasLogic ? 'high' : 'low',
    signals,
    previewText,
  };
}

function extractJsonObject(text) {
  const raw = String(text || '').trim();
  const start = raw.indexOf('{');
  const end = raw.lastIndexOf('}');

  if (start === -1 || end === -1 || end <= start) {
    return null;
  }

  try {
    return JSON.parse(raw.slice(start, end + 1));
  } catch {
    return null;
  }
}

const POSITIVE_REASON_PATTERNS = [
  /\bsuitable\b/i,
  /\bworth\b/i,
  /\bplausible\b/i,
  /\banaly[sz]able\b/i,
  /\breverse[- ]engineering\b/i,
  /\bvulnerability analysis\b/i,
  /\bsecurity-relevant\b/i,
  /\bmeaningful (?:logic|program behavior)\b/i,
  /\bcan be accepted\b/i,
  /\b수용 가능\b/i,
  /\b허용 가능\b/i,
  /\b분석 (?:가치|가능)\b/i,
];

const NEGATIVE_REASON_PATTERNS = [
  /\breject\b/i,
  /\bnot suitable\b/i,
  /\bnot worth\b/i,
  /\bno meaningful logic\b/i,
  /\bexclude\b/i,
  /\b차단\b/i,
  /\b제외\b/i,
];

function classifyReasonTone(reason) {
  const text = String(reason || '').trim();

  if (!text) {
    return 'neutral';
  }

  const positive = POSITIVE_REASON_PATTERNS.some((pattern) => pattern.test(text));
  const negative = NEGATIVE_REASON_PATTERNS.some((pattern) => pattern.test(text));

  if (positive && !negative) {
    return 'positive';
  }

  if (negative && !positive) {
    return 'negative';
  }

  if (positive) {
    return 'positive';
  }

  return 'neutral';
}

async function screenWithCodexExec({ fileName, contentType, previewText, heuristic }) {
  if (!String(process.env.CODEX_HOME || process.env.HOME || '').trim()) {
    return null;
  }

  const prompt = [
    'You classify uploaded files for a vulnerability-analysis product.',
    'Accept uploads that are likely to contain vulnerability-prone or security-relevant logic worth reporting on.',
    'This includes backend services, web apps with meaningful logic, mobile apps, native C/C++ programs, Dockerized labs, PoCs, exploit practice projects, CTF bundles with analyzable logic, and reverse-engineering targets when a rough dump shows meaningful program behavior.',
    'Infer what kind of program it is first, such as service/backend, parser/decoder, stateful CLI tool, reverse-engineering target, mobile app payload, or trivial stdio demo.',
    'For binaries, rely on the disassembly sample to infer rough program behavior. Do not classify a binary as meaningful only from symbol names or libc imports.',
    'If the disassembly only shows basic prompt-printing and input-reading with no state management, parser behavior, protocol handling, storage, command execution, or challenge-specific logic, reject it as a trivial demo binary.',
    'Do not accept something merely because it says CTF or contains helper binaries. The upload should contain code or configuration where vulnerabilities, insecure patterns, or exploit-relevant logic could realistically be discussed in a report.',
    'Reject trivial binaries that only expose startup/basic I/O indicators such as read, write, printf, puts, or libc boilerplate without stronger evidence of parser, protocol, auth, storage, memory-management, command-execution, or application logic.',
    'Reject uploads that are mostly pure assets or presentation-only content, such as image files, game map files, media, documents, or frontend-only styling/markup bundles with no meaningful logic.',
    'If an archive contains code plus helper files like libc, ld-linux, run scripts, Docker assets, PoC scripts, APK/XAPK payloads, or Java archives, judge based on the presence of analyzable code or reverseable program behavior, not the helper files alone.',
    'Respond with JSON only.',
    '{"accepted":boolean,"category":string,"reason":string,"suspicious":boolean}',
    '',
    JSON.stringify({
      fileName,
      contentType,
      heuristicAccepted: heuristic.accepted,
      heuristicReason: heuristic.reason,
      heuristicSignals: heuristic.signals || [],
      previewText: String(previewText || '').slice(0, CODEX_PREVIEW_CHAR_LIMIT),
    }),
  ].join('\n');

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'phase-codex-upload-'));
  const outputFile = path.join(tempDir, 'last-message.txt');
  const args = [
    'exec',
    '--skip-git-repo-check',
    '--sandbox',
    'read-only',
    '--color',
    'never',
    '--ephemeral',
    '--output-last-message',
    outputFile,
    '-C',
    process.cwd(),
  ];

  if (process.env.UPLOAD_CODEX_MODEL) {
    args.push('--model', process.env.UPLOAD_CODEX_MODEL);
  }

  args.push('-');

  try {
    await new Promise((resolve, reject) => {
      const child = spawn('codex', args, {
        cwd: process.cwd(),
        stdio: ['pipe', 'pipe', 'pipe'],
        env: process.env,
      });
      const timeoutMs = Number(process.env.UPLOAD_CODEX_TIMEOUT_MS || 20000);
      const timer = setTimeout(() => {
        child.kill('SIGTERM');
        reject(new Error('codex-timeout'));
      }, timeoutMs);

      child.stdin.write(prompt);
      child.stdin.end();

      child.on('error', (error) => {
        clearTimeout(timer);
        reject(error);
      });

      child.on('close', (code) => {
        clearTimeout(timer);

        if (code === 0) {
          resolve();
          return;
        }

        reject(new Error(`codex-exit-${code}`));
      });
    });
    const parsed = extractJsonObject(fs.readFileSync(outputFile, 'utf8'));

    if (!parsed || typeof parsed.accepted !== 'boolean') {
      return null;
    }

    const reason = String(parsed.reason || heuristic.reason);
    const tone = classifyReasonTone(reason);

    if ((parsed.accepted && tone === 'negative') || (!parsed.accepted && tone === 'positive')) {
      return {
        ...heuristic,
        reason: heuristic.reason,
      };
    }

    return {
      accepted: parsed.accepted && !parsed.suspicious,
      category: String(parsed.category || 'application-source'),
      reason,
      source: 'codex',
      suspicious: Boolean(parsed.suspicious),
      hardReject: false,
      confidence: 'low',
    };
  } catch {
    return null;
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

export async function screenUploadedFile({ fileName, contentType, previewBuffer, file }) {
  const archiveResult = await inspectArchiveFile({
    fileName,
    file,
  });

  if (archiveResult) {
    const mode = getScreeningMode();

    if (archiveResult.hardReject || mode === 'rules') {
      return archiveResult;
    }

    if (archiveResult.confidence === 'high') {
      return archiveResult;
    }

    const codexArchiveResult = await screenWithCodexExec({
      fileName,
      contentType,
      previewText: archiveResult.previewText || '',
      heuristic: archiveResult,
    });

    if (codexArchiveResult) {
      return codexArchiveResult;
    }

    return archiveResult;
  }

  const heuristic = await buildHeuristicScreeningResult({ fileName, previewBuffer, file });
  const mode = getScreeningMode();

  if (heuristic.hardReject || mode === 'rules') {
    return heuristic;
  }

  if (heuristic.confidence === 'high') {
    return heuristic;
  }

  const codexResult = await screenWithCodexExec({
    fileName,
    contentType,
    previewText: heuristic.previewText || decodePreview(previewBuffer),
    heuristic,
  });

  if (codexResult) {
    return codexResult;
  }

  return heuristic;
}

export function ensureUploadRoot() {
  fs.mkdirSync(UPLOAD_ROOT_DIR, { recursive: true });
  return UPLOAD_ROOT_DIR;
}

export function getUploadDirectorySize(directoryPath = UPLOAD_ROOT_DIR) {
  if (!fs.existsSync(directoryPath)) {
    return 0n;
  }

  const entries = fs.readdirSync(directoryPath, { withFileTypes: true });

  return entries.reduce((total, entry) => {
    const entryPath = path.join(directoryPath, entry.name);

    if (entry.isDirectory()) {
      return total + getUploadDirectorySize(entryPath);
    }

    if (entry.isFile()) {
      return total + BigInt(fs.statSync(entryPath).size);
    }

    return total;
  }, 0n);
}

export function toDisplayBytes(value) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let amount = Number(value);
  let unitIndex = 0;

  while (amount >= 1024 && unitIndex < units.length - 1) {
    amount /= 1024;
    unitIndex += 1;
  }

  return `${amount.toFixed(amount >= 10 || unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

export async function readFilePreview(file) {
  const previewBlob = typeof file.slice === 'function' ? file.slice(0, PREVIEW_BYTE_LIMIT) : file;
  return Buffer.from(await previewBlob.arrayBuffer());
}

export async function saveUploadedFile({ userId, file, originalName }) {
  ensureUploadRoot();

  const userDirectory = path.join(UPLOAD_ROOT_DIR, `user-${userId}`);
  fs.mkdirSync(userDirectory, { recursive: true });

  const safeFileName = sanitizeFileName(originalName);
  const storedFileName = `${Date.now()}-${crypto.randomUUID().slice(0, 8)}-${safeFileName}`;
  const absolutePath = path.join(userDirectory, storedFileName);
  const relativePath = path.relative(process.cwd(), absolutePath).split(path.sep).join('/');
  const buffer = Buffer.from(await file.arrayBuffer());

  fs.writeFileSync(absolutePath, buffer);

  return {
    absolutePath,
    relativePath,
    storedFileName,
    size: buffer.length,
  };
}
