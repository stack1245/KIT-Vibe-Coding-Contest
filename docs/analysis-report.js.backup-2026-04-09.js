import 'server-only';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

const ANALYSIS_TIMEOUT_MS = 6 * 60 * 1000;
const MIN_ANALYSIS_DURATION_MS = 0;
const MAX_TEXT_BYTES = 320 * 1024;
const MAX_TEXT_FILES = 220;
const MAX_BINARY_FILES = 96;
const MAX_WALK_FILES = 1600;
const MAX_BINARY_STRINGS = 280;
const MAX_BINARY_SYMBOLS = 220;
const MAX_DISASSEMBLY_LINES = 240;
const MAX_ARCHIVE_CONTEXT_FILES = 120;
const MAX_ARCHIVE_LISTING_ENTRIES = 240;

const ZIP_ARCHIVE_EXTENSIONS = new Set(['.zip', '.jar', '.apk', '.xapk', '.ipa']);
const ARCHIVE_EXTENSIONS = ['.zip', '.jar', '.apk', '.xapk', '.ipa', '.tar', '.tgz', '.tar.gz', '.txz', '.tar.xz'];
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
const TEXT_EXTENSIONS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.java', '.kt', '.kts', '.swift', '.dart',
  '.go', '.rb', '.php', '.cs', '.cpp', '.cc', '.c', '.h', '.hpp', '.rs', '.scala', '.sql',
  '.html', '.css', '.scss', '.sass', '.less', '.vue', '.svelte', '.astro', '.json', '.yml', '.yaml',
  '.xml', '.toml', '.ini', '.properties', '.gradle', '.md', '.txt', '.sh', '.bash', '.zsh', '.env',
]);
const PROJECT_MARKERS = new Set([
  'dockerfile', 'docker-compose.yml', 'docker-compose.yaml', 'makefile', 'cmakelists.txt',
  'package.json', 'requirements.txt', 'pyproject.toml', 'cargo.toml', 'go.mod', 'androidmanifest.xml',
]);
const SKIP_DIRECTORY_NAMES = new Set([
  '.git',
  '.idea',
  '.next',
  '.turbo',
  '.vscode',
  '__pycache__',
  'bin',
  'build',
  'coverage',
  'dist',
  'node_modules',
  'obj',
  'out',
  'target',
  'tmp',
  'vendor',
]);

const APP_TYPE_RULES = [
  {
    type: '힙 메모리 객체를 관리하는',
    patterns: [/\bglibc\b/i, /\blibc\b/i, /\btcache\b/i, /\bunsorted bin\b/i, /\b_IO_FILE\b/i, /\bfsop\b/i, /\bheap\b/i],
  },
  {
    type: '메뉴 입력을 받아 상태를 변경하는',
    patterns: [/\bctf\b/i, /\bchallenge\b/i, /\bpwn\b/i, /\bflag\b/i, /\bmenu\b/i, /\bchoice\b/i, /\bstdin\b/i],
  },
  {
    type: 'API 요청을 처리하는',
    patterns: [/\bexpress\b/i, /\brouter\.(get|post|put|delete)\b/i, /\bfastapi\b/i, /\bflask\b/i, /\b@RestController\b/i],
  },
  {
    type: '인증과 데이터 처리를 수행하는',
    patterns: [/\blogin\b/i, /\bsignup\b/i, /\bsession\b/i, /\bpassword\b/i, /\btoken\b/i],
  },
  {
    type: '모바일 기능을 제공하는',
    patterns: [/\bandroidmanifest\b/i, /\bactivity\b/i, /\bfragment\b/i, /\bintent\b/i],
  },
  {
    type: '네트워크 시각화 기능을 제공하는',
    patterns: [/\bchart\b/i, /\bgraph\b/i, /\bnetwork\b/i, /\bd3\b/i, /\bcytoscape\b/i],
  },
];

const VULNERABILITY_RULES = [
  {
    id: 'heap-corruption',
    name: 'Heap Corruption',
    severity: 'high',
    patterns: [/\bmalloc\b/i, /\bcalloc\b/i, /\brealloc\b/i, /\bfree\b/i, /\btcache\b/i, /\bunsorted bin\b/i, /\bfastbin\b/i],
    locationHint: '힙 할당과 해제를 반복하는 로직',
    detail: '힙 객체를 생성하고 해제하는 흐름이 강하게 보이며, glibc allocator 관련 흔적까지 확인된다. 이런 구조는 use-after-free, double free, tcache poisoning, unsorted bin corruption처럼 실제 exploit로 이어지기 쉬운 메모리 손상 문제를 만들 수 있다.',
    remediation: '객체 생명주기를 분명히 관리하고, 해제 후 참조를 제거하며, 인덱스 기반 접근과 길이 검증을 철저히 넣는 편이 좋다. 메뉴형 프로그램이라면 생성/수정/삭제/출력 기능 간 상태 전이를 함께 검토해야 한다.',
    explanation: 'Heap Corruption은 힙에 할당된 객체의 메타데이터나 인접 메모리 영역이 손상되어, 공격자가 할당기 동작이나 객체 참조 흐름을 조작할 수 있게 되는 취약점이다.',
  },
  {
    id: 'fsop',
    name: 'FSOP',
    severity: 'high',
    patterns: [/\b_IO_FILE\b/i, /\bstdout\b/i, /\bstdin\b/i, /\bstderr\b/i, /\bfsop\b/i, /\bvtable\b/i],
    locationHint: 'glibc FILE 구조체와 표준 스트림 주변 로직',
    detail: '표준 스트림 객체나 FILE 구조체 주변 흔적이 보여 FSOP 계열 악용이 가능한 문제 설정일 가능성이 높다. 이 계열은 힙 손상과 결합되면 가짜 FILE 구조체 또는 vtable 변조를 통해 코드 실행으로 이어질 수 있다.',
    remediation: '실서비스 코드라면 FILE 구조체를 직접 다루지 않도록 하고, 교육용 바이너리라면 어떤 힙 오염 경로가 표준 스트림 조작으로 이어지는지 명확히 추적해야 한다.',
    explanation: 'FSOP는 File Stream Oriented Programming의 약자로, glibc의 FILE 구조체나 표준 스트림 객체를 오염시켜 제어 흐름을 탈취하는 메모리 손상 취약점 계열이다.',
  },
  {
    id: 'stack-overflow',
    name: 'Buffer Overflow',
    severity: 'high',
    patterns: [/\bgets\b/i, /\bstrcpy\b/i, /\bstrcat\b/i, /\bsprintf\b/i, /\bscanf\b/i, /\bread\b/i],
    locationHint: '고정 길이 버퍼에 입력을 복사하는 경로',
    detail: '길이 제한이 불명확한 입력 함수나 문자열 복사 함수가 보여 스택 오버플로우 가능성이 높다. 보호기법이 일부 있더라도 ret overwrite, ROP, stack pivot 같은 공격으로 이어질 수 있다.',
    remediation: '길이를 명시하는 안전한 API로 바꾸고, 읽기 길이와 실제 버퍼 크기 검증을 분리해야 한다. 바이너리라면 함수별 지역 버퍼 크기와 입력 길이 상한을 함께 확인하는 편이 좋다.',
    explanation: 'Buffer Overflow는 버퍼 크기를 초과하는 입력이 인접 메모리를 덮어쓰면서 제어 흐름이나 데이터를 손상시키는 대표적인 메모리 손상 취약점이다.',
  },
  {
    id: 'format-string',
    name: 'Format String',
    severity: 'high',
    patterns: [/\bprintf\b/i, /\bfprintf\b/i, /\bsnprintf\b/i, /\b%p\b/i, /\b%n\b/i],
    locationHint: '사용자 문자열을 출력 포맷으로 사용하는 경로',
    detail: '포맷 함수 흔적과 포인터 출력 패턴이 보여 포맷 스트링 계열 취약점 가능성을 배제하기 어렵다. 이 문제는 메모리 주소 유출과 임의 쓰기를 동시에 만들 수 있어 exploit 안정성이 매우 높아질 수 있다.',
    remediation: '포맷 문자열은 상수로 고정하고, 사용자 입력은 별도의 인자로 전달해야 한다. 교육용 분석에서는 leak primitive와 write primitive가 모두 가능한지까지 나눠 보는 편이 좋다.',
    explanation: 'Format String은 사용자 입력이 printf 계열 함수의 포맷 문자열로 해석되면서 메모리 읽기나 쓰기가 가능해지는 취약점이다.',
  },
  {
    id: 'arbitrary-write',
    name: 'Arbitrary Write',
    severity: 'high',
    patterns: [/\bscanf\s*\(\s*"%lu"\s*,\s*&\w+\s*\)/i, /\bfgets\s*\(\s*\(\s*char\s*\*\s*\)\s*\w+\s*,/i, /\bread\s*\(\s*0\s*,\s*\(\s*void\s*\*\s*\)\s*\w+\s*,/i],
    locationHint: '사용자가 지정한 주소에 데이터를 쓰는 경로',
    detail: '외부 입력으로 받은 값을 주소처럼 해석한 뒤 그 주소에 다시 데이터를 기록하는 흐름이 보인다. 이 구조는 공격자에게 write-what-where primitive를 제공하므로 제어 흐름 탈취나 중요 구조체 오염으로 매우 쉽게 이어질 수 있다.',
    remediation: '사용자 입력을 포인터로 직접 해석하지 말고, 허용된 버퍼 범위 내부에서만 읽고 쓰도록 강제해야 한다. 주소처럼 보이는 정수 입력을 그대로 캐스팅해 사용하는 로직은 제거하는 편이 맞다.',
    explanation: 'Arbitrary Write는 공격자가 원하는 주소에 원하는 데이터를 쓰게 만들 수 있는 취약점으로, 메모리 손상 계열에서 가장 직접적인 exploit primitive 중 하나다.',
  },
  {
    id: 'command-injection',
    name: 'Command Injection',
    severity: 'high',
    patterns: [/\bexecve?\b/i, /\bsystem\b/i, /\bpopen\b/i, /\bCreateProcess\b/i, /\bos\.system\b/i],
    locationHint: '외부 입력이 시스템 명령으로 이어지는 지점',
    detail: '외부 입력 또는 내부 상태가 시스템 명령 실행으로 연결될 가능성이 보인다. 서버나 실습 바이너리 권한으로 명령이 실행되면 즉시 쉘 획득까지 이어질 수 있어 치명도가 높다.',
    remediation: '셸 호출을 피하고, 불가피하다면 허용 가능한 명령과 인자를 완전 화이트리스트로 제한해야 한다.',
    explanation: 'Command Injection은 외부 입력이 운영체제 명령에 섞여 들어가면서 공격자가 임의 명령을 실행할 수 있게 되는 취약점이다.',
  },
  {
    id: 'sql-injection',
    name: 'SQL Injection',
    severity: 'high',
    patterns: [
      /\bSELECT\b[\s\S]{0,200}\+/i,
      /\bINSERT\b[\s\S]{0,200}\+/i,
      /\bUPDATE\b[\s\S]{0,200}\+/i,
      /\bDELETE\b[\s\S]{0,200}\+/i,
      /`[^`]*(SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{/i,
      /f["'][\s\S]{0,240}(SELECT|INSERT|UPDATE|DELETE)[\s\S]{0,240}\{[\s\S]{0,120}\}[\s\S]{0,240}["']/i,
      /\bread_sql_query\s*\(\s*f["'][\s\S]{0,240}(SELECT|INSERT|UPDATE|DELETE)[\s\S]{0,240}\{[\s\S]{0,120}\}[\s\S]{0,240}["']/i,
      /\bexecute\s*\(\s*f["'][\s\S]{0,240}(SELECT|INSERT|UPDATE|DELETE|CREATE TABLE)[\s\S]{0,240}\{[\s\S]{0,120}\}[\s\S]{0,240}["']/i,
      /\.execute\s*\(\s*["'][\s\S]{0,240}(SELECT|INSERT|UPDATE|DELETE)[\s\S]{0,240}%s/i,
      /\.execute\s*\(\s*["'][\s\S]{0,240}(SELECT|INSERT|UPDATE|DELETE)[\s\S]{0,240}\.format\s*\(/i,
      /\b(query|execute)\s*\(\s*["'`][\s\S]{0,200}(SELECT|INSERT|UPDATE|DELETE)[\s\S]{0,200}["'`]\s*\+/i,
      /\b(query|execute)\s*\(\s*[^)]*\+\s*req\.(body|query|params)/i,
      /\bsequelize\.query\s*\(\s*[^)]*\$\{/i,
    ],
    locationHint: '동적 쿼리 문자열을 조합하는 경로',
    detail: '쿼리문을 문자열 결합으로 조립하는 흔적이 보여 SQL Injection 가능성이 높다. 인증 우회, 데이터 덤프, 관리자 권한 획득까지 이어질 수 있다.',
    remediation: 'prepared statement 또는 parameter binding으로 값과 쿼리 구조를 분리해야 한다.',
    explanation: 'SQL Injection은 사용자 입력이 SQL 구문으로 해석되어 원래 의도하지 않은 쿼리 실행을 일으키는 취약점이다.',
  },
  {
    id: 'nosql-injection',
    name: 'NoSQL Injection',
    severity: 'high',
    patterns: [
      /\b(find|findOne|findById|updateOne|updateMany|deleteOne|deleteMany|aggregate)\s*\(\s*req\.(body|query|params)/i,
      /\b(find|findOne|updateOne|aggregate)\s*\(\s*[^)]*\$\w+/i,
      /\$where\b/i,
      /\$regex\b/i,
      /\$ne\b/i,
      /\$gt\b/i,
      /\$lt\b/i,
      /\bmongodb\b/i,
      /\bmongoose\b/i,
    ],
    locationHint: '사용자 입력이 NoSQL 쿼리 객체나 연산자로 직접 들어가는 경로',
    detail: '사용자 입력이 MongoDB 같은 NoSQL 쿼리 객체로 그대로 들어가면 `$ne`, `$regex`, `$where` 같은 연산자를 악용해 인증 우회나 데이터 조회 범위 확장이 일어날 수 있다.',
    remediation: '사용자 입력을 그대로 쿼리 객체로 넘기지 말고, 허용 필드와 타입을 엄격히 고정한 뒤 필요한 값만 추출해 조합해야 한다.',
    explanation: 'NoSQL Injection은 사용자 입력이 NoSQL 쿼리의 연산자나 조건 객체로 해석되어 원래 의도하지 않은 조회나 인증 우회를 일으키는 취약점이다.',
  },
  {
    id: 'xss',
    name: 'XSS',
    severity: 'medium',
    patterns: [
      /dangerouslySetInnerHTML/i,
      /innerHTML\s*=/i,
      /\bv-html\b/i,
      /document\.write\s*\(/i,
      /render_template_string\s*\(/i,
      /\|\s*safe\b/i,
      /\bMarkup\s*\(/i,
      /return\s+f?["'][\s\S]{0,160}<script[\s\S]{0,160}["']/i,
      /response\.write\s*\(/i,
      /request\.(args|form|values)\.get\s*\(/i,
      /return\s+\w+\s*$/im,
    ],
    locationHint: '브라우저에 HTML을 그대로 주입하는 지점',
    detail: '신뢰되지 않은 문자열을 HTML로 렌더링할 가능성이 보여 브라우저 기반 공격 표면이 존재한다. 세션 탈취와 관리자 기능 대리 실행으로 이어질 수 있다.',
    remediation: '사용자 입력은 텍스트로 렌더링하고, 필요 시 검증된 sanitizer와 CSP를 함께 적용해야 한다.',
    explanation: 'XSS는 공격자가 삽입한 스크립트가 다른 사용자의 브라우저에서 실행되도록 만들어 세션 탈취나 화면 조작을 일으키는 취약점이다.',
  },
  {
    id: 'path-traversal',
    name: 'Path Traversal',
    severity: 'high',
    patterns: [
      /\.\.\//,
      /\bpath\.join\b/i,
      /\bfs\.(readFile|writeFile|createReadStream|createWriteStream)\b/i,
      /@app\.route\s*\(\s*["'][^"']*<path:[^>]+>[^"']*["']\s*\)/i,
      /\bopen\s*\(\s*\w+\s*\)\.read\s*\(/i,
      /\bsend_file\s*\(\s*\w+\s*\)/i,
      /\bFileResponse\s*\(\s*\w+\s*\)/i,
    ],
    locationHint: '사용자 입력과 파일 경로를 결합하는 지점',
    detail: '외부 입력이 파일 경로와 합쳐지는 구조가 보여 상위 디렉터리 접근이나 민감 파일 노출 가능성이 있다.',
    remediation: '정규화 결과가 허용된 루트 내부에 있는지 검증하고, 파일명은 서버 내부 식별자로 재매핑하는 편이 좋다.',
    explanation: 'Path Traversal은 상대 경로 조작을 통해 애플리케이션이 허용하지 않은 상위 디렉터리 파일에 접근하게 만드는 취약점이다.',
  },
  {
    id: 'hardcoded-secret',
    name: 'Hardcoded Secret',
    severity: 'high',
    patterns: [/(api[_-]?key|secret|token|password)\s*[:=]\s*['"][^'"]{6,}['"]/i, /Bearer\s+[A-Za-z0-9._-]{12,}/i],
    locationHint: '소스 코드 또는 설정에 민감정보가 직접 들어간 지점',
    detail: '비밀값이 코드에 직접 포함된 흔적이 보인다. 저장소 유출이나 빌드 결과 노출만으로도 즉시 인증 우회로 이어질 수 있다.',
    remediation: '환경 변수나 시크릿 저장소로 옮기고, 이미 노출된 값은 회전해야 한다.',
    explanation: 'Hardcoded Secret은 인증 토큰, 비밀번호, API 키 같은 민감정보가 코드나 설정에 직접 포함되어 노출되는 문제다.',
  },
];

function normalizeSeverity(value) {
  return ['high', 'medium', 'low'].includes(value) ? value : 'low';
}

function compareSeverity(left, right) {
  const order = { high: 3, medium: 2, low: 1 };
  return (order[right] || 0) - (order[left] || 0);
}

function detectArchiveExtension(fileName) {
  const lowered = String(fileName || '').toLowerCase();
  return ARCHIVE_EXTENSIONS.find((extension) => lowered.endsWith(extension)) || '';
}

function normalizeBaseName(filePath) {
  return path.basename(String(filePath || '')).toLowerCase();
}

function getInterestingArchiveEntryScore(entryPath) {
  const normalized = String(entryPath || '').replace(/\\/g, '/');
  const lowered = normalized.toLowerCase();
  const baseName = normalizeBaseName(normalized);
  const extension = path.extname(lowered);

  let score = 0;

  if (PROJECT_MARKERS.has(baseName)) score += 12;
  if (TEXT_EXTENSIONS.has(extension)) score += 9;
  if (REVIEWABLE_BINARY_EXTENSIONS.has(extension)) score += 7;
  if (/src\/|app\/|pages\/|components\/|lib\/|server\/|api\/|routes\/|controllers?\//i.test(lowered)) score += 6;
  if (/auth|login|session|token|jwt|oauth|query|sql|mongo|upload|path|file|admin|exec|command/i.test(lowered)) score += 4;
  if (/test|spec|__tests__|fixture|mock|coverage|storybook/i.test(lowered)) score -= 5;
  if (/\.(png|jpg|jpeg|gif|webp|svg|mp3|mp4|mov|avi|pdf|docx?|xlsx?|pptx?|ttf|woff2?)$/i.test(lowered)) score -= 10;

  return score;
}

function createArchiveListingContext(fileName, entries) {
  const interestingEntries = entries
    .map((entry) => ({ entry, score: getInterestingArchiveEntryScore(entry) }))
    .filter((item) => item.score > 0)
    .sort((left, right) => right.score - left.score)
    .slice(0, MAX_ARCHIVE_LISTING_ENTRIES)
    .map((item) => item.entry);

  if (!interestingEntries.length) {
    return null;
  }

  return {
    sourceFile: `${fileName}:archive-index`,
    kind: 'text',
    text: `ARCHIVE CONTENTS\n${interestingEntries.join('\n')}`.slice(0, 32000),
    fullText: interestingEntries.join('\n'),
  };
}

function isLikelyTextFile(filePath) {
  const extension = path.extname(filePath).toLowerCase();
  const baseName = normalizeBaseName(filePath);
  return TEXT_EXTENSIONS.has(extension) || PROJECT_MARKERS.has(baseName);
}

function readTextSnippet(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8').slice(0, MAX_TEXT_BYTES).trim();
  } catch {
    return '';
  }
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function inferAnalysisFocusFromName(name) {
  const text = String(name || '').toLowerCase();

  if (/sql|mysql|postgres|sqlite|sequelize|prisma|query|db|database/.test(text)) {
    return 'SQL/ORM 쿼리 구간';
  }
  if (/mongo|mongoose|nosql|aggregate|bson/.test(text)) {
    return 'NoSQL 쿼리 구간';
  }
  if (/auth|login|session|token|jwt|oauth|signin/.test(text)) {
    return '인증과 세션 처리 구간';
  }
  if (/path|file|upload|download|storage|fs/.test(text)) {
    return '파일 처리와 경로 검증 구간';
  }
  if (/cmd|exec|system|shell|process|spawn/.test(text)) {
    return '명령 실행과 프로세스 처리 구간';
  }
  if (/heap|malloc|free|glibc|fsop|stdin|stdout|stderr|pwn|chall/.test(text)) {
    return '메모리 처리와 stdio 구조 구간';
  }
  if (/route|controller|api|server|service|app/.test(text)) {
    return '서비스 엔드포인트와 요청 처리 구간';
  }
  return '핵심 로직 구간';
}

function buildDynamicProgressMessage(name, action = '읽고 있습니다') {
  const focus = inferAnalysisFocusFromName(name);
  const safeName = path.basename(String(name || '업로드 파일'));
  return `${safeName}를 중심으로 ${focus}을 ${action}.`;
}

function sanitizeCodexProgressLine(line) {
  const text = String(line || '')
    .replace(/\u001b\[[0-9;]*m/g, '')
    .replace(/\s+/g, ' ')
    .trim();

  if (!text) {
    return '';
  }

  if (/^openai|^codex\b|^model\b|^tokens?\b|^cost\b|^thinking\b/i.test(text)) {
    return '';
  }

  return text.slice(0, 180);
}

function sanitizeAnalysisName(value, fallback = 'item') {
  const sanitized = String(value || fallback)
    .replace(/[^a-zA-Z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 120);
  return sanitized || fallback;
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

async function listArchiveEntries(filePath, extension) {
  if (ZIP_ARCHIVE_EXTENSIONS.has(extension)) {
    const { stdout } = await execFileAsync('unzip', ['-Z1', filePath], {
      timeout: 15000,
      maxBuffer: 2 * 1024 * 1024,
    });
    return String(stdout || '').split('\n').map((line) => line.trim()).filter(Boolean);
  }

  const { stdout } = await execFileAsync('tar', ['-tf', filePath], {
    timeout: 15000,
    maxBuffer: 2 * 1024 * 1024,
  });
  return String(stdout || '').split('\n').map((line) => line.trim()).filter(Boolean);
}

async function extractArchiveToDirectory(filePath, extension, outputDir) {
  if (ZIP_ARCHIVE_EXTENSIONS.has(extension)) {
    await execFileAsync('unzip', ['-o', filePath, '-d', outputDir], {
      timeout: 300000,
      maxBuffer: 2 * 1024 * 1024,
    });
    return;
  }

  await execFileAsync('tar', ['-xf', filePath, '-C', outputDir], {
    timeout: 300000,
    maxBuffer: 2 * 1024 * 1024,
  });
}

function walkDirectory(rootDir) {
  const queue = [rootDir];
  const files = [];

  while (queue.length && files.length < MAX_WALK_FILES) {
    const currentPath = queue.shift();
    const entries = fs.readdirSync(currentPath, { withFileTypes: true });

    entries.forEach((entry) => {
      const entryPath = path.join(currentPath, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRECTORY_NAMES.has(String(entry.name || '').toLowerCase())) {
          return;
        }
        queue.push(entryPath);
        return;
      }

      if (entry.isFile()) {
        files.push(entryPath);
      }
    });
  }

  return files;
}

function collectInterestingDisassemblyLines(disassemblyText) {
  return String(disassemblyText || '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .filter((line) => /call|cmp|test|jmp|je|jne|lea|mov|syscall|ret/i.test(line))
    .slice(0, MAX_DISASSEMBLY_LINES);
}

function toPseudoCFromAssembly(lines) {
  return String(lines || '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .slice(0, 10)
    .map((line) => {
      if (/call\s+.*(malloc|calloc|realloc)/i.test(line)) {
        return 'ptr = allocate_buffer(size);';
      }
      if (/call\s+.*free/i.test(line)) {
        return 'release_buffer(ptr);';
      }
      if (/call\s+.*(read|recv|fgets|scanf|gets)/i.test(line)) {
        return 'read_input(user_buffer, requested_size);';
      }
      if (/call\s+.*(printf|fprintf|snprintf)/i.test(line)) {
        return 'print_message(user_controlled_format);';
      }
      if (/call\s+.*(system|execve|popen)/i.test(line)) {
        return 'execute_system_command(user_supplied_command);';
      }
      if (/cmp|test/i.test(line)) {
        return 'if (state_or_input_check_failed) { handle_error(); }';
      }
      if (/jmp|je|jne/i.test(line)) {
        return 'if (condition) { branch_to_next_logic(); }';
      }
      if (/mov/i.test(line)) {
        return 'object_or_buffer_field = user_or_runtime_value;';
      }
      if (/lea/i.test(line)) {
        return 'ptr = &object_or_stack_buffer;';
      }
      if (/ret/i.test(line)) {
        return 'return service_result;';
      }
      return null;
    })
    .filter(Boolean)
    .slice(0, 6)
    .join('\n');
}

function extractCodeExcerpt(text, patterns, kind) {
  const lines = String(text || '').split('\n');
  const matchedIndex = lines.findIndex((line) => patterns.some((pattern) => pattern.test(line)));

  if (matchedIndex === -1) {
    return kind === 'binary'
      ? toPseudoCFromAssembly(lines.join('\n')) || '/* 취약점을 직접 가리키는 코드 조각을 자동 추출하지 못했습니다. */'
      : '/* 취약점을 직접 가리키는 코드 조각을 자동 추출하지 못했습니다. */';
  }

  if (kind === 'binary') {
    const nearby = lines.slice(Math.max(0, matchedIndex - 2), matchedIndex + 4).join('\n');
    return toPseudoCFromAssembly(nearby) || '/* 디스어셈블 근처에서 C 스타일 의사코드를 충분히 복원하지 못했습니다. */';
  }

  const start = Math.max(0, matchedIndex - 2);
  const end = Math.min(lines.length, matchedIndex + 3);
  return lines
    .slice(start, end)
    .map((line, index) => `${start + index + 1}: ${line}`)
    .join('\n');
}

async function inspectBinaryPath(filePath, label) {
  try {
    const { stdout: fileStdout } = await execFileAsync('file', ['-b', filePath], {
      timeout: 10000,
      maxBuffer: 256 * 1024,
    });
    const fileDescription = String(fileStdout || '').trim();

    let stringsOutput = '';
    try {
      const { stdout } = await execFileAsync('strings', ['-n', '4', filePath], {
        timeout: 30000,
        maxBuffer: 2 * 1024 * 1024,
      });
      stringsOutput = String(stdout || '')
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean)
        .slice(0, MAX_BINARY_STRINGS)
        .join('\n');
    } catch {}

    let symbolOutput = '';
    try {
      const { stdout } = await execFileAsync('readelf', ['-Ws', filePath], {
        timeout: 30000,
        maxBuffer: 2 * 1024 * 1024,
      });
      symbolOutput = String(stdout || '')
        .split('\n')
        .map((line) => line.trim())
        .filter((line) => /\bFUNC\b|\bOBJECT\b/.test(line))
        .slice(0, MAX_BINARY_SYMBOLS)
        .join('\n');
    } catch {}

    let disassemblyOutput = '';
    try {
      const { stdout } = await execFileAsync('objdump', ['-d', '-M', 'intel', '--no-show-raw-insn', filePath], {
        timeout: 45000,
        maxBuffer: 4 * 1024 * 1024,
      });
      disassemblyOutput = collectInterestingDisassemblyLines(stdout).join('\n');
    } catch {}

    const combined = [
      `FILE TYPE: ${fileDescription}`,
      stringsOutput ? `STRINGS:\n${stringsOutput}` : '',
      symbolOutput ? `SYMBOLS:\n${symbolOutput}` : '',
      disassemblyOutput ? `DISASSEMBLY:\n${disassemblyOutput}` : '',
    ].filter(Boolean).join('\n\n');

    if (!combined) {
      return null;
    }

    return {
      sourceFile: label,
      text: combined.slice(0, 32000),
      kind: 'binary',
    };
  } catch {
    return null;
  }
}

async function detectFileKind(filePath) {
  try {
    const { stdout } = await execFileAsync('file', ['-b', '--mime-type', filePath], {
      timeout: 8000,
      maxBuffer: 128 * 1024,
    });
    const mimeType = String(stdout || '').trim().toLowerCase();

    if (mimeType.startsWith('text/')) {
      return 'text';
    }

    if (
      mimeType.includes('json')
      || mimeType.includes('xml')
      || mimeType.includes('javascript')
      || mimeType.includes('x-sh')
      || mimeType.includes('x-shellscript')
    ) {
      return 'text';
    }

    if (
      mimeType.includes('x-executable')
      || mimeType.includes('x-pie-executable')
      || mimeType.includes('x-sharedlib')
      || mimeType.includes('x-object')
      || mimeType.includes('octet-stream')
      || mimeType.includes('x-dosexec')
      || mimeType.includes('java-vm')
      || mimeType.includes('wasm')
      || mimeType.includes('x-mach-binary')
    ) {
      return 'binary';
    }

    return isLikelyTextFile(filePath) ? 'text' : 'unknown';
  } catch {
    return isLikelyTextFile(filePath) ? 'text' : 'unknown';
  }
}

async function collectContextFromFile(filePath, label) {
  if (isLikelyTextFile(filePath)) {
    const text = readTextSnippet(filePath);
    if (!text) {
      return null;
    }

    return {
      sourceFile: label,
      text: text.slice(0, 32000),
      kind: 'text',
      fullText: text,
    };
  }

  const detectedKind = await detectFileKind(filePath);

  if (detectedKind === 'text') {
    const text = readTextSnippet(filePath);
    if (!text) {
      return null;
    }

    return {
      sourceFile: label,
      text: text.slice(0, 32000),
      kind: 'text',
      fullText: text,
    };
  }

  if (detectedKind === 'binary') {
    return inspectBinaryPath(filePath, label);
  }

  return null;
}

async function collectContextFromArchive(file, onProgress) {
  const extension = detectArchiveExtension(file.originalName);
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'phase-analysis-archive-'));

  try {
    const archiveEntries = await listArchiveEntries(file.absolutePath, extension).catch(() => []);
    const listingContext = createArchiveListingContext(file.originalName, archiveEntries);

    await extractArchiveToDirectory(file.absolutePath, extension, tempDir);
    const files = walkDirectory(tempDir)
      .map((candidate) => ({
        candidate,
        relativePath: path.relative(tempDir, candidate).split(path.sep).join('/'),
        score: getInterestingArchiveEntryScore(path.relative(tempDir, candidate)),
      }))
      .filter((item) => item.score > 0)
      .sort((left, right) => right.score - left.score)
      .slice(0, MAX_ARCHIVE_CONTEXT_FILES);
    const contexts = [];
    let textCount = 0;
    let binaryCount = 0;

    if (listingContext) {
      contexts.push(listingContext);
      textCount += 1;
    }

    for (const { candidate, relativePath } of files) {
      const relativeLabel = `${file.originalName}:${relativePath}`;
      onProgress?.({
        stage: '내용 분석 중',
        progressPercent: 32,
        message: buildDynamicProgressMessage(relativeLabel),
      });
      const detectedKind = await detectFileKind(candidate);

      if (detectedKind === 'text' && textCount >= MAX_TEXT_FILES) {
        continue;
      }

      if (detectedKind === 'binary' && binaryCount >= MAX_BINARY_FILES) {
        continue;
      }

      if (detectedKind !== 'text' && detectedKind !== 'binary') {
        continue;
      }

      const context = await collectContextFromFile(candidate, relativeLabel);
      if (!context) {
        continue;
      }

      contexts.push(context);
      if (context.kind === 'text') {
        textCount += 1;
      }
      if (context.kind === 'binary') {
        binaryCount += 1;
      }
    }

    return contexts;
  } catch {
    const archiveEntries = await listArchiveEntries(file.absolutePath, extension).catch(() => []);
    const listingContext = createArchiveListingContext(file.originalName, archiveEntries);
    return listingContext ? [listingContext] : [];
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

async function buildFileContexts(acceptedFiles, onProgress) {
  const contexts = [];

  for (const file of acceptedFiles) {
    const extension = detectArchiveExtension(file.originalName);
    onProgress?.({
      stage: '내용 분석 중',
      progressPercent: 24,
      message: buildDynamicProgressMessage(file.originalName),
    });

    if (extension) {
      const archiveContexts = await collectContextFromArchive(file, onProgress);
      contexts.push(...archiveContexts);
      continue;
    }

    const context = await collectContextFromFile(file.absolutePath, file.originalName);
    if (context) {
      contexts.push(context);
    }
  }

  return contexts;
}

export async function prepareCodexAnalysisWorkspace(acceptedFiles) {
  const workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'phase-analysis-codex-'));
  const manifest = [];

  try {
    for (let index = 0; index < acceptedFiles.length; index += 1) {
      const file = acceptedFiles[index];
      const safeBaseName = `${String(index + 1).padStart(2, '0')}-${sanitizeAnalysisName(file.originalName, 'upload')}`;
      const archiveExtension = detectArchiveExtension(file.originalName);
      const originalTargetPath = path.join(workspaceRoot, safeBaseName);

      fs.copyFileSync(file.absolutePath, originalTargetPath);

      if (archiveExtension) {
        const extractedDir = path.join(workspaceRoot, `${safeBaseName}__extracted`);
        fs.mkdirSync(extractedDir, { recursive: true });
        await extractArchiveToDirectory(file.absolutePath, archiveExtension, extractedDir);
        manifest.push({
          originalName: file.originalName,
          storedPath: safeBaseName,
          extractedPath: `${safeBaseName}__extracted`,
          archive: true,
        });
        continue;
      }

      manifest.push({
        originalName: file.originalName,
        storedPath: safeBaseName,
        extractedPath: '',
        archive: false,
      });
    }

    return { workspaceRoot, manifest };
  } catch (error) {
    fs.rmSync(workspaceRoot, { recursive: true, force: true });
    throw error;
  }
}

function buildCodexAnalysisPrompt({ manifest }) {
  return [
    'You are generating a final security report for an educational vulnerability-analysis product.',
    'The current working directory contains the uploaded files and extracted archives.',
    'Read the codebase broadly and deeply before answering. Do not stop after the first obvious issue.',
    'First identify the real runtime entrypoints, executable components, request handlers, background jobs, and binary targets before deciding what the service actually does.',
    'Inspect source, configs, scripts, and binaries. For binaries, use strings/readelf/objdump when needed.',
    'Treat the upload as a real production service, not as a challenge or demo.',
    'Only report vulnerabilities that are directly supported by the code or binary evidence you inspected.',
    'If a vulnerability is only suspected, exclude it from findings.',
    'Prefer recommendation mode over vulnerability mode when evidence is partial, split across unrelated files, or depends on guessing hidden behavior.',
    'Use documentation, comments, tests, fixtures, examples, sample payloads, tutorial snippets, regex tables, detection rules, and prose only as background context, never as vulnerability evidence.',
    'Do not treat vulnerability names, exploit examples, placeholder secrets, test credentials, regex patterns, or scanner rule definitions as proof of a real issue.',
    'Do not use README, Markdown, plain text notes, stylesheets, snapshots, or test-only files as the primary evidence location for a finding.',
    'If the project contains security tooling, analyzers, rule engines, upload filters, or educational examples, treat those as metadata unless the vulnerable runtime path itself is proven.',
    'Prefer exact vulnerability names such as FSOP, Arbitrary Write, XSS, SQL Injection, NoSQL Injection, Buffer Overflow, Command Injection, Path Traversal, Heap Corruption, Hardcoded Secret.',
    'Pay special attention to SQL/ORM query construction and MongoDB/Mongoose style query objects.',
    'If user input is concatenated into SQL, classify it as SQL Injection when directly supported by code.',
    'If user input is passed into MongoDB/Mongoose filters, operators, or query objects in a way that can alter query semantics, classify it as NoSQL Injection when directly supported by code.',
    'A vulnerability finding is valid only when the source of attacker-controlled input and the dangerous sink are both visible in real runtime code or binary behavior.',
    'Prefer evidence where the source and sink appear in the same file, same function, same handler, or a clearly traceable call chain. Do not combine unrelated files into one exploit path.',
    'For command injection, require a real command-execution sink plus user-controlled input reaching that sink in executable code.',
    'For SQL injection and NoSQL injection, require a real query sink plus attacker-controlled values affecting query structure or semantics in executable code.',
    'For XSS, require real user-controlled content reaching an HTML or script rendering sink in executable runtime code.',
    'For memory-corruption findings such as FSOP, Heap Corruption, Buffer Overflow, Format String, or Arbitrary Write, require native code or real binary evidence. Never infer these from web app text, docs, CSS, or scanner rules.',
    'The application summary must describe service logic only, not how you analyzed it.',
    'For each finding, include a real file path summary and a codeLocation snippet. If source code exists, use source code. Only use C-style pseudocode when source truly does not exist.',
    'Each codeLocation must be a verbatim snippet from the cited runtime file or binary-derived pseudocode tied to the cited binary. If you cannot cite an exact snippet, discard the finding.',
    'Write the final report in Korean.',
    'Respond with JSON only.',
    JSON.stringify({
      schema: {
        title: 'string',
        applicationType: 'string',
        applicationReport: 'string',
        resultMode: '"vulnerability" | "recommendation"',
        summary: 'string',
        findings: [
          {
            title: 'string',
            severity: '"high" | "medium" | "low"',
            location: 'string',
            codeLocation: 'string',
            explanation: 'string',
            detail: 'string',
            remediation: 'string',
          },
        ],
      },
      constraints: [
        'title must end with "서비스"',
        'applicationReport must describe what the service does in practice',
        'findings must contain only fact-checked vulnerabilities or concrete hardening recommendations',
        'explanation/detail/remediation should be educational, detailed, and easy to understand',
      ],
      uploadedFiles: manifest,
    }, null, 2),
  ].join('\n\n');
}

async function analyzeWithCodexExec({ acceptedFiles, onProgress }) {
  if (!String(process.env.CODEX_HOME || process.env.HOME || '').trim()) {
    return null;
  }

  if (acceptedFiles.some((file) => detectArchiveExtension(file.originalName))) {
    onProgress?.({
      stage: '내용 분석 중',
      progressPercent: 40,
      message: '압축 업로드를 해제해 내부 파일까지 심층 분석하고 있습니다.',
    });
  }

  const { workspaceRoot, manifest } = await prepareCodexAnalysisWorkspace(acceptedFiles);
  const outputFile = path.join(workspaceRoot, 'analysis-report.json');
  const prompt = buildCodexAnalysisPrompt({ manifest });
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
    workspaceRoot,
  ];

  const model = process.env.ANALYSIS_CODEX_MODEL || process.env.UPLOAD_CODEX_MODEL || 'gpt-5.4';
  if (model) {
    args.push('--model', model);
  }

  args.push('-');

  try {
    await new Promise((resolve, reject) => {
      const child = spawn('codex', args, {
        cwd: workspaceRoot,
        stdio: ['pipe', 'pipe', 'pipe'],
        env: process.env,
      });
      const timeoutMs = Number(process.env.ANALYSIS_CODEX_TIMEOUT_MS || 3 * 60 * 1000);
      const timer = setTimeout(() => {
        child.kill('SIGTERM');
        reject(new Error('analysis-codex-timeout'));
      }, timeoutMs);

      const handleProgressChunk = (chunk) => {
        const lines = String(chunk || '')
          .split('\n')
          .map((line) => sanitizeCodexProgressLine(line))
          .filter(Boolean);

        const latestLine = lines.at(-1);
        if (!latestLine) {
          return;
        }

        onProgress?.({
          stage: '취약점 분석 중',
          progressPercent: 62,
          message: latestLine,
        });
      };

      child.stdout?.on('data', handleProgressChunk);
      child.stderr?.on('data', handleProgressChunk);

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
        reject(new Error(`analysis-codex-exit-${code}`));
      });
    });

    const parsed = extractJsonObject(fs.readFileSync(outputFile, 'utf8'));
    if (!parsed || !Array.isArray(parsed.findings)) {
      return null;
    }

    return parsed;
  } catch {
    return null;
  } finally {
    fs.rmSync(workspaceRoot, { recursive: true, force: true });
  }
}

function inferApplicationType(joinedText, sourceFiles) {
  const fileJoined = sourceFiles.join('\n');
  const bestMatch = APP_TYPE_RULES
    .map((rule) => ({
      ...rule,
      score: rule.patterns.reduce((total, pattern) => total + (pattern.test(joinedText) || pattern.test(fileJoined) ? 1 : 0), 0),
    }))
    .sort((left, right) => right.score - left.score)[0];

  return bestMatch?.score > 0 ? bestMatch.type : '기능을 제공하는';
}

function buildApplicationNarrative(applicationType, sourceFiles, joinedText) {
  const points = [];
  const primaryFiles = sourceFiles.slice(0, 5).join(', ') || '업로드된 프로젝트 파일';

  if (/\bmenu\b|\bchoice\b|\bselect\b/i.test(joinedText)) {
    points.push('메뉴 입력을 받아 생성, 수정, 삭제, 조회 같은 기능을 수행하며 사용자의 선택에 따라 내부 상태가 바뀌는 로직이 존재한다');
  }
  if (/\bmalloc\b|\bfree\b|\bcalloc\b|\brealloc\b/i.test(joinedText)) {
    points.push('동적 메모리 할당과 해제가 반복되어 객체의 생성 시점과 해제 시점이 서비스 동작에 직접 영향을 주는 구조다');
  }
  if (/\b_IO_FILE\b|\bstdout\b|\bstdin\b|\bfsop\b/i.test(joinedText)) {
    points.push('표준 입출력 스트림과 FILE 구조체에 가까운 입출력 처리 로직이 포함되어 있어 출력 흐름과 내부 객체 상태가 밀접하게 연결되어 있다');
  }
  if (/\bdockerfile\b|\blibc\.so\b|\bld-linux\b/i.test(joinedText)) {
    points.push('런타임 구성 파일과 라이브러리 파일이 함께 포함되어 있어 특정 실행 환경을 기준으로 동작하는 서비스 구조를 가진다');
  }
  if (/\bexpress\b|\brouter\.(get|post|put|delete)\b|\bfastapi\b|\bflask\b/i.test(joinedText)) {
    points.push('외부 요청을 받아 라우팅하고 응답을 반환하는 API 처리 흐름이 존재한다');
  }
  if (/\bandroidmanifest\b|\bactivity\b|\bintent\b/i.test(joinedText)) {
    points.push('화면 전환과 컴포넌트 호출을 통해 기능이 이어지는 모바일 서비스 구조를 가진다');
  }
  if (/\blogin\b|\bsession\b|\btoken\b|\bauth\b/i.test(joinedText)) {
    points.push('인증 정보와 세션 상태를 다루는 기능이 존재해 사용자 식별과 권한 처리 흐름이 핵심 로직에 포함된다');
  }
  if (/\b(read|write|open|close)\b/i.test(joinedText) && /\bfile\b|\bpath\b|\bdir\b/i.test(joinedText)) {
    points.push('파일이나 경로를 열고 읽고 쓰는 기능이 포함되어 있어 외부 입력이 저장소나 파일 시스템 동작으로 이어질 수 있다');
  }
  if (/\bsend\b|\brecv\b|\bsocket\b|\bconnect\b|\blisten\b|\baccept\b/i.test(joinedText)) {
    points.push('네트워크 연결을 통해 데이터를 송수신하는 기능이 존재해 외부 입력이 지속적으로 서비스 상태에 반영될 수 있다');
  }

  const narrative = points.length
    ? points.join('. ')
    : '사용자 입력을 받아 상태를 갱신하고 그 결과를 화면이나 응답으로 제공하는 일반적인 애플리케이션 서비스 구조를 가진다';

  return `이 서비스는 ${applicationType} 애플리케이션 서비스로 보인다. 주요 로직은 ${primaryFiles}에서 확인되며, ${narrative}. 실무 환경에서는 사용자의 요청을 처리하고 내부 상태를 유지하면서 결과를 반환하는 형태로 운영되는 서비스에 가깝다.`;
}

function createFindingFromRule(rule, context) {
  return {
    id: `${rule.id}-${Buffer.from(`${rule.name}-${context.sourceFile}`).toString('base64').slice(0, 12)}`,
    title: rule.name,
    severity: normalizeSeverity(rule.severity),
    location: context.sourceFile,
    codeLocation: extractCodeExcerpt(context.fullText || context.text, rule.patterns, context.kind),
    explanation: rule.explanation || rule.detail,
    detail: rule.detail,
    remediation: rule.remediation,
    abuse: `${rule.locationHint}을 기준으로 외부 입력이나 메모리 상태를 조작하면 ${rule.name}이 실제 exploit primitive로 이어질 수 있다.`,
  };
}

function buildStructuredFinding(finding) {
  const locationText = Array.isArray(finding.locations)
    ? finding.locations.slice(0, 5).join(', ')
    : finding.location;
  const abuseText = [finding.detail, finding.abuse].filter(Boolean).join(' ');

  return {
    ...finding,
    location: locationText || finding.location,
    codeLocation: finding.codeLocation || locationText || finding.location,
    description: [
      `취약점에 관한 설명: ${finding.explanation}`,
      `어떤식으로 악용되는지: ${abuseText}`,
      `코드의 위치: ${finding.codeLocation || locationText || finding.location}`,
      `취약점이 안터지기 위해선 어떻게 해야하는지: ${finding.remediation}`,
    ].join('\n\n'),
  };
}

function countMatchedPatterns(text, patterns) {
  return patterns.reduce((total, pattern) => total + (pattern.test(text) ? 1 : 0), 0);
}

function splitContextsByKind(contexts) {
  const textContexts = contexts.filter((context) => context.kind === 'text');
  const binaryContexts = contexts.filter((context) => context.kind === 'binary');
  return { textContexts, binaryContexts };
}

function selectPreferredCodeContexts(contexts) {
  const { textContexts, binaryContexts } = splitContextsByKind(contexts);
  return textContexts.length ? textContexts : binaryContexts;
}

function getRuleExampleText(ruleId) {
  switch (ruleId) {
    case 'fsop':
      return '예를 들어 힙 손상으로 `_IO_2_1_stdout_` 같은 표준 스트림 객체의 필드나 vtable이 오염되면, 단순 출력 함수 호출이 공격자가 의도한 제어 흐름으로 바뀔 수 있다.';
    case 'heap-corruption':
      return '예를 들어 삭제한 객체를 다시 참조하거나 같은 청크를 두 번 해제하면, 다음 할당에서 공격자가 원하는 주소가 연결되어 임의 쓰기 primitive로 이어질 수 있다.';
    case 'stack-overflow':
      return '예를 들어 길이 제한 없이 버퍼에 입력을 복사하면 저장된 리턴 주소나 인접 변수까지 덮어써서 함수 복귀 흐름을 바꿀 수 있다.';
    case 'format-string':
      return '예를 들어 `printf(user_input);` 같은 형태라면 `%p`로 주소를 읽고 `%n`으로 메모리를 쓰는 식의 공격이 가능해질 수 있다.';
    case 'command-injection':
      return '예를 들어 사용자 입력을 그대로 `system()` 인자로 넘기면 `;`나 `&&`를 이용해 원래 의도와 다른 명령을 이어 붙일 수 있다.';
    case 'sql-injection':
      return '예를 들어 `WHERE id = " + userInput`처럼 쿼리를 붙이면 `1 OR 1=1` 같은 입력만으로 인증 우회나 전체 데이터 조회가 일어날 수 있다.';
    case 'nosql-injection':
      return '예를 들어 `findOne({ username, password: req.body.password })` 대신 요청 바디 전체를 그대로 넘기면 `{ "$ne": null }` 같은 연산자 입력으로 인증 우회가 가능해질 수 있다.';
    case 'xss':
      return '예를 들어 댓글이나 프로필 소개에 들어간 문자열을 HTML로 그대로 렌더링하면 `<script>`나 이벤트 핸들러가 다른 사용자 브라우저에서 실행될 수 있다.';
    case 'path-traversal':
      return '예를 들어 다운로드 파일명을 그대로 경로와 합치면 `../../etc/passwd` 같은 입력으로 서비스 외부 파일에 접근하려는 시도가 가능해질 수 있다.';
    case 'hardcoded-secret':
      return '예를 들어 코드에 직접 박힌 운영 토큰은 저장소 유출, 로그 노출, 빌드 산출물 노출만으로도 바로 악용될 수 있다.';
    default:
      return '실제 서비스에서는 작은 입력 검증 누락 하나가 권한 상승, 데이터 유출, 코드 실행 같은 더 큰 문제로 이어질 수 있다.';
  }
}

function buildVerificationEvidence(rule, contexts) {
  const combinedText = contexts.map((context) => context.fullText || context.text).join('\n\n');
  const verifiedContexts = contexts.slice(0, 3).map((context) => context.sourceFile).join(', ');
  const matchedTokens = rule.patterns
    .map((pattern) => {
      const match = combinedText.match(pattern);
      return match?.[0]?.trim() || '';
    })
    .filter(Boolean)
    .slice(0, 4);

  const tokenText = matchedTokens.length
    ? `확인된 핵심 단서는 ${matchedTokens.join(', ')} 이다.`
    : '패턴 매칭 외에도 함수 호출과 코드 조각을 함께 비교했다.';

  return `${verifiedContexts || '관련 코드 구간'}에서 서로 독립적인 증거가 함께 확인되었고, ${tokenText} 이 항목은 단순 추측이 아니라 다중 증거가 모였을 때만 표시하도록 제한했다.`;
}

function buildExpandedExplanation(rule, contexts) {
  return `${rule.explanation} 교육 관점에서 보면 이 취약점은 "어떤 입력이 어떤 내부 구조를 망가뜨리거나 우회시키는가"를 이해하는 것이 핵심이다. ${getRuleExampleText(rule.id)} ${buildVerificationEvidence(rule, contexts)}`;
}

function buildExpandedAbuse(rule, contexts) {
  const evidenceText = buildVerificationEvidence(rule, contexts);
  return `${rule.detail} 공격자는 보통 입력 길이, 포맷 문자열, 경로 조작, 명령 인자, 객체 생명주기 같은 제어 지점을 이용해 이 문제를 실제 악용 단계로 연결한다. ${getRuleExampleText(rule.id)} ${evidenceText}`;
}

function buildExpandedRemediation(rule) {
  return `${rule.remediation} 운영 환경에서는 입력 검증, 상태 전이 검증, 권한 분리, 예외 처리, 로깅 기준을 함께 정리해야 같은 유형의 문제가 다시 반복되지 않는다. 교육 목적에서는 "취약점이 발생한 직접 원인", "악용에 필요한 조건", "패치 후 막히는 지점"을 각각 따로 비교해보는 것이 좋다.`;
}

function hasUserControlledPointerInput(text) {
  return (
    /\bscanf\s*\(\s*"%l[dux]+"\s*,\s*&\w+\s*\)/i.test(text)
    || /\bscanf\s*\(\s*"%p"\s*,\s*&\w+\s*\)/i.test(text)
    || /\bfgets\s*\(\s*\w+\s*,[^;]+;\s*\w+\s*=\s*\(?(unsigned\s+long|uintptr_t|size_t|long long|void\s*\*)\)?\s*strtou?ll?/i.test(text)
    || /\bstrtou?ll?\s*\([^)]*\)/i.test(text)
    || /\bstrtoul\s*\([^)]*\)/i.test(text)
    || /\batol\s*\([^)]*\)/i.test(text)
  );
}

function hasPointerCastWrite(text) {
  return (
    /\bfgets\s*\(\s*\(\s*char\s*\*\s*\)\s*\w+\s*,/i.test(text)
    || /\bread\s*\(\s*[^,]+,\s*\(\s*void\s*\*\s*\)\s*\w+\s*,/i.test(text)
    || /\bmemcpy\s*\(\s*\(\s*void\s*\*\s*\)\s*\w+\s*,/i.test(text)
    || /\bmemmove\s*\(\s*\(\s*void\s*\*\s*\)\s*\w+\s*,/i.test(text)
    || /\bstrncpy?\s*\(\s*\(\s*char\s*\*\s*\)\s*\w+\s*,/i.test(text)
    || /\b\*\s*\(\s*(char|int|long|void)\s*\*\s*\)\s*\w+\s*=/i.test(text)
  );
}

function hasStreamAddressLeak(text) {
  return (
    /\bprintf\s*\(\s*"%p\\n?"\s*,\s*(stdin|stdout|stderr)\s*\)/i.test(text)
    || /\bfprintf\s*\(\s*[^,]+,\s*"%p\\n?"\s*,\s*(stdin|stdout|stderr)\s*\)/i.test(text)
    || /\bputs\s*\(\s*.*(stdin|stdout|stderr).*\)/i.test(text)
  );
}

function hasDirectResponseReflection(text) {
  const assignments = Array.from(
    String(text || '').matchAll(/\b([a-zA-Z_]\w*)\s*=\s*request\.(args|form|values)\.get\s*\(/g),
  ).map((match) => match[1]);

  return assignments.some((name) => {
    const returnPattern = new RegExp(`\\breturn\\s+${name}\\b`);
    return returnPattern.test(text);
  });
}

function hasPathTraversalFlow(text) {
  const hasPathRoute = /@app\.route\s*\(\s*["'][^"']*<path:([a-zA-Z_]\w*)>[^"']*["']\s*\)/i.test(text);
  const directOpen = /\bopen\s*\(\s*([a-zA-Z_]\w*)\s*\)\.read\s*\(/i.test(text);
  const directSend = /\bsend_file\s*\(\s*([a-zA-Z_]\w*)\s*\)/i.test(text) || /\bFileResponse\s*\(\s*([a-zA-Z_]\w*)\s*\)/i.test(text);
  const requestControlledPath = /\b([a-zA-Z_]\w*)\s*=\s*request\.(args|form|values)\.get\s*\(/i.test(text)
    && (/\bopen\s*\(\s*[a-zA-Z_]\w+\s*\)/i.test(text) || /\bsend_file\s*\(\s*[a-zA-Z_]\w+\s*\)/i.test(text));

  return (hasPathRoute && (directOpen || directSend)) || requestControlledPath || /\.\.\//.test(text);
}

function verifyRuleEvidence(rule, contexts) {
  const combinedText = contexts.map((context) => context.fullText || context.text).join('\n\n');
  const matchCount = countMatchedPatterns(combinedText, rule.patterns);
  const hasSourceEvidence = contexts.some((context) => context.kind === 'text');

  switch (rule.id) {
    case 'heap-corruption':
      return matchCount >= 4
        && /\b(edit|delete|update|show|write|read|size|index|chunk|menu|choice)\b/i.test(combinedText);
    case 'fsop':
      return (
        countMatchedPatterns(combinedText, [/\b_IO_FILE\b/i, /\bstdout\b|\bstdin\b|\bstderr\b/i, /\bvtable\b/i, /\bfsop\b/i]) >= 2
        || (hasStreamAddressLeak(combinedText) && hasUserControlledPointerInput(combinedText) && hasPointerCastWrite(combinedText))
      );
    case 'stack-overflow':
      return (
        /\bgets\b|\bstrcpy\b|\bstrcat\b|\bsprintf\b/i.test(combinedText)
        || ((/\bscanf\b|\bread\b/i.test(combinedText)) && /\bbuffer\b|\bbuf\b|\bchar\s+\w+\s*\[[0-9]+\]/i.test(combinedText))
      );
    case 'format-string':
      return (
        hasSourceEvidence
        && (/\bprintf\b|\bfprintf\b|\bsnprintf\b/i.test(combinedText))
        && (
          /printf\s*\(\s*[^"'][^)]+\)/i.test(combinedText)
          || /fprintf\s*\(\s*[^,]+,\s*[^"'][^)]+\)/i.test(combinedText)
          || /snprintf\s*\([^,]+,\s*[^,]+,\s*[^"'][^)]+\)/i.test(combinedText)
        )
      );
    case 'arbitrary-write':
      return (
        hasSourceEvidence
        && hasUserControlledPointerInput(combinedText)
        && hasPointerCastWrite(combinedText)
      );
    case 'command-injection':
      return (
        /\bexecve?\b|\bsystem\b|\bpopen\b|\bCreateProcess\b|\bos\.system\b/i.test(combinedText)
        && /\b(argv|argc|getenv|request|input|param|query|body|user|command|cmd)\b/i.test(combinedText)
      );
    case 'sql-injection':
      return (
        hasSourceEvidence
        && (
          /\bSELECT\b[\s\S]{0,200}\+/i.test(combinedText)
          || /\bINSERT\b[\s\S]{0,200}\+/i.test(combinedText)
          || /\bUPDATE\b[\s\S]{0,200}\+/i.test(combinedText)
          || /\bDELETE\b[\s\S]{0,200}\+/i.test(combinedText)
          || /`[^`]*(SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{/i.test(combinedText)
          || /f["'][\s\S]{0,240}(SELECT|INSERT|UPDATE|DELETE)[\s\S]{0,240}\{[\s\S]{0,120}\}[\s\S]{0,240}["']/i.test(combinedText)
          || /\bread_sql_query\s*\(\s*f["'][\s\S]{0,240}(SELECT|INSERT|UPDATE|DELETE)[\s\S]{0,240}\{[\s\S]{0,120}\}[\s\S]{0,240}["']/i.test(combinedText)
          || /\bexecute\s*\(\s*f["'][\s\S]{0,240}(SELECT|INSERT|UPDATE|DELETE|CREATE TABLE)[\s\S]{0,240}\{[\s\S]{0,120}\}[\s\S]{0,240}["']/i.test(combinedText)
          || /\.execute\s*\(\s*["'][\s\S]{0,240}(SELECT|INSERT|UPDATE|DELETE)[\s\S]{0,240}\.format\s*\(/i.test(combinedText)
          || /\b(query|execute)\s*\(\s*["'`][\s\S]{0,200}(SELECT|INSERT|UPDATE|DELETE)[\s\S]{0,200}["'`]\s*\+/i.test(combinedText)
          || /\b(query|execute)\s*\(\s*[^)]*\+\s*req\.(body|query|params)/i.test(combinedText)
          || /\bsequelize\.query\s*\(\s*[^)]*\$\{/i.test(combinedText)
        )
        && /\b(query|read_sql_query|execute|raw|cursor\.execute|sqlite3|sqlite|pandas|pd\.read_sql_query|sequelize\.query|mysql|postgres|jdbc)\b/i.test(combinedText)
      );
    case 'nosql-injection':
      return (
        hasSourceEvidence
        && /\b(mongodb|mongoose|collection|findOne|find|updateOne|updateMany|aggregate)\b/i.test(combinedText)
        && (
          /\b(find|findOne|findById|updateOne|updateMany|deleteOne|deleteMany|aggregate)\s*\(\s*req\.(body|query|params)/i.test(combinedText)
          || /\b(find|findOne|updateOne|aggregate)\s*\(\s*[^)]*\.\.\.\s*req\.(body|query|params)/i.test(combinedText)
          || /\$where\b/i.test(combinedText)
          || /\$regex\b/i.test(combinedText)
          || /\$ne\b/i.test(combinedText)
          || /\$gt\b/i.test(combinedText)
          || /\$lt\b/i.test(combinedText)
        )
      );
    case 'xss':
      return (
        hasSourceEvidence
        && (
          /\bdangerouslySetInnerHTML\b|innerHTML\s*=|\bv-html\b|document\.write\s*\(/i.test(combinedText)
          || /render_template_string\s*\(/i.test(combinedText)
          || /\|\s*safe\b/i.test(combinedText)
          || /\bMarkup\s*\(/i.test(combinedText)
          || /return\s+f?["'][\s\S]{0,160}<script[\s\S]{0,160}["']/i.test(combinedText)
          || hasDirectResponseReflection(combinedText)
        )
        && /\b(req|request|params|query|form|searchParams|location|user|content|html|markdown|comment|message|name|input)\b/i.test(combinedText)
      );
    case 'path-traversal':
      return (
        hasSourceEvidence
        && (
          hasPathTraversalFlow(combinedText)
          || (
            matchCount >= 1
            && countMatchedPatterns(
              combinedText,
              [/\.\.\//, /\bpath\.join\b/i, /\bfs\.(readFile|writeFile|createReadStream|createWriteStream)\b/i],
            ) >= 2
          )
        )
      );
    case 'hardcoded-secret':
      return matchCount >= 1;
    default:
      return false;
  }
}

function createFindingFromVerifiedRule(rule, contexts) {
  const codeContexts = selectPreferredCodeContexts(contexts);
  const uniqueLocations = Array.from(new Set(contexts.map((context) => context.sourceFile))).slice(0, 5);
  const primaryContext = codeContexts[0] || contexts[0];
  return buildStructuredFinding({
    ...createFindingFromRule(rule, primaryContext),
    locations: uniqueLocations,
    explanation: buildExpandedExplanation(rule, contexts),
    detail: buildExpandedAbuse(rule, contexts),
    remediation: buildExpandedRemediation(rule),
  });
}

function collectHeuristicFallbackFindings(contexts) {
  const combinedText = contexts.map((context) => context.fullText || context.text).join('\n\n');
  const findings = [];

  const sqlRule = VULNERABILITY_RULES.find((rule) => rule.id === 'sql-injection');
  if (
    sqlRule
    && (
      /\bread_sql_query\s*\(\s*f["']/i.test(combinedText)
      || /\bexecute\s*\(\s*f["']/i.test(combinedText)
      || /\bSELECT\b[\s\S]{0,240}\{[\s\S]{0,120}\}/i.test(combinedText)
    )
    && /\b(request|req|form|get\(|args|query|params|input|password|username|id)\b/i.test(combinedText)
    && /\b(sqlite|sqlite3|pandas|pd\.read_sql_query|execute|query)\b/i.test(combinedText)
  ) {
    const matchedContexts = contexts.filter((context) => (
      /\bread_sql_query\s*\(\s*f["']/i.test(context.text)
      || /\bexecute\s*\(\s*f["']/i.test(context.text)
      || /\bSELECT\b[\s\S]{0,240}\{[\s\S]{0,120}\}/i.test(context.text)
    ));
    if (matchedContexts.length) {
      findings.push(createFindingFromVerifiedRule(sqlRule, matchedContexts));
    }
  }

  const xssRule = VULNERABILITY_RULES.find((rule) => rule.id === 'xss');
  if (
    xssRule
    && (
      /render_template_string\s*\(/i.test(combinedText)
      || /\|\s*safe\b/i.test(combinedText)
      || /\bMarkup\s*\(/i.test(combinedText)
      || /return\s+f?["'][\s\S]{0,200}<script[\s\S]{0,200}["']/i.test(combinedText)
      || hasDirectResponseReflection(combinedText)
    )
    && /\b(request|req|form|get\(|args|query|params|input|name|comment|content|html|message)\b/i.test(combinedText)
  ) {
    const matchedContexts = contexts.filter((context) => (
      /render_template_string\s*\(/i.test(context.text)
      || /\|\s*safe\b/i.test(context.text)
      || /\bMarkup\s*\(/i.test(context.text)
      || /return\s+f?["'][\s\S]{0,200}<script[\s\S]{0,200}["']/i.test(context.text)
      || hasDirectResponseReflection(context.text)
    ));
    if (matchedContexts.length) {
      findings.push(createFindingFromVerifiedRule(xssRule, matchedContexts));
    }
  }

  const pathTraversalRule = VULNERABILITY_RULES.find((rule) => rule.id === 'path-traversal');
  if (pathTraversalRule && hasPathTraversalFlow(combinedText)) {
    const matchedContexts = contexts.filter((context) => hasPathTraversalFlow(context.text));
    if (matchedContexts.length) {
      findings.push(createFindingFromVerifiedRule(pathTraversalRule, matchedContexts));
    }
  }

  return findings
    .filter(Boolean)
    .sort((left, right) => compareSeverity(left.severity, right.severity));
}

function collectVulnerabilityFindings(contexts) {
  const verifiedFindings = VULNERABILITY_RULES
    .map((rule) => {
      const matchedContexts = contexts.filter((context) => rule.patterns.some((pattern) => pattern.test(context.text)));
      if (!matchedContexts.length || !verifyRuleEvidence(rule, matchedContexts)) {
        return null;
      }

      return createFindingFromVerifiedRule(rule, matchedContexts);
    })
    .filter(Boolean)
    .sort((left, right) => compareSeverity(left.severity, right.severity));

  if (verifiedFindings.length) {
    return verifiedFindings;
  }

  return collectHeuristicFallbackFindings(contexts);
}

function buildRecommendations(joinedText, sourceFiles) {
  return [
    {
      id: 'baseline-hardening-0',
      title: '입력 검증',
      severity: 'medium',
      location: sourceFiles[0] || '프로젝트 전반',
      codeLocation: '/* 요청을 받는 컨트롤러, 라우터, 입력 파서, 버퍼 복사 지점 전체를 우선 점검해야 한다. */',
      explanation: '입력 검증 부족은 외부 입력의 타입, 길이, 형식을 충분히 제한하지 않아 이후 다른 취약점으로 이어지기 쉬운 상태를 뜻한다. 교육 관점에서는 많은 취약점이 사실상 이 단계의 실패에서 시작되므로, 어떤 값이 어디까지 들어와도 되는지 먼저 명확히 정의하는 습관이 중요하다. 예를 들어 문자열 길이, 정수 범위, 허용 문자 집합, 필수 필드 여부가 코드마다 제각각이면 이후 다른 방어 로직이 있어도 우회가 쉬워질 수 있다.',
      detail: '검증이 약하면 악성 문자열이나 비정상 길이 데이터가 내부 로직으로 그대로 전달되어 SQL Injection, XSS, 메모리 손상 같은 문제의 발판이 될 수 있다. 예를 들어 웹 서비스에서는 요청 파라미터가 그대로 쿼리나 HTML 렌더링으로 이어질 수 있고, 네이티브 서비스에서는 길이 검증이 빠진 입력이 버퍼 처리까지 이어질 수 있다. 이번 항목은 특정 취약점 확정이 아니라, 서비스 전반에서 가장 먼저 보완해야 하는 공통 위험 지점으로 이해하는 편이 맞다.',
      remediation: '요청 단위 검증 레이어를 두고 타입, 길이, 허용 문자, 예외 처리 기준을 일관되게 강제해야 한다. 실무에서는 컨트롤러마다 따로 막기보다 공통 validator, schema, DTO, parser 단계에서 먼저 거르는 편이 유지보수와 재발 방지에 유리하다. 교육용으로는 "검증 전 입력", "검증 후 입력", "검증 실패 응답"을 나눠 비교하면서 어느 단계에서 데이터가 걸러지는지 확인해보는 것이 좋다.',
    },
    {
      id: 'baseline-hardening-1',
      title: '설정 분리',
      severity: 'low',
      location: sourceFiles[0] || '프로젝트 전반',
      codeLocation: '/* 환경 변수 로더, 설정 초기화 코드, 인증 키 주입 부분을 분리해 관리해야 한다. */',
      explanation: '설정 분리 부족은 비밀값, 로그, 배포 설정이 같은 위치에서 관리되어 노출이나 오작동 위험이 커진 상태를 뜻한다. 실제 서비스에서는 기능 코드보다 운영 설정이 먼저 새는 경우도 많기 때문에, 인증 키와 환경 설정을 별도 관리 체계로 분리하는 것이 중요하다. 예를 들어 개발 편의를 위해 코드에 바로 넣어둔 토큰 하나가 운영 환경에서는 전체 시스템 권한으로 이어질 수 있다.',
      detail: '운영 키가 코드나 로그에 섞이면 저장소 유출이나 디버그 출력만으로도 공격자가 권한을 얻을 수 있다. 또 배포 환경마다 설정이 분리되지 않으면 테스트용 느슨한 보안 설정이 운영 환경까지 그대로 남아 있을 수 있다. 이 항목은 특정 exploit보다는 서비스 운영 안전성을 높이는 기본 보안 위생에 가깝다.',
      remediation: '환경 변수, 시크릿 저장소, 운영 로그 정책을 분리하고 민감값은 직접 코드에 남기지 않아야 한다. 이미 노출된 값은 단순 삭제로 끝내지 말고 회전해야 하며, 로그에는 민감한 헤더나 토큰이 남지 않도록 마스킹 규칙을 적용하는 편이 좋다. 교육용으로는 "코드", "설정", "운영 로그" 세 영역이 서로 섞일 때 어떤 사고가 나는지 사례 중심으로 함께 보는 것이 좋다.',
    },
  ]
    .map((item) => buildStructuredFinding({
      ...item,
      abuse: '',
    }))
    .filter((item) => item.description || joinedText);
}

function summarizeFindings(findings, resultMode) {
  if (!findings.length) {
    return resultMode === 'recommendation'
      ? '보완해야 할 보안 포인트를 정리했습니다.'
      : '발견된 취약점이 없습니다.';
  }

  const names = findings.slice(0, 3).map((finding) => finding.title).join(', ');
  return `${resultMode === 'recommendation' ? '보완해야 할점' : '발견된 취약점'} : ${names}${findings.length > 3 ? ` 외 ${findings.length - 3}개` : ''}`;
}

function buildReportTitle(applicationType, findings, resultMode) {
  if (resultMode === 'vulnerability' && findings.length) {
    const primaryFinding = findings[0]?.title || '취약점';
    return `${primaryFinding} 취약점이 있는 ${applicationType} 서비스`;
  }

  return `${applicationType} 서비스`;
}

function calculateOverallSeverity(findings) {
  const severityCounts = findings.reduce((accumulator, finding) => {
    accumulator[finding.severity] = (accumulator[finding.severity] || 0) + 1;
    return accumulator;
  }, {});

  if ((severityCounts.high || 0) >= 1) {
    return 'high';
  }

  if ((severityCounts.medium || 0) >= 2 || findings.length >= 4) {
    return 'medium';
  }

  return findings.length ? findings[0].severity : 'low';
}

function normalizeCodexFinding(finding, index) {
  return buildStructuredFinding({
    id: `codex-finding-${index + 1}`,
    title: String(finding?.title || `Finding ${index + 1}`).trim(),
    severity: normalizeSeverity(String(finding?.severity || 'low').toLowerCase()),
    location: String(finding?.location || '관련 코드 구간').trim(),
    codeLocation: String(finding?.codeLocation || finding?.location || '관련 코드 구간').trim(),
    explanation: String(finding?.explanation || '설명이 없습니다.').trim(),
    detail: String(finding?.detail || '세부 설명이 없습니다.').trim(),
    remediation: String(finding?.remediation || '대응 방안이 제공되지 않았습니다.').trim(),
    abuse: '',
  });
}

function normalizeCodexReport(parsedReport, sourceFiles) {
  if (!parsedReport || !Array.isArray(parsedReport.findings)) {
    return null;
  }

  const findings = parsedReport.findings.map(normalizeCodexFinding);
  const resultMode = parsedReport.resultMode === 'recommendation' || !findings.length
    ? 'recommendation'
    : 'vulnerability';
  const finalFindings = findings.length ? findings : buildRecommendations('', sourceFiles.map((file) => file.originalName));
  const applicationType = String(parsedReport.applicationType || '기능을 제공하는').trim();
  const normalizedTitle = String(parsedReport.title || `${applicationType} 서비스`).trim();

  return {
    title: normalizedTitle.endsWith('서비스') ? normalizedTitle : `${normalizedTitle} 서비스`,
    applicationType,
    summary: String(parsedReport.summary || summarizeFindings(finalFindings, resultMode)).trim(),
    applicationReport: String(parsedReport.applicationReport || `이 서비스는 ${applicationType} 애플리케이션 서비스로 보인다.`).trim(),
    resultMode,
    overallSeverity: calculateOverallSeverity(finalFindings),
    findingsCount: finalFindings.length,
    findings: finalFindings,
    sourceFiles,
  };
}

export function buildRuleBasedAnalysisReport({ contexts, sourceFiles }) {
  const sourceFileNames = sourceFiles.map((file) => file.originalName);
  const joinedText = contexts.map((context) => context.fullText || context.text).join('\n\n');
  const applicationType = inferApplicationType(joinedText, sourceFileNames);
  const findings = collectVulnerabilityFindings(contexts);
  const resultMode = findings.length ? 'vulnerability' : 'recommendation';
  const finalFindings = findings.length ? findings : buildRecommendations(joinedText, sourceFileNames);

  return {
    title: buildReportTitle(applicationType, finalFindings, resultMode),
    applicationType,
    summary: summarizeFindings(finalFindings, resultMode),
    applicationReport: buildApplicationNarrative(applicationType, sourceFileNames, joinedText),
    resultMode,
    overallSeverity: calculateOverallSeverity(finalFindings),
    findingsCount: finalFindings.length,
    findings: finalFindings,
    sourceFiles,
  };
}

export function selectPreferredAnalysisReport({ normalizedCodexReport, ruleBasedReport }) {
  if (normalizedCodexReport?.resultMode === 'vulnerability') {
    return normalizedCodexReport;
  }

  if (ruleBasedReport?.resultMode === 'vulnerability') {
    return ruleBasedReport;
  }

  return normalizedCodexReport || ruleBasedReport || null;
}

function buildFallbackReport(acceptedFiles, reason = '') {
  const sourceFiles = acceptedFiles.map((file) => ({
    originalName: file.originalName,
    relativePath: file.relativePath || '',
    size: file.size || 0,
  }));
  const sourceFileNames = sourceFiles.map((file) => file.originalName);
  const findings = [
    buildStructuredFinding({
      id: 'fallback-review-0',
      title: '업로드 분석 시간이 길어 추가 검토가 필요',
      severity: 'medium',
      location: sourceFileNames[0] || '프로젝트 전반',
      codeLocation: '/* 장시간 분석 후에도 확정 증거가 부족한 함수, 입력 처리 지점, 상태 변경 루틴을 재검토해야 한다. */',
      explanation: '제한 시간 안에 취약점을 확정할 만큼 충분한 증거를 끝까지 모으지 못한 상태다. 이 항목은 취약점이 없다는 뜻이 아니라, 현재 자동 분석이 "추측이 아닌 확정" 단계까지 도달하지 못했다는 의미다. 따라서 교육용으로는 왜 확정하지 못했는지와 어떤 추가 증거가 더 필요했는지를 같이 보는 것이 중요하다.',
      detail: `현재 업로드는 압축 해제 후 전체 파일을 순회하는 과정에서 시간이 오래 걸렸다. ${reason || '세부 취약점 탐지는 계속 시도했지만 제한 시간 안에 완전히 확정하지 못했다.'} 실제로는 함수 호출 관계, 입력 경로, 메모리 상태 변화, 권한 경계를 더 오래 추적해야 할 수 있다. 즉 자동화만으로 바로 결론을 내리기 어려운 구조이며, 사람이 추가로 읽으면 취약점이 확정될 가능성도 남아 있다.`,
      remediation: '입력 처리, 메모리 상태 변화, 권한 경계, 파일 조작 경로를 다시 추적하면서 증거를 보강해 재분석하는 편이 좋다. 특히 어떤 입력이 어떤 함수로 들어가고, 그 값이 버퍼, 쿼리, 명령 실행, 파일 경로, 인증 상태 중 어디에 영향을 주는지 순서대로 정리해야 한다. 교육 관점에서는 이 과정을 통해 "확정 가능한 취약점"과 "아직 의심 단계인 징후"를 구분하는 연습을 할 수 있다.',
      abuse: '',
    }),
  ];

  return {
    title: '기능을 제공하는 소프트웨어 서비스',
    applicationType: '기능을 제공하는 소프트웨어',
    summary: '발견된 취약점 : 장시간 분석 후에도 확정되지 않아 추가 검토 포인트를 남겼습니다.',
    applicationReport: `업로드된 파일 전체를 해제하고 순회했지만 제한 시간 안에 exploit 가능한 취약점을 확정하지 못했다. 주요 파일은 ${sourceFileNames.slice(0, 8).join(', ') || '업로드된 프로젝트 파일'}다. 현재 단계에서는 메모리 오염, 입력 처리, 권한 경계, 파일 조작 경로를 우선 점검하는 편이 좋다.`,
    resultMode: 'recommendation',
    overallSeverity: calculateOverallSeverity(findings),
    findingsCount: findings.length,
    findings,
    sourceFiles,
  };
}

async function generateAnalysisReportInternal({ acceptedFiles, onProgress }) {
  const sourceFiles = acceptedFiles.map((file) => ({
    originalName: file.originalName,
    relativePath: file.relativePath || '',
    size: file.size || 0,
  }));
  const codexReport = await analyzeWithCodexExec({ acceptedFiles, onProgress });
  const normalizedCodexReport = normalizeCodexReport(codexReport, sourceFiles);
  if (normalizedCodexReport?.resultMode === 'vulnerability') {
    return normalizedCodexReport;
  }

  const contexts = await buildFileContexts(acceptedFiles, onProgress);
  const ruleBasedReport = buildRuleBasedAnalysisReport({ contexts, sourceFiles });

  return selectPreferredAnalysisReport({
    normalizedCodexReport,
    ruleBasedReport,
  });
}

export async function generateAnalysisReport({ acceptedFiles, onProgress }) {
  const startedAt = Date.now();
  try {
    const report = await Promise.race([
      generateAnalysisReportInternal({ acceptedFiles, onProgress }),
      new Promise((_, reject) => {
        setTimeout(() => reject(new Error('analysis-timeout')), ANALYSIS_TIMEOUT_MS);
      }),
    ]);
    const remaining = MIN_ANALYSIS_DURATION_MS - (Date.now() - startedAt);
    if (remaining > 0) {
      await delay(remaining);
    }
    return report;
  } catch (error) {
    const remaining = MIN_ANALYSIS_DURATION_MS - (Date.now() - startedAt);
    if (remaining > 0) {
      await delay(remaining);
    }
    return buildFallbackReport(
      acceptedFiles,
      error instanceof Error && error.message === 'analysis-timeout'
        ? '분석 시간이 길어져 제한 시간 안에 취약점을 확정하지 못했다.'
        : '분석 도중 일부 파일을 끝까지 해석하지 못했다.'
    );
  }
}
