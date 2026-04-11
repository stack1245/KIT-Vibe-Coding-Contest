import 'server-only';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import {
  getArchiveSafetyIssues,
  inspectArchiveFootprint,
  MAX_SAFE_ARCHIVE_ENTRY_COUNT,
  MAX_SAFE_ARCHIVE_TOTAL_UNCOMPRESSED_BYTES,
} from './archive-safety';

const execFileAsync = promisify(execFile);

const ANALYSIS_TIMEOUT_MS = Number(process.env.ANALYSIS_TIMEOUT_MS || 45 * 60 * 1000);
const MAX_TEXT_BYTES = 320 * 1024;
const MAX_TEXT_FILES = 420;
const MAX_BINARY_FILES = 144;
const MAX_CODEX_ARCHIVE_WORKSPACE_FILES = 20;
const MAX_CODEX_MANIFEST_SAMPLE_FILES = 8;
const MAX_WALK_FILES = 100;
const MAX_BINARY_STRINGS = 280;
const MAX_BINARY_SYMBOLS = 220;
const MAX_DISASSEMBLY_LINES = 240;
const MAX_ARCHIVE_CONTEXT_FILES = 320;
const MAX_ARCHIVE_LISTING_ENTRIES = 240;
const MAX_ARCHIVE_PATH_CANDIDATES = 1200;
const MAX_ARCHIVE_SCORE_PREVIEW_BYTES = 8192;
const MAX_INVESTIGATION_TARGETS = 16;
const MIN_ANALYSIS_RECHECK_TIMEOUT_MS = 4 * 60 * 1000;

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
const DEFINITIVE_NO_VULNERABILITY_SUMMARY_PATTERNS = [
  /실행 가능한 코드 경로에서 확정된 취약점이 확인되지 않았습니다\./i,
  /확정된 취약점이 확인되지 않았습니다\./i,
  /취약점이 없습니다\./i,
  /no confirmed vulnerabilities? (were )?found/i,
  /no vulnerabilities? found/i,
];
const CONCRETE_VULNERABILITY_SUMMARY_PATTERNS = [
  /\b(sql injection|sqli|command injection|xss|path traversal|auth bypass|idor|rce|ssrf|nosql injection)\b/i,
  /\b(buffer overflow|format string|heap corruption|hardcoded secret|prototype pollution)\b/i,
  /(권한|인증)\s*우회/i,
  /경로\s*조작/i,
  /명령\s*주입/i,
];

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
    patterns: [
      /\bexecve?\s*\(/i,
      /\bsystem\s*\(/i,
      /\bpopen\s*\(/i,
      /\bCreateProcess(?:A|W)?\s*\(/i,
      /\bos\.system\s*\(/i,
      /\bchild_process\.(exec|execFile|spawn)\s*\(/i,
    ],
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
      /\bpath\.join\b/i,
      /\bpath\.resolve\b/i,
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
    id: 'insecure-default-secret',
    name: 'Insecure Default Secret',
    severity: 'high',
    patterns: [
      /process\.env\.[A-Z0-9_]*(SECRET|TOKEN|KEY|PASSWORD)[A-Z0-9_]*\s*(\|\||\?\?)\s*['"][^'"]{6,}['"]/i,
      /String\s*\(\s*process\.env\.[A-Z0-9_]*(SECRET|TOKEN|KEY|PASSWORD)[A-Z0-9_]*\s*\|\|\s*['"][^'"]{6,}['"]\s*\)/i,
      /os\.getenv\s*\(\s*['"][A-Z0-9_]*(SECRET|TOKEN|KEY|PASSWORD)[A-Z0-9_]*['"]\s*,\s*['"][^'"]{6,}['"]\s*\)/i,
      /getenv\s*\(\s*["'][A-Z0-9_]*(SECRET|TOKEN|KEY|PASSWORD)[A-Z0-9_]*["']\s*\)\s*\?:\s*["'][^"']{6,}["']/i,
    ],
    locationHint: '비밀값 환경 변수를 읽으며 하드코딩 기본값을 두는 지점',
    detail: '운영 환경 변수 누락만으로 누구나 예측 가능한 기본 시크릿이 활성화되면 세션 위조, 토큰 위조, 내부 API 접근 우회로 바로 이어질 수 있다.',
    remediation: '운영에서는 비밀값 누락 시 즉시 실패하게 만들고, 개발 편의용 기본 시크릿은 운영 경로에서 절대 허용하지 말아야 한다.',
    explanation: 'Insecure Default Secret은 인증 키나 세션 시크릿이 비어 있을 때 예측 가능한 기본값으로 대체되어 공격자가 서명이나 토큰을 쉽게 위조할 수 있게 되는 취약점이다.',
  },
  {
    id: 'host-header-poisoning',
    name: 'Host Header Poisoning',
    severity: 'medium',
    patterns: [
      /\bx-forwarded-host\b/i,
      /\bx-forwarded-proto\b/i,
      /\bheaders\.get\s*\(\s*['"]host['"]\s*\)/i,
      /\bredirect[_-]?uri\b/i,
      /\bNextResponse\.redirect\b/i,
      /\bredirect\s*\(/i,
      /\blocation\s*:/i,
    ],
    locationHint: 'Host/X-Forwarded-* 헤더로 절대 URL이나 redirect 주소를 만드는 지점',
    detail: '신뢰되지 않은 Host 또는 X-Forwarded-* 헤더를 redirect URL, OAuth callback, 공유 링크 생성에 쓰면 공격자가 임의 도메인으로 사용자를 유도하거나 인증 흐름을 오염시킬 수 있다.',
    remediation: '절대 URL은 고정된 APP_BASE_URL 같은 서버 설정에서 만들고, 프록시 헤더는 신뢰 가능한 프록시가 정제하는 환경에서만 명시적으로 허용해야 한다.',
    explanation: 'Host Header Poisoning은 요청 헤더의 host 정보가 절대 URL이나 redirect 생성에 그대로 반영되어 open redirect, OAuth redirect 오염, 링크 위조로 이어지는 취약점이다.',
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

const MEMORY_CORRUPTION_RULE_IDS = new Set([
  'heap-corruption',
  'fsop',
  'stack-overflow',
  'format-string',
  'arbitrary-write',
]);

const RUNTIME_SOURCE_RULE_IDS = new Set([
  'command-injection',
  'sql-injection',
  'nosql-injection',
  'xss',
  'path-traversal',
  'insecure-default-secret',
  'host-header-poisoning',
  'hardcoded-secret',
]);

function normalizeSeverity(value) {
  return ['high', 'medium', 'low'].includes(value) ? value : 'low';
}

function normalizeExploitability(value) {
  const normalized = String(value || '').trim();
  if (/가정/.test(normalized)) {
    return '가정 기반 가능';
  }
  return '실제 exploit 가능';
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
  if (/docs?\/|examples?\/|samples?\/|demo\/|tutorial\/|__snapshots__\/|snapshots?\/|backup|\.bak(\.|$)|\.backup(\.|$)|\.old(\.|$)|\.orig(\.|$)/i.test(lowered)) score -= 9;
  if (/\.(png|jpg|jpeg|gif|webp|svg|mp3|mp4|mov|avi|pdf|docx?|xlsx?|pptx?|ttf|woff2?)$/i.test(lowered)) score -= 10;

  return score;
}

function isLikelyLogicBearingArchivePath(relativePath) {
  const normalizedPath = String(relativePath || '').replace(/\\/g, '/');
  const lowered = normalizedPath.toLowerCase();
  const baseName = normalizeBaseName(lowered);
  const extension = path.extname(lowered);
  const hints = getPathClassificationHints(normalizedPath);

  if (
    hints.isAssetPath
    || hints.isStylePath
    || hints.isTestPath
    || hints.isDocPath
    || hints.isExamplePath
    || hints.isBackupPath
  ) {
    return false;
  }

  if (PROJECT_MARKERS.has(baseName)) {
    return true;
  }

  if (TEXT_EXTENSIONS.has(extension) || REVIEWABLE_BINARY_EXTENSIONS.has(extension)) {
    return true;
  }

  return /(^|\/)(app|src|pages|api|routes?|controllers?|handlers?|services?|lib|server|client|components|models?|repositories?|workers?|jobs?|middlewares?|auth|session|db|database|queries?)(\/|$)/i.test(normalizedPath);
}

function getInterestingArchiveTextScore(text) {
  const snippet = String(text || '').slice(0, MAX_ARCHIVE_SCORE_PREVIEW_BYTES);
  if (!snippet.trim()) {
    return 0;
  }

  let score = 0;

  if (/\b(import|from|require|module\.exports|export\s+default|package\s+main)\b/.test(snippet)) score += 3;
  if (/\b(app|router)\.(get|post|put|delete|patch|use)\s*\(|@app\.route|@(?:Get|Post|Put|Delete|RequestMapping)|\bFastAPI\b|\bAPIRouter\b|\bBlueprint\b/.test(snippet)) score += 10;
  if (/\b(createServer|app\.listen|server\.listen|uvicorn|gunicorn|main\s*\(|public\s+static\s+void\s+main)\b/.test(snippet)) score += 8;
  if (/\b(login|signup|session|cookie|token|jwt|auth|role|permission)\b/i.test(snippet)) score += 5;
  if (/\b(select|insert|update|delete|query|execute|cursor\.execute|read_sql_query|sequelize\.query|sqlite3|mongodb|mongoose)\b/i.test(snippet)) score += 6;
  if (/\b(render_template_string|dangerouslySetInnerHTML|innerHTML|send_file|open\s*\(|os\.system|system\s*\(|execve?\s*\(|popen\s*\()\b/i.test(snippet)) score += 6;
  if (/\b(readme|usage|installation|example|tutorial)\b/i.test(snippet) && !/\b(import|def |class |function |const |let |var |app\.|router\.)\b/.test(snippet)) score -= 8;
  if ((snippet.match(/\n/g) || []).length < 3 && snippet.length > 2000) score -= 6;

  return score;
}

function getInterestingArchiveCandidateScore(candidate, relativePath) {
  const baseScore = getInterestingArchiveEntryScore(relativePath);
  const logicBoost = isLikelyLogicBearingArchivePath(relativePath) ? 10 : 0;

  if (baseScore + logicBoost <= 0) {
    return baseScore + logicBoost;
  }

  if (!isLikelyTextFile(candidate)) {
    return baseScore + logicBoost;
  }

  return baseScore + logicBoost + getInterestingArchiveTextScore(readTextSnippet(candidate).slice(0, MAX_ARCHIVE_SCORE_PREVIEW_BYTES));
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

function createArchiveSafetyContext(fileName, issues = []) {
  const text = [
    `ARCHIVE SAFETY NOTICE: ${fileName}`,
    `압축 해제를 건너뛰었습니다: ${issues.join(', ') || 'archive-safety-check-failed'}`,
    `최대 허용 항목 수: ${MAX_SAFE_ARCHIVE_ENTRY_COUNT}`,
    `최대 허용 압축 해제 크기: ${MAX_SAFE_ARCHIVE_TOTAL_UNCOMPRESSED_BYTES} bytes`,
  ].join('\n');

  return {
    sourceFile: `${fileName}:archive-safety`,
    kind: 'text',
    text,
    fullText: text,
    evidenceRole: 'supporting',
    runtimeEligible: false,
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

function normalizeSourcePath(value) {
  return String(value || '').replace(/\\/g, '/');
}

function getPathClassificationHints(sourceFile) {
  const normalizedPath = normalizeSourcePath(sourceFile).toLowerCase();

  return {
    normalizedPath,
    isArchiveIndex: normalizedPath.endsWith(':archive-index'),
    isTestPath: /(^|\/)(test|tests|__tests__|spec|specs|fixtures?|mocks?)(\/|$)|\.(test|spec)\./i.test(normalizedPath),
    isDocPath: /(^|\/)(docs?|documentation)(\/|$)|(^|\/)(readme|changelog|license|notes?)(\.|$)|\.(md|rst|adoc)$/i.test(normalizedPath),
    isExamplePath: /(^|\/)(examples?|samples?|demo|tutorial)(\/|$)/i.test(normalizedPath),
    isBackupPath: /(^|\/)(__snapshots__|snapshots?|backups?)(\/|$)|\.(bak|backup|old|orig)(\.|$)|backup-\d{4}-\d{2}-\d{2}/i.test(normalizedPath),
    isStylePath: /\.(css|scss|sass|less)$/i.test(normalizedPath),
    isAssetPath: /\.(png|jpg|jpeg|gif|webp|svg|mp3|mp4|mov|avi|pdf|woff2?|ttf)$/i.test(normalizedPath),
    isConfigPath: /(^|\/)\.?env(\.|$)|(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|tsconfig\.json|eslint|prettier|vite\.config|vitest\.config|next\.config|docker-compose|dockerfile|makefile)(\.|$)|\.(ya?ml|toml|ini|properties)$/i.test(normalizedPath),
  };
}

function isLikelySecurityToolingContext(context) {
  const hints = getPathClassificationHints(context?.sourceFile || '');
  const safeText = String(context?.fullText || context?.text || '');
  const regexSignalEntries = (safeText.match(/\{\s*regex:\s*\/[\s\S]{0,240}?\/[dgimsuy]*\s*,\s*signal:\s*['"]/g) || []).length;
  const vulnerabilityRuleEntries = (safeText.match(/\bpatterns\s*:\s*\[/g) || []).length;
  const structuredRuleEntries = (safeText.match(/\b(locationHint|detail|remediation|explanation)\s*:/g) || []).length;
  const patternTableMarkers = /\b(EXPLICIT_VULNERABILITY_PATTERNS|TEXT_PROGRAM_PROFILE_RULES|BINARY_RISK_PATTERNS|BINARY_LOGIC_PATTERNS|collectPatternSignals|collectExplicitVulnerabilitySignals|inferTextProgramProfile|inferBinaryProgramProfile)\b/.test(safeText);
  const ruleEngineMarkers = /\b(VULNERABILITY_RULES|collectVulnerabilityFindings|verifyRuleEvidence|buildStructuredFinding|createFindingFromRule|buildCodexFinalReportPrompt|buildCodexReconPrompt)\b/.test(safeText);
  const toolingPath = /(^|\/)(upload-screening|analysis-report|analysis-job-runner|scanner|screening|signature|rules?)(\.|\/|$)/i.test(hints.normalizedPath);
  const looksLikeRuleDefinitionTable = vulnerabilityRuleEntries >= 3 && structuredRuleEntries >= 6;

  return (
    (regexSignalEntries >= 6 && (patternTableMarkers || toolingPath))
    || (toolingPath && (patternTableMarkers || ruleEngineMarkers || looksLikeRuleDefinitionTable))
    || (ruleEngineMarkers && looksLikeRuleDefinitionTable)
  );
}

function isLikelySignatureSnippet(snippet) {
  const safeText = String(snippet || '');
  const regexMentions = (safeText.match(/\bregex\s*:/g) || []).length;
  const signalMentions = (safeText.match(/\bsignal\s*:/g) || []).length;
  const regexLiteralEntries = (safeText.match(/\/(?:\\.|[^/\n])+\/[dgimsuy]*/g) || []).length;
  const ruleKeyMentions = (safeText.match(/\b(patterns|locationHint|detail|remediation|explanation)\s*:/g) || []).length;
  const ruleEngineMarkers = /\b(VULNERABILITY_RULES|BINARY_RISK_PATTERNS|BINARY_LOGIC_PATTERNS|EXPLICIT_VULNERABILITY_PATTERNS|collectPatternSignals|collectExplicitVulnerabilitySignals)\b/.test(safeText);
  const looksLikeRegexArraySnippet = regexLiteralEntries >= 3 && String(safeText).split('\n').length <= 12;

  return (
    (regexMentions >= 1 && signalMentions >= 1)
    || ruleKeyMentions >= 2
    || ruleEngineMarkers
    || looksLikeRegexArraySnippet
  );
}

function isLikelyIllustrativeTextContext(context) {
  if (!context || context.kind !== 'text') {
    return false;
  }

  const hints = getPathClassificationHints(context.sourceFile);
  if ((hints.isTestPath || hints.isDocPath || hints.isExamplePath || hints.isBackupPath) && !context.embeddedSourceFile) {
    return true;
  }

  const safeText = String(context.fullText || context.text || '');
  const exampleMarkers = countMatchedPatterns(safeText, [
    /\b(example|sample|fixture|mock|demo|tutorial)\b/i,
    /^\s*[-*]\s+(sql injection|command injection|buffer overflow|path traversal|hardcoded secret|xss)\b/im,
    /\b(sql injection|command injection|buffer overflow|path traversal|hardcoded secret|xss)\s+example\b/i,
  ]);
  const testHarnessMarkers = countMatchedPatterns(safeText, [
    /\bdescribe\s*\(/,
    /\bit\s*\(/,
    /\btest\s*\(/,
    /\bexpect\s*\(/,
    /\bto(Be|Equal|Contain|Match)\s*\(/,
  ]);

  return exampleMarkers >= 2 || (exampleMarkers >= 1 && testHarnessMarkers >= 2);
}

function normalizeComparableText(value) {
  return String(value || '')
    .replace(/\r/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

function stripCodeLocationLineNumbers(snippet) {
  return String(snippet || '')
    .split('\n')
    .map((line) => line.replace(/^\s*\d+:\s?/, '').trimEnd())
    .join('\n')
    .trim();
}

function extractFencedCodeBlocks(text) {
  const blocks = [];
  const pattern = /```[^\n]*\n([\s\S]*?)```/g;
  let match = pattern.exec(String(text || ''));

  while (match) {
    const content = String(match[1] || '').trim();
    if (content) {
      blocks.push(content);
    }
    match = pattern.exec(String(text || ''));
  }

  return blocks;
}

function classifyTextContext(text, sourceFile) {
  const safeText = String(text || '');
  const hints = getPathClassificationHints(sourceFile);
  const fencedBlocks = extractFencedCodeBlocks(safeText);
  const fencedCodeBytes = fencedBlocks.reduce((total, block) => total + block.length, 0);

  const codeScore = countMatchedPatterns(safeText, [
    /(^|\n)\s*(import|export|from|const|let|var|function|class|async function|module\.exports|require\(|def |async def |fn |pub fn |package\s+[a-zA-Z_][\w.]*\s*;|use\s+[a-zA-Z_][\w:]*\s*;|#include\s*[<"])/m,
    /\b(app|router)\.(get|post|put|delete|patch)\s*\(/i,
    /@(?:app\.route|Get|Post|Put|Delete|RequestMapping|RestController)\b/i,
    /\breturn\b[\s\S]{0,120}[;}]?/i,
    /\b(if|else|for|while|switch|case|try|catch)\b/i,
    /=>|::|->/,
    /[{;}]/,
    /\b(SELECT|INSERT|UPDATE|DELETE)\b/i,
  ]);
  const frameworkScore = countMatchedPatterns(safeText, [
    /\b(app|router)\.(get|post|put|delete|patch|use)\s*\(/i,
    /@(?:app\.route|Get|Post|Put|Delete|RequestMapping|RestController|SpringBootApplication)\b/i,
    /\b(createServer|app\.listen|server\.listen|uvicorn|gunicorn|FastAPI|Express|NextResponse|NextRequest)\b/i,
    /\bexport\s+default\s+function\b/i,
  ]);
  const entrypointScore = countMatchedPatterns(safeText, [
    /\bint\s+main\s*\(/,
    /\bpublic\s+static\s+void\s+main\s*\(/,
    /\bif\s+__name__\s*==\s*['"]__main__['"]/,
    /\bmodule\.exports\b|\bexport\s+default\b|\bapp\.listen\s*\(/i,
  ]);
  const dataflowScore = countMatchedPatterns(safeText, [
    /\b(req|request)\.(body|query|params|args|form|values)\b/i,
    /\b(query|execute|read_sql_query|findOne|find|updateOne|aggregate|dangerouslySetInnerHTML|innerHTML|system|execve|popen|send_file|FileResponse|fs\.(readFile|writeFile))\b/i,
  ]);
  const nativeCodeScore = countMatchedPatterns(safeText, [
    /#include\s*[<"]/,
    /\bint\s+main\s*\(/,
    /\b(malloc|calloc|realloc|free|printf|scanf|fgets|read|write|memcpy|strcpy)\s*\(/,
    /\bstruct\s+[a-zA-Z_]\w*/i,
    /\*\s*[a-zA-Z_]\w+/,
  ]);
  const docScore = countMatchedPatterns(safeText, [
    /^#{1,6}\s+/m,
    /^\s*[-*+]\s+/m,
    /^\s*\d+\.\s+/m,
    /\b(readme|usage|installation|example|tutorial|guide|문서|설명|사용법)\b/i,
  ]);
  const testScore = countMatchedPatterns(safeText, [
    /\b(describe|it|test|expect|assert|beforeEach|afterEach|pytest|unittest|vitest|jest)\b/i,
    /\b(mock|fixture|stub|fake)\b/i,
  ]);
  const styleScore = countMatchedPatterns(safeText, [
    /^\s*[.#@]?[a-zA-Z0-9:_\-\[\]="'() >+,]+{\s*$/m,
    /\b(color|background|font|padding|margin|border|display|grid|flex|animation|box-shadow)\s*:/i,
    /::(before|after|placeholder)\b/,
    /var\(--[a-z0-9-]+\)/i,
  ]);
  const configScore = countMatchedPatterns(safeText, [
    /^\s*[\w.-]+\s*:\s*.+$/m,
    /^\s*[\w.-]+\s*=\s*.+$/m,
    /^{\s*"[\w.-]+"/m,
  ]);
  const executionScore = codeScore + (frameworkScore * 2) + (entrypointScore * 2) + dataflowScore + (nativeCodeScore * 2);
  const sourceDumpLike = fencedCodeBytes >= 120 && fencedCodeBytes >= Math.max(100, Math.floor(safeText.length * 0.35));

  const documentationDominates = (docScore + Number(hints.isDocPath) * 2 + Number(hints.isExamplePath)) >= executionScore + 4;
  const testDominates = (testScore + Number(hints.isTestPath) * 3) >= executionScore + 4;
  const styleDominates = (styleScore + Number(hints.isStylePath) * 3) >= executionScore + 4;
  const configDominates = (configScore + Number(hints.isConfigPath) * 3) >= executionScore + 4;

  if (hints.isArchiveIndex) {
    return {
      evidenceRole: 'metadata',
      runtimeEligible: false,
      nativeLike: false,
    };
  }

  if (hints.isAssetPath) {
    return {
      evidenceRole: 'asset',
      runtimeEligible: false,
      nativeLike: false,
    };
  }

  if (styleDominates && frameworkScore === 0 && entrypointScore === 0) {
    return {
      evidenceRole: 'style',
      runtimeEligible: false,
      nativeLike: false,
    };
  }

  if (executionScore >= 8 || (sourceDumpLike && executionScore >= 4)) {
    return {
      evidenceRole: 'runtime-source',
      runtimeEligible: true,
      nativeLike: nativeCodeScore >= 2,
    };
  }

  if (hints.isTestPath && !sourceDumpLike && executionScore < 8 && frameworkScore === 0 && entrypointScore === 0 && nativeCodeScore < 2) {
    return {
      evidenceRole: 'test',
      runtimeEligible: false,
      nativeLike: false,
    };
  }

  if (testDominates && frameworkScore === 0 && entrypointScore === 0 && dataflowScore === 0) {
    return {
      evidenceRole: 'test',
      runtimeEligible: false,
      nativeLike: false,
    };
  }

  if (hints.isDocPath && !sourceDumpLike && executionScore < 8 && frameworkScore === 0 && entrypointScore === 0 && nativeCodeScore < 2) {
    return {
      evidenceRole: 'documentation',
      runtimeEligible: false,
      nativeLike: false,
    };
  }

  if (documentationDominates && !sourceDumpLike && frameworkScore === 0 && entrypointScore === 0 && dataflowScore === 0) {
    return {
      evidenceRole: 'documentation',
      runtimeEligible: false,
      nativeLike: false,
    };
  }

  if (configDominates && entrypointScore === 0 && frameworkScore === 0 && dataflowScore === 0) {
    return {
      evidenceRole: 'config',
      runtimeEligible: false,
      nativeLike: false,
    };
  }

  return {
    evidenceRole: 'runtime-source',
    runtimeEligible: (
      executionScore >= 6
      || nativeCodeScore >= 1
      || sourceDumpLike
      || (executionScore >= 4 && (frameworkScore > 0 || entrypointScore > 0 || dataflowScore > 0))
    ),
    nativeLike: nativeCodeScore >= 2,
  };
}

function extractEmbeddedRuntimeContextsFromText(text, sourceFile) {
  const blocks = extractFencedCodeBlocks(text);
  const totalCodeBytes = blocks.reduce((total, block) => total + block.length, 0);

  if (totalCodeBytes < 120 || totalCodeBytes < Math.max(100, Math.floor(String(text || '').length * 0.35))) {
    return [];
  }

  return blocks
    .map((block, index) => {
      const blockSourceFile = `${sourceFile}#codeblock${index + 1}`;
      const classification = classifyTextContext(block, blockSourceFile);
      if (!classification.runtimeEligible || classification.evidenceRole !== 'runtime-source') {
        return null;
      }

      return {
        sourceFile: blockSourceFile,
        text: block.slice(0, 32000),
        kind: 'text',
        fullText: block,
        embeddedSourceFile: sourceFile,
        ...classification,
      };
    })
    .filter(Boolean);
}

function enrichAnalysisContext(context) {
  if (!context) {
    return null;
  }

  if (context.evidenceRole) {
    return context;
  }

  if (context.kind === 'binary') {
    return {
      ...context,
      evidenceRole: 'runtime-binary',
      runtimeEligible: true,
      nativeLike: true,
    };
  }

  const classification = classifyTextContext(context.fullText || context.text, context.sourceFile);
  return {
    ...context,
    ...classification,
  };
}

function normalizeAnalysisContexts(contexts = []) {
  const normalized = [];
  const seen = new Set();

  contexts.forEach((context) => {
    const enriched = enrichAnalysisContext(context);
    if (enriched) {
      const key = `${enriched.sourceFile}::${enriched.kind}`;
      if (!seen.has(key)) {
        seen.add(key);
        normalized.push(enriched);
      }
    }

    if (
      context?.kind === 'text'
      && !context?.embeddedSourceFile
      && !String(context?.sourceFile || '').includes('#codeblock')
    ) {
      extractEmbeddedRuntimeContextsFromText(context.fullText || context.text, context.sourceFile)
        .forEach((embeddedContext) => {
          const key = `${embeddedContext.sourceFile}::${embeddedContext.kind}`;
          if (!seen.has(key)) {
            seen.add(key);
            normalized.push(embeddedContext);
          }
        });
    }
  });

  return normalized.filter(Boolean);
}

function isDeepRuntimeContext(context) {
  if (!context?.runtimeEligible) {
    return false;
  }

  if (context.kind === 'binary') {
    return true;
  }

  const hints = getPathClassificationHints(context.sourceFile);
  const safeText = String(context.fullText || context.text || '');
  const hasStrongRuntimeStructure = (
    /\b(app|router)\.(get|post|put|delete|patch|use)\s*\(/i.test(safeText)
    || /@(?:app\.route|Get|Post|Put|Delete|RequestMapping|RestController|SpringBootApplication)\b/i.test(safeText)
    || /\b(createServer|app\.listen|server\.listen|uvicorn|gunicorn|FastAPI|Express)\b/i.test(safeText)
    || /\bint\s+main\s*\(/.test(safeText)
    || /\bpublic\s+static\s+void\s+main\s*\(/.test(safeText)
  );

  if ((hints.isDocPath || hints.isExamplePath) && !context.embeddedSourceFile) {
    return false;
  }

  if (hints.isBackupPath && !context.embeddedSourceFile) {
    return false;
  }

  if (hints.isTestPath && !context.embeddedSourceFile) {
    return false;
  }

  return true;
}

function getRuntimeEvidenceContexts(contexts = []) {
  return normalizeAnalysisContexts(contexts).filter(isDeepRuntimeContext);
}

function getRuleCandidateContexts(contexts, rule) {
  return normalizeAnalysisContexts(contexts).filter((context) => {
    if (
      !isDeepRuntimeContext(context)
      || isLikelySecurityToolingContext(context)
      || isLikelyIllustrativeTextContext(context)
      || !rule.patterns.some((pattern) => pattern.test(context.text))
    ) {
      return false;
    }

    if (MEMORY_CORRUPTION_RULE_IDS.has(rule.id)) {
      return context.kind === 'binary' || context.nativeLike;
    }

    if (RUNTIME_SOURCE_RULE_IDS.has(rule.id)) {
      return context.kind === 'text' && context.evidenceRole === 'runtime-source';
    }

    return true;
  });
}

function groupContextsBySourceFile(contexts = []) {
  const groups = new Map();

  contexts.forEach((context) => {
    const key = String(context.sourceFile || '');
    if (!groups.has(key)) {
      groups.set(key, []);
    }

    groups.get(key).push(context);
  });

  return Array.from(groups.values());
}

function getCodexFindingRuleId(finding) {
  const title = String(finding?.title || '').trim().toLowerCase();

  if (title.includes('heap corruption')) return 'heap-corruption';
  if (title.includes('fsop')) return 'fsop';
  if (title.includes('buffer overflow')) return 'stack-overflow';
  if (title.includes('format string')) return 'format-string';
  if (title.includes('arbitrary write')) return 'arbitrary-write';
  if (title.includes('command injection')) return 'command-injection';
  if (title.includes('sql injection')) return 'sql-injection';
  if (title.includes('nosql injection')) return 'nosql-injection';
  if (title.includes('xss')) return 'xss';
  if (title.includes('path traversal')) return 'path-traversal';
  if (title.includes('insecure default secret') || title.includes('default secret') || title.includes('session forgery')) return 'insecure-default-secret';
  if (title.includes('host header poisoning') || title.includes('host header trust') || title.includes('open redirect') || title.includes('oauth redirect')) return 'host-header-poisoning';
  if (title.includes('hardcoded secret')) return 'hardcoded-secret';
  return '';
}

function getCodexFindingMatchedContexts(finding, contexts) {
  const runtimeContexts = getRuntimeEvidenceContexts(contexts);
  if (!runtimeContexts.length) {
    return [];
  }

  const locationText = normalizeComparableText([finding?.location, finding?.codeLocation].filter(Boolean).join('\n'));
  const normalizedSnippet = normalizeComparableText(stripCodeLocationLineNumbers(finding?.codeLocation || ''));

  return runtimeContexts.filter((context) => {
    const normalizedSource = normalizeSourcePath(context.sourceFile).toLowerCase();
    const baseName = path.basename(normalizedSource);
    if (locationText.includes(normalizedSource) || (baseName && locationText.includes(baseName))) {
      return true;
    }

    if (normalizedSnippet.length >= 24) {
      const haystack = normalizeComparableText(context.fullText || context.text);
      return haystack.includes(normalizedSnippet);
    }

    return false;
  });

}

function hasCodexContextAnchor(finding, contexts) {
  return getCodexFindingMatchedContexts(finding, contexts).length > 0;
}

function hasValidatedCodexEvidence(finding, contexts) {
  const rawSnippet = stripCodeLocationLineNumbers(finding?.codeLocation || '');
  if (isLikelySignatureSnippet(rawSnippet)) {
    return false;
  }

  const matchedContexts = getCodexFindingMatchedContexts(finding, contexts)
    .filter((context) => !isLikelySecurityToolingContext(context) && !isLikelyIllustrativeTextContext(context));
  if (!matchedContexts.length) {
    return false;
  }

  const ruleId = getCodexFindingRuleId(finding);
  const matchedRule = VULNERABILITY_RULES.find((rule) => rule.id === ruleId);

  if (MEMORY_CORRUPTION_RULE_IDS.has(ruleId)) {
    return matchedContexts.some((context) => context.kind === 'binary' || context.nativeLike)
      && (!matchedRule || verifyRuleEvidence(matchedRule, matchedContexts));
  }

  if (RUNTIME_SOURCE_RULE_IDS.has(ruleId)) {
    return matchedContexts.some((context) => context.kind === 'text' && context.evidenceRole === 'runtime-source')
      && (!matchedRule || verifyRuleEvidence(matchedRule, matchedContexts));
  }

  return matchedRule ? verifyRuleEvidence(matchedRule, matchedContexts) : true;
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

function normalizeInvestigationTargetPath(value) {
  const normalized = normalizeSourcePath(value);
  return normalized.replace(/^.+\.(zip|jar|apk|xapk|ipa|tar|tgz|txz)(:[^/]+\/)/i, '$2').replace(/^:/, '');
}

function collectHighRiskInvestigationTargets({ contexts = [], reconnaissanceReport = null } = {}) {
  const targets = new Map();
  const addTarget = (targetPath, why, score = 0) => {
    const normalizedPath = normalizeInvestigationTargetPath(targetPath);
    if (!normalizedPath) {
      return;
    }

    const existing = targets.get(normalizedPath);
    if (!existing || existing.score < score) {
      targets.set(normalizedPath, {
        path: normalizedPath,
        why: compactReportText(String(why || '고위험 로직 후보').trim(), { maxLength: 120, maxSentences: 1 }),
        score,
      });
    }
  };

  const runtimeContexts = getRuntimeEvidenceContexts(contexts)
    .filter((context) => !isLikelySecurityToolingContext(context) && !isLikelyIllustrativeTextContext(context));

  runtimeContexts.forEach((context) => {
    const targetPath = context.embeddedSourceFile || context.sourceFile;
    const combinedText = `${normalizeSourcePath(targetPath)}\n${String(context.fullText || context.text || '')}`;
    const reasons = [];
    let score = 0;

    if (/(^|\/)(app\/api|api|routes?|controllers?|handlers?|middlewares?|server|services?)\//i.test(combinedText) || /(^|\/)route\.(js|ts|jsx|tsx|py|php|java|go|rb|cs)$/i.test(combinedText)) {
      reasons.push('요청 엔트리포인트');
      score += 6;
    }
    if (/\b(auth|login|signup|session|cookie|token|jwt|oauth|password|role|permission|owner(ship)?|userId|accountId)\b/i.test(combinedText)) {
      reasons.push('인증 또는 권한');
      score += 5;
    }
    if (/\b(process\.env\.[A-Z0-9_]*(SECRET|TOKEN|KEY|PASSWORD)|os\.getenv\s*\(|getenv\s*\(|secret|api[_-]?key)\b/i.test(combinedText)) {
      reasons.push('시크릿 또는 설정');
      score += 5;
    }
    if (/\b(x-forwarded-host|x-forwarded-proto|host['"]?\)|redirect[_-]?uri|shareUrl|origin|location\s*:|NextResponse\.redirect|redirect\s*\()\b/i.test(combinedText)) {
      reasons.push('redirect 또는 origin');
      score += 4;
    }
    if (/\b(query|execute|read_sql_query|findOne|findById|updateOne|updateMany|deleteOne|deleteMany|insert|update|delete|database|db|sqlite|postgres|mysql|mongo)\b/i.test(combinedText)) {
      reasons.push('데이터 저장소');
      score += 4;
    }
    if (/\b(upload|download|file|path|fs\.|open\s*\(|send_file|FileResponse|createReadStream|createWriteStream)\b/i.test(combinedText)) {
      reasons.push('파일 처리');
      score += 3;
    }

    if (score >= 7) {
      addTarget(targetPath, reasons.join(', '), score);
    }
  });

  const reconTargets = Array.isArray(reconnaissanceReport?.highRiskRecheckTargets)
    ? reconnaissanceReport.highRiskRecheckTargets
    : [];
  reconTargets.forEach((target, index) => {
    addTarget(target, '1차 구조 분석에서 재검증 대상으로 지목된 파일', 11 - Math.min(index, 5));
  });

  const reconEntrypoints = Array.isArray(reconnaissanceReport?.entrypoints)
    ? reconnaissanceReport.entrypoints
    : [];
  reconEntrypoints.forEach((entrypoint, index) => {
    const entryPath = String(entrypoint?.path || '').trim();
    if (!entryPath) {
      return;
    }
    addTarget(entryPath, `외부 입력 엔트리포인트${entrypoint?.why ? `: ${entrypoint.why}` : ''}`, 10 - Math.min(index, 5));
  });

  return Array.from(targets.values())
    .sort((left, right) => right.score - left.score || left.path.localeCompare(right.path))
    .slice(0, MAX_INVESTIGATION_TARGETS)
    .map(({ score, ...target }) => target);
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

function extractFirstSnippetLineNumber(snippet) {
  const match = String(snippet || '').match(/^\s*(\d+):/m);
  return match ? Number(match[1]) : null;
}

function formatFindingLocation(location, codeLocation) {
  const normalizedLocation = String(location || '').trim();
  const lineNumber = extractFirstSnippetLineNumber(codeLocation);

  if (!normalizedLocation) {
    return lineNumber ? `관련 코드 구간:${lineNumber}` : '관련 코드 구간';
  }

  if (!lineNumber || /:\d+\b/.test(normalizedLocation)) {
    return normalizedLocation;
  }

  return `${normalizedLocation}:${lineNumber}`;
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
      return [];
    }

    return [
      {
        sourceFile: label,
        text: text.slice(0, 32000),
        kind: 'text',
        fullText: text,
      },
      ...extractEmbeddedRuntimeContextsFromText(text, label),
    ];
  }

  const detectedKind = await detectFileKind(filePath);

  if (detectedKind === 'text') {
    const text = readTextSnippet(filePath);
    if (!text) {
      return [];
    }

    return [
      {
        sourceFile: label,
        text: text.slice(0, 32000),
        kind: 'text',
        fullText: text,
      },
      ...extractEmbeddedRuntimeContextsFromText(text, label),
    ];
  }

  if (detectedKind === 'binary') {
    const context = await inspectBinaryPath(filePath, label);
    return context ? [context] : [];
  }

  return [];
}

async function collectContextFromArchive(file, onProgress) {
  const extension = detectArchiveExtension(file.originalName);
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'phase-analysis-archive-'));

  try {
    const archiveEntries = await listArchiveEntries(file.absolutePath, extension).catch(() => []);
    const listingContext = createArchiveListingContext(file.originalName, archiveEntries);
    const footprint = await inspectArchiveFootprint(file.absolutePath, extension, {
      zipArchiveExtensions: Array.from(ZIP_ARCHIVE_EXTENSIONS),
      timeoutMs: 15000,
      maxBuffer: 2 * 1024 * 1024,
    }).catch(() => ({ entryCount: archiveEntries.length, totalUncompressedBytes: 0 }));
    const archiveSafetyIssues = getArchiveSafetyIssues({
      entries: archiveEntries,
      entryCount: footprint.entryCount || archiveEntries.length,
      totalUncompressedBytes: footprint.totalUncompressedBytes || 0,
      maxEntries: MAX_SAFE_ARCHIVE_ENTRY_COUNT,
      maxTotalBytes: MAX_SAFE_ARCHIVE_TOTAL_UNCOMPRESSED_BYTES,
    });

    if (archiveSafetyIssues.length) {
      return [listingContext, createArchiveSafetyContext(file.originalName, archiveSafetyIssues)].filter(Boolean);
    }

    await extractArchiveToDirectory(file.absolutePath, extension, tempDir);
    const files = walkDirectory(tempDir)
      .map((candidate) => ({
        candidate,
        relativePath: path.relative(tempDir, candidate).split(path.sep).join('/'),
        score: getInterestingArchiveEntryScore(path.relative(tempDir, candidate)),
      }))
      .filter((item) => item.score > 0 || isLikelyLogicBearingArchivePath(item.relativePath))
      .sort((left, right) => right.score - left.score)
      .slice(0, MAX_ARCHIVE_PATH_CANDIDATES)
      .map((item) => ({
        ...item,
        score: getInterestingArchiveCandidateScore(item.candidate, item.relativePath),
      }))
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
        stage: '로직 분석 중',
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

      const fileContexts = await collectContextFromFile(candidate, relativeLabel);
      if (!fileContexts.length) {
        continue;
      }

      fileContexts.forEach((context) => {
        contexts.push(context);
        if (context.kind === 'text') {
          textCount += 1;
        }
        if (context.kind === 'binary') {
          binaryCount += 1;
        }
      });
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
      stage: '구조 분석 중',
      progressPercent: 24,
      message: buildDynamicProgressMessage(file.originalName),
    });

    if (extension) {
      const archiveContexts = await collectContextFromArchive(file, onProgress);
      contexts.push(...archiveContexts);
      continue;
    }

    const fileContexts = await collectContextFromFile(file.absolutePath, file.originalName);
    if (fileContexts.length) {
      contexts.push(...fileContexts);
    }
  }

  return normalizeAnalysisContexts(contexts);
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
        const archiveEntries = await listArchiveEntries(file.absolutePath, archiveExtension).catch(() => []);
        const footprint = await inspectArchiveFootprint(file.absolutePath, archiveExtension, {
          zipArchiveExtensions: Array.from(ZIP_ARCHIVE_EXTENSIONS),
          timeoutMs: 15000,
          maxBuffer: 2 * 1024 * 1024,
        }).catch(() => ({ entryCount: archiveEntries.length, totalUncompressedBytes: 0 }));
        const archiveSafetyIssues = getArchiveSafetyIssues({
          entries: archiveEntries,
          entryCount: footprint.entryCount || archiveEntries.length,
          totalUncompressedBytes: footprint.totalUncompressedBytes || 0,
          maxEntries: MAX_SAFE_ARCHIVE_ENTRY_COUNT,
          maxTotalBytes: MAX_SAFE_ARCHIVE_TOTAL_UNCOMPRESSED_BYTES,
        });

        if (archiveSafetyIssues.length) {
          manifest.push({
            originalName: file.originalName,
            storedPath: safeBaseName,
            extractedPath: '',
            archive: true,
            extractionSkipped: true,
            extractionReason: archiveSafetyIssues.join(', '),
          });
          continue;
        }

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

function buildCodexReconPrompt({ manifest }) {
  return [
    '다음 워크플로에 따라 프로젝트의 보안 취약점을 분석한다.',
    '현재 작업 디렉터리에는 업로드된 파일과 압축 해제 결과가 들어 있다.',
    '기본 가정은 이 서비스 어딘가에 exploit 가능한 취약점이 숨어 있을 수 있다는 것이다. recommendation으로 너무 빨리 물러서지 말고 먼저 입증 가능한 취약점을 찾는 방향으로 움직인다.',
    'PHASE 1 — 전체 프로젝트 구조 파악.',
    'JS/TS/PHP/Python 등 로직이 실제로 실행되는 파일을 모두 식별한다.',
    '프론트엔드 코드는 API 호출, auth flow, 상태 전이, client-server boundary, 입력 처리 로직을 추적한다.',
    '취약점 증명 단계로 넘어가기 전에 짧은 구조 요약을 먼저 만든다.',
    '키워드 분류기처럼 행동하지 말고, 먼저 실제 런타임 구조를 복원하라.',
    '분석 가능한 취약점 종류를 미리 좁히지 말고, 인증 우회, 로직 결함, 데이터 노출, 파일 처리, 코드 실행, 메모리 손상까지 모두 열어둔 상태로 본다.',
    '웹 라우트, API 핸들러, RPC 핸들러, 메뉴 엔트리, CLI 명령, worker, background job 등 외부 입력을 받는 엔트리포인트를 동등하게 본다.',
    '파일은 절대 3개 이상 전체 내용을 읽지 않는다. 나머지는 파일명과 첫 20줄만 본다. 빠르게 구조만 파악하고 끝낸다.',
    '특히 auth/session/config/database/upload/origin-redirect/token-storage/ownership-check-order 관련 파일은 우선순위를 높여 본다.',
    'logicFilesReviewed에는 실제로 읽고 역할을 파악한 파일만 적고, 엔트리포인트에서 도달 가능한 로직 파일을 가능한 한 전부 포함시킨다.',
    '누락된 파일이나 모듈이 있으면 import, call site, 인자명, 주변 제어 흐름을 근거로 역할을 추론하고 가정임을 메모한다.',
    'txt나 md도 구조상 실제 소스코드라면 분석 대상이 될 수 있다. 확장자만으로 판단하지 않는다.',
    'README, tutorial, test, fixture, sample payload, rule table, scanner signature, 설명 문장은 그것 자체가 실행 로직이 아닌 이상 취약점 근거로 쓰지 않는다.',
    '프로젝트 안에 보안 도구나 분석기나 취약점 예제가 있어도 그것을 대상 서비스와 혼동하지 않는다. 반드시 런타임 관련성을 입증한다.',
    '소스, 설정, 스크립트, 아카이브, 바이너리를 모두 본다. 바이너리는 필요하면 strings/readelf/objdump를 활용한다.',
    '출력은 간결하고 구조적으로 작성하며, 한국어 JSON만 반환한다.',
    JSON.stringify({
      schema: {
        structureSummary: 'string',
        runtimeMap: ['string'],
        logicFilesReviewed: ['string'],
        entrypoints: [
          {
            path: 'string',
            kind: 'string',
            why: 'string',
          },
        ],
        importsAndModules: [
          {
            module: 'string',
            role: 'string',
          },
        ],
        missingModules: [
          {
            module: 'string',
            inferredBehavior: 'string',
            evidence: 'string',
          },
        ],
        routeOrHandlerInventory: [
          {
            entrypoint: 'string',
            source: 'string',
            sink: 'string',
            validation: 'string',
            auth: 'string',
          },
        ],
        securityMechanisms: [
          {
            mechanism: 'string',
            location: 'string',
            bypassAssessment: 'string',
          },
        ],
        highRiskRecheckTargets: ['string'],
        coverageAssessment: 'string',
        attackSurfaces: ['string'],
        candidateVulnerabilitiesNeedingProof: ['string'],
        unresolvedAssumptions: ['string'],
      },
      constraints: [
        'structureSummary는 짧고 아키텍처 중심이어야 한다',
        'runtimeMap은 최대 6개까지만 작성한다',
        'logicFilesReviewed는 최대 5개까지만 작성한다',
        'entrypoints는 최대 8개까지만 작성한다',
        'importsAndModules는 최대 8개까지만 작성한다',
        'missingModules는 최대 12개까지만 작성한다',
        'routeOrHandlerInventory는 최대 8개까지만 작성한다',
        'securityMechanisms는 최대 6개까지만 작성한다',
        'highRiskRecheckTargets는 최대 6개까지만 작성한다',
        'coverageAssessment에는 vulnerability 또는 recommendation 결론을 내리기에 로직 파일 검토가 충분했는지 적는다',
        'attackSurfaces는 최대 6개까지만 작성한다',
        'candidateVulnerabilitiesNeedingProof는 최대 5개까지만 작성한다',
        'unresolvedAssumptions는 최대 10개까지만 작성한다',
        '장황한 서술 대신 짧고 사실적인 문장을 쓴다',
      ],
      uploadedFiles: manifest,
    }, null, 2),
  ].join('\n\n');
}

function hasDefinitiveNoVulnerabilitySummary(summary) {
  const text = String(summary || '').trim();
  return DEFINITIVE_NO_VULNERABILITY_SUMMARY_PATTERNS.some((pattern) => pattern.test(text));
}

function mentionsConcreteVulnerabilitySummary(summary) {
  const text = String(summary || '').trim();
  return CONCRETE_VULNERABILITY_SUMMARY_PATTERNS.some((pattern) => pattern.test(text));
}

function buildFocusedRecheckHints(findings = []) {
  return findings
    .slice(0, 8)
    .map((finding) => ({
      title: String(finding?.title || '').trim(),
      severity: String(finding?.severity || '').trim(),
      location: String(finding?.location || '').trim(),
      explanation: compactReportText(String(finding?.explanation || '').trim(), {
        maxLength: 180,
        maxSentences: 2,
      }),
    }))
    .filter((finding) => finding.title);
}

function hasWeakRecommendationPayload(parsedReport) {
  if (String(parsedReport?.resultMode || '').trim() !== 'recommendation') {
    return false;
  }

  const findings = Array.isArray(parsedReport?.findings) ? parsedReport.findings : [];
  if (findings.length < 2) {
    return true;
  }

  return hasDefinitiveNoVulnerabilitySummary(parsedReport?.summary || '');
}

function shouldRunFocusedRecheck({ parsedReport, suspectedFindings = [], investigationTargets = [] }) {
  if (!parsedReport || !Array.isArray(parsedReport.findings)) {
    return false;
  }

  return true;
}

function buildCodexFinalReportPrompt({
  manifest,
  reconnaissance,
  investigationTargets = [],
  forceProofMode = false,
  focusedRecheck = null,
}) {
  const recheckSection = focusedRecheck
    ? [
        'This is a FOCUSED RECHECK pass. The first pass already produced a report.',
        `First pass findings: ${JSON.stringify(buildFocusedRecheckHints(focusedRecheck.firstPassReport?.findings || []), null, 2)}`,
        focusedRecheck.suspectedFindings?.length
          ? `Suspected findings from rule-based analysis that need verification: ${JSON.stringify(focusedRecheck.suspectedFindings.map((finding) => ({ title: finding.title, location: finding.location })), null, 2)}`
          : '',
        'Your job is to verify these findings more deeply, fix wrong ones, and surface any new ones the first pass missed.',
      ].filter(Boolean)
    : [];

  const investigationSection = investigationTargets?.length
    ? ['High-risk targets identified for deeper investigation:', JSON.stringify(investigationTargets, null, 2)]
    : [];

  const proofModeSection = forceProofMode
    ? [
        'PROOF MODE: For each finding you include, you must cite the exact file path and a verbatim or near-verbatim code snippet. Do not include findings without direct code evidence.',
        'VERIFICATION PASS: You are reviewing the first-pass findings below.',
        'For each finding, re-examine the actual code and decide: is this a CONFIRMED vulnerability or just a possibility?',
        'CONFIRMED: you can cite exact file + code snippet proving the vulnerability exists.',
        'REMOVE: the evidence is indirect, speculative, or only shows potential — not an actual flaw.',
        'Only keep findings you can fully confirm. It is better to report 2 confirmed findings than 6 uncertain ones.',
        'Do not add new findings in this pass. Only verify, confirm, or remove existing ones.',
      ]
    : [];

  return [
    'You are generating the final security report for an educational vulnerability-analysis product.',
    'The current working directory contains the uploaded files and extracted archives.',
    'Use the reconnaissance notes below as a starting point, but verify them against the code and binaries before concluding.',
    'Analyze this like an experienced penetration tester, not just a conservative code reviewer. Your goal is to find and report as many real and suspected vulnerabilities as possible.',
    'Spend the early part of your effort rechecking repository identity, file roles, entrypoints, handlers, trust boundaries, and user-controlled input paths before writing any finding.',
    'For archive uploads, every file is still indexed. Read fileIndexPath plus retainedFileSample/excludedFileSample to understand the whole repository before choosing evidence.',
    'The extracted workspace may be pruned to runtime-relevant raw files for speed, but excluded files remain analyzed in the index metadata.',
    'A txt or md file may still be real source code if its structure proves it is part of the executable logic. Do not decide based on extension alone.',
    'Do not use README prose, tutorial text, tests, fixtures, examples, backup prompts, analyzer rules, scanner signatures, or explanatory comments as vulnerability evidence unless they are themselves the real executable path.',
    'If a suspicious string comes from a prompt file, rule table, backup file, or security-training text, classify it as reference material and continue tracing the real runtime instead of reporting it.',
    'Report confirmed vulnerabilities with direct code evidence. For each finding you must cite the exact file and a code snippet.',
    'Also include suspected vulnerabilities where the attack path is plausible but not 100% confirmed — mark these clearly in the detail field as "추가 검증 필요".',
    'Do not report pure hygiene issues or missing best practices unless they are part of a realistic attack chain.',
    'Aim for 3-5 findings total. Quality over quantity.',
    'Actively look for the following vulnerability classes in every codebase: authentication/authorization flaws, insecure direct object references (IDOR), missing rate limiting, sensitive data exposure, insecure session management, hardcoded secrets, path traversal, injection flaws (SQL/NoSQL/Command/LDAP), XSS, CSRF, open redirect, insecure deserialization, broken access control, security misconfiguration, and outdated dependencies.',
    'For each vulnerability class above, check if there is any runtime code path related to it before concluding it does not exist.',
    'If a pattern strongly suggests a vulnerability (e.g. user-controlled input near a dangerous sink), include it as a suspected finding even if the full source-to-sink chain is not 100% confirmed.',
    'Do not combine unrelated files into one exploit path. You must be able to explain the real or plausible source-to-sink or state-corruption path in the actual program.',
    'For command injection, look for any command sink (spawn, exec, system, popen, etc.) and trace whether attacker-controlled input could reach it, even indirectly.',
    'For SQL/NoSQL injection, look for any query construction and check whether user input affects query structure or semantics.',
    'For XSS, look for any rendering sink and check whether user-controlled content could reach it.',
    'For memory-corruption findings such as FSOP, Heap Corruption, Buffer Overflow, Format String, or Arbitrary Write, require native code or binary evidence.',
    'Treat the uploaded program as a service and describe it from the user or operator point of view.',
    'The application summary must say what the service does in practice, such as "이 서비스는 ..." and "사용자는 ...할 수 있다".',
    'Do not explain source code, internal logic, architecture, runtime reconstruction, files, or how you analyzed the program in applicationReport.',
    'For each finding, include a real file path summary and a codeLocation snippet. If source code exists, use source code. Only use C-style pseudocode when source truly does not exist.',
    'Each codeLocation should be a representative snippet from the cited runtime file. If exact verbatim is unavailable, provide the closest relevant code block.',
    'Write the final report in Korean.',
    'Respond with JSON only.',
    ...recheckSection,
    ...investigationSection,
    ...proofModeSection,
    'Reconnaissance notes:',
    reconnaissance || 'No reconnaissance notes were produced.',
    JSON.stringify({
      schema: {
        title: 'string',
        applicationType: 'string',
        applicationReport: 'string',
        repositoryUnderstanding: {
          programType: 'string',
          mainPurpose: 'string',
          runtimeCriticalFiles: ['string'],
          referenceOnlyFiles: ['string'],
        },
        resultMode: '"vulnerability" | "recommendation"',
        summary: 'string',
        findings: [
          {
            title: 'string',
            severity: '"high" | "medium" | "low"',
            confirmed: 'boolean (true if directly verified, false if suspected)',
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
        'applicationReport must describe what the service does in practice from the user perspective',
        'applicationReport must not mention analysis, source code, internal logic, runtime reconstruction, or file names',
        'repositoryUnderstanding must briefly summarize what kind of program this is and which files are runtime-critical versus reference-only',
        'findings must include BOTH confirmed and suspected vulnerabilities. Aim for at least 5 findings if the codebase has any complexity.',
        'for suspected findings, detail must clearly state "의심 단계" or "추가 검증 필요" so the reader understands the confidence level',
        'explanation/detail/remediation should be educational, detailed, and easy to understand',
        'do not omit low-severity findings such as missing security headers, verbose errors, or weak configurations',
      ],
      uploadedFiles: manifest,
    }, null, 2),
  ].join('\n\n');
}

function buildCodexFinalRescuePrompt({ manifest, reconnaissance }) {
  return [
    'You are generating a time-boxed final security report for an educational vulnerability-analysis product.',
    'The current working directory contains the uploaded files and extracted archives.',
    'Time is limited. Use the reconnaissance notes as the primary repository map.',
    'Focus on runtimeCriticalFiles and the strongest candidate vulnerability paths already surfaced in reconnaissance.',
    'Do not treat README text, tests, prompt backups, analyzer rules, or scanner signatures as runtime evidence.',
    'Report confirmed and suspected vulnerabilities. Mark suspected ones as "추가 검증 필요" in the detail field.',
    'For suspected findings, clearly state "의심 단계" or "추가 검증 필요" in the detail field.',
    'Aim for 3-5 findings. Do not report pure hygiene issues.',
    'Keep the output compact, factual, and JSON only.',
    'Write the final report in Korean.',
    'Reconnaissance notes:',
    reconnaissance || 'No reconnaissance notes were produced.',
    JSON.stringify({
      schema: {
        title: 'string',
        applicationType: 'string',
        applicationReport: 'string',
        repositoryUnderstanding: {
          programType: 'string',
          mainPurpose: 'string',
          runtimeCriticalFiles: ['string'],
          referenceOnlyFiles: ['string'],
        },
        resultMode: '"vulnerability" | "recommendation"',
        summary: 'string',
        findings: [
          {
            title: 'string',
            severity: '"high" | "medium" | "low"',
            confirmed: 'boolean (true if directly verified, false if suspected)',
            location: 'string',
            codeLocation: 'string',
            explanation: 'string',
            detail: 'string',
            remediation: 'string',
          },
        ],
      },
      constraints: [
        'Keep findings to at most 6 items',
        'Include both confirmed and suspected findings',
        'For suspected findings, detail must say "의심 단계" or "추가 검증 필요"',
        'applicationReport must be service-facing, not analysis-facing',
        'do not omit low-severity findings',
      ],
      uploadedFiles: manifest,
    }, null, 2),
  ].join('\n\n');
}

async function runCodexExecPass({
  workspaceRoot,
  outputFile,
  prompt,
  onProgress,
  passLabel = 'codex-pass',
  stage = '취약점 검증 중',
  progressPercent = 62,
  timeoutMs = 5 * 60 * 1000,
}) {
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

  await new Promise((resolve, reject) => {
    const progressLines = [];
    const child = spawn('codex', args, {
      cwd: workspaceRoot,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: process.env,
    });
    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      const recentProgress = progressLines.slice(-8).join(' | ');
      reject(new Error(`${passLabel}: timeout after ${timeoutMs}ms${recentProgress ? ` | recent=${recentProgress}` : ''}`));
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

      progressLines.push(latestLine);
      if (progressLines.length > 24) {
        progressLines.splice(0, progressLines.length - 24);
      }

      onProgress?.({
        stage,
        progressPercent,
        message: latestLine,
      });
    };

    child.stdout?.on('data', handleProgressChunk);
    child.stderr?.on('data', handleProgressChunk);

    child.stdin.write(prompt);
    child.stdin.end();

    child.on('error', (error) => {
      clearTimeout(timer);
      const recentProgress = progressLines.slice(-8).join(' | ');
      reject(new Error(`${passLabel}: spawn-error=${error.message}${recentProgress ? ` | recent=${recentProgress}` : ''}`));
    });

    child.on('close', (code) => {
      clearTimeout(timer);
      if (code === 0) {
        resolve();
        return;
      }
      const recentProgress = progressLines.slice(-8).join(' | ');
      reject(new Error(`${passLabel}: exit=${code}${recentProgress ? ` | recent=${recentProgress}` : ''}`));
    });
  });
}

async function analyzeWithCodexExec({ acceptedFiles, contexts = [], onProgress, suspectedFindings = [] }) {
  if (!String(process.env.CODEX_HOME || process.env.HOME || '').trim()) {
    return null;
  }

  if (acceptedFiles.some((file) => detectArchiveExtension(file.originalName))) {
    onProgress?.({
      stage: '구조 분석 중',
      progressPercent: 34,
      message: '압축 파일을 풀고 실행 가능한 로직 파일 구조를 복원하고 있습니다.',
    });
  }

  const { workspaceRoot, manifest } = await prepareCodexAnalysisWorkspace(acceptedFiles);
  const reconOutputFile = path.join(workspaceRoot, 'analysis-recon.txt');
  const finalOutputFile = path.join(workspaceRoot, 'analysis-report.json');
  const recheckOutputFile = path.join(workspaceRoot, 'analysis-report-recheck.json');
  const totalTimeoutMs = Number(process.env.ANALYSIS_CODEX_TIMEOUT_MS || 25 * 60 * 1000);
  const reconTimeoutMs = totalTimeoutMs - (5 * 60 * 1000);
  const finalTimeoutMs = 5 * 60 * 1000;
  const analysisStartedAt = Date.now();

  try {
    onProgress?.({
      stage: '로직 분석 중',
      progressPercent: 38,
      message: '엔트리포인트, import 체인, 실제 런타임 파일을 끝까지 추적하고 있습니다.',
    });

    await runCodexExecPass({
      workspaceRoot,
      outputFile: reconOutputFile,
      prompt: buildCodexReconPrompt({ manifest }),
      onProgress,
      passLabel: 'codex-recon',
      stage: '로직 분석 중',
      progressPercent: 48,
      timeoutMs: reconTimeoutMs,
    });

    const reconnaissance = fs.existsSync(reconOutputFile)
      ? fs.readFileSync(reconOutputFile, 'utf8')
      : '';
    const reconnaissanceReport = extractJsonObject(reconnaissance);
    const investigationTargets = collectHighRiskInvestigationTargets({
      contexts,
      reconnaissanceReport,
    });

    onProgress?.({
      stage: '취약점 검증 중',
      progressPercent: 64,
      message: '복원한 런타임 경로를 기준으로 source-sink 검증과 우회 가능성을 확인하고 있습니다.',
    });

    await runCodexExecPass({
      workspaceRoot,
      outputFile: finalOutputFile,
      prompt: buildCodexFinalReportPrompt({ manifest, reconnaissance, investigationTargets }),
      onProgress,
      passLabel: 'codex-final-report',
      stage: '취약점 검증 중',
      progressPercent: 74,
      timeoutMs: finalTimeoutMs,
    });

    const parsed = extractJsonObject(fs.readFileSync(finalOutputFile, 'utf8'));
    if (!parsed || !Array.isArray(parsed.findings)) {
      console.error('[analysis/codex] invalid-final-json', {
        finalOutputFile,
        exists: fs.existsSync(finalOutputFile),
        outputPreview: fs.existsSync(finalOutputFile)
          ? fs.readFileSync(finalOutputFile, 'utf8').slice(0, 1200)
          : '',
      });
      return null;
    }

    const remainingTimeoutMs = totalTimeoutMs - (Date.now() - analysisStartedAt);
    if (
      shouldRunFocusedRecheck({ parsedReport: parsed, suspectedFindings, investigationTargets })
      && remainingTimeoutMs >= MIN_ANALYSIS_RECHECK_TIMEOUT_MS
    ) {
      onProgress?.({
        stage: '정밀 재검증 중',
        progressPercent: 82,
        message: '1차 결과를 다시 열고 source-sink, 권한 검사, 우회 가능성을 끝까지 재검증하고 있습니다.',
      });

      await runCodexExecPass({
        workspaceRoot,
        outputFile: recheckOutputFile,
        prompt: buildCodexFinalReportPrompt({
          manifest,
          reconnaissance,
          investigationTargets,
          forceProofMode: true,
          focusedRecheck: {
            firstPassReport: parsed,
            suspectedFindings,
          },
        }),
        onProgress,
        passLabel: 'codex-final-recheck',
        stage: '정밀 재검증 중',
        progressPercent: 88,
        timeoutMs: remainingTimeoutMs,
      });

      const rechecked = extractJsonObject(fs.readFileSync(recheckOutputFile, 'utf8'));
      if (rechecked && Array.isArray(rechecked.findings)) {
        return rechecked;
      }

      console.error('[analysis/codex] invalid-recheck-json', {
        recheckOutputFile,
        exists: fs.existsSync(recheckOutputFile),
        outputPreview: fs.existsSync(recheckOutputFile)
          ? fs.readFileSync(recheckOutputFile, 'utf8').slice(0, 1200)
          : '',
      });
    }

    return parsed;
  } catch (error) {
    console.error('[analysis/codex] failed', {
      error: error instanceof Error ? error.message : String(error),
      workspaceRoot,
      reconOutputExists: fs.existsSync(reconOutputFile),
      finalOutputExists: fs.existsSync(finalOutputFile),
      reconPreview: fs.existsSync(reconOutputFile)
        ? fs.readFileSync(reconOutputFile, 'utf8').slice(0, 1200)
        : '',
      finalPreview: fs.existsSync(finalOutputFile)
        ? fs.readFileSync(finalOutputFile, 'utf8').slice(0, 1200)
        : '',
    });
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

function collectServiceBehaviorPoints(text) {
  const points = [];
  const pushPoint = (message) => {
    if (!points.includes(message)) {
      points.push(message);
    }
  };

  if (/\bmenu\b|\bchoice\b|\bselect\b|\bstdin\b/i.test(text)) {
    pushPoint('사용자는 메뉴나 입력창을 통해 항목을 조회하거나 생성, 수정, 삭제할 수 있다');
  }
  if (/\bexpress\b|\brouter\.(get|post|put|delete)\b|\bfastapi\b|\bflask\b|\b@RestController\b|\bhttp\b|\bapi\b/i.test(text)) {
    pushPoint('사용자나 외부 시스템은 요청을 보내고 그 결과를 응답으로 받을 수 있다');
  }
  if (/\blogin\b|\bsignup\b|\bsession\b|\btoken\b|\bauth\b|\bpassword\b/i.test(text)) {
    pushPoint('사용자는 로그인이나 인증 절차를 거쳐 권한이 필요한 기능을 이용할 수 있다');
  }
  if ((/\b(read|write|open|close|upload|download)\b/i.test(text) && /\bfile\b|\bpath\b|\bdir\b/i.test(text)) || /\bupload\b|\bdownload\b/i.test(text)) {
    pushPoint('사용자는 파일을 올리거나 내려받고 저장된 데이터를 다룰 수 있다');
  }
  if (/\bsend\b|\brecv\b|\bsocket\b|\bconnect\b|\blisten\b|\baccept\b|\bwebsocket\b/i.test(text)) {
    pushPoint('외부 시스템과 연결을 유지하면서 데이터를 주고받는 기능이 있다');
  }
  if (/\bselect\b|\binsert\b|\bupdate\b|\bdelete\b|\bquery\b|\bdatabase\b|\bdb\b|\bmongo\b|\bfindOne\b|\bfindMany\b/i.test(text)) {
    pushPoint('서비스는 저장된 데이터를 조회하거나 추가, 수정, 삭제하는 기능을 제공한다');
  }
  if (/\bandroidmanifest\b|\bactivity\b|\bfragment\b|\bintent\b/i.test(text)) {
    pushPoint('사용자는 여러 화면을 오가며 기능을 이용할 수 있다');
  }
  if (/\bchart\b|\bgraph\b|\bnetwork\b|\bd3\b|\bcytoscape\b/i.test(text)) {
    pushPoint('사용자는 데이터를 시각적으로 확인하거나 관계를 탐색할 수 있다');
  }
  if (/\bmalloc\b|\bfree\b|\bcalloc\b|\brealloc\b|\b_IO_FILE\b|\bstdout\b|\bstdin\b/i.test(text)) {
    pushPoint('사용자의 입력에 따라 데이터를 만들고 바꾸고 다시 확인하는 상호작용이 있다');
  }

  return points.slice(0, 2);
}

function buildApplicationNarrative(applicationType, sourceFiles, joinedText) {
  const signalText = [joinedText, sourceFiles.join('\n')].filter(Boolean).join('\n');
  const points = collectServiceBehaviorPoints(signalText);
  const narrative = points.length
    ? points.join('. ')
    : '사용자 입력을 받아 데이터를 처리하고 결과를 반환한다';

  return compactReportText(`이 서비스는 ${narrative}.`, { maxLength: 180, maxSentences: 2 });
}

function compactReportText(value, { maxLength = 220, maxSentences = 2 } = {}) {
  const normalized = String(value || '').replace(/\s+/g, ' ').trim();
  if (!normalized) {
    return '';
  }

  const sentences = normalized.split(/(?<=[.!?])\s+/).filter(Boolean);
  const sentenceLimited = sentences.length
    ? sentences.slice(0, maxSentences).join(' ')
    : normalized;

  if (sentenceLimited.length <= maxLength) {
    return sentenceLimited;
  }

  return `${sentenceLimited.slice(0, Math.max(0, maxLength - 1)).trimEnd()}…`;
}

function compactScenarioText(value, { maxLength = 560, maxSentences = 5 } = {}) {
  const text = String(value || '').trim();
  const hasNumberedSteps = /(?:^|\s)1[\.\)]\s*/.test(text) || /(?:^|\s)2[\.\)]\s*/.test(text);

  return compactReportText(text, {
    maxLength: hasNumberedSteps ? Math.max(maxLength, 720) : maxLength,
    maxSentences: hasNumberedSteps ? Math.max(maxSentences, 6) : maxSentences,
  });
}

function normalizeApplicationReport({ applicationType, applicationReport, sourceFiles, joinedText = '' }) {
  const normalizedReport = String(applicationReport || '').trim();
  if (normalizedReport) {
    if (/이\s*서비스는/.test(normalizedReport) && !/코드|로직|구조|분석|흐름/.test(normalizedReport)) {
      return compactReportText(normalizedReport, { maxLength: 220, maxSentences: 2 });
    }

    return buildApplicationNarrative(applicationType, sourceFiles, [joinedText, normalizedReport].filter(Boolean).join('\n'));
  }

  const hintText = [joinedText, applicationReport].filter(Boolean).join('\n');
  return buildApplicationNarrative(applicationType, sourceFiles, hintText);
}

function createFindingFromRule(rule, context) {
  const codeLocation = extractCodeExcerpt(context.fullText || context.text, rule.patterns, context.kind);

  return {
    id: `${rule.id}-${Buffer.from(`${rule.name}-${context.sourceFile}`).toString('base64').slice(0, 12)}`,
    title: rule.name,
    exploitability: '실제 exploit 가능',
    severity: normalizeSeverity(rule.severity),
    location: formatFindingLocation(context.sourceFile, codeLocation),
    codeLocation,
    explanation: rule.explanation || rule.detail,
    detail: rule.detail,
    remediation: rule.remediation,
    abuse: '',
  };
}

function buildStructuredFinding(finding) {
  const locationText = Array.isArray(finding.locations)
    ? finding.locations.slice(0, 5).join(', ')
    : finding.location;
  const abuseText = [finding.detail, finding.abuse].filter(Boolean).join(' ');
  const formattedLocation = formatFindingLocation(locationText || finding.location, finding.codeLocation);
  const rawExploitability = String(finding?.exploitability || '').trim();
  const exploitability = rawExploitability ? normalizeExploitability(rawExploitability) : '';

  return {
    ...finding,
    exploitability,
    location: formattedLocation,
    codeLocation: finding.codeLocation || formattedLocation || finding.location,
    poc: String(finding?.poc || '').trim(),
    description: [
      `[${finding.title || '취약점'}]`,
      `- 위치: ${formattedLocation || '위치 정보가 없습니다.'}`,
      `- 원인: ${finding.explanation || '원인 정보가 없습니다.'}`,
      `- 공격 시나리오: ${abuseText || '공격 시나리오 정보가 없습니다.'}`,
      ...(exploitability ? [`- 성립 여부: ${exploitability}`] : []),
      `- 심각도: ${finding.severity || 'low'}`,
      `- 수정 방안: ${finding.remediation || '수정 방안 정보가 없습니다.'}`,
      ...(String(finding?.poc || '').trim() ? [`- PoC: ${String(finding.poc).trim()}`] : []),
    ].join('\n'),
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
  const runtimeContexts = getRuntimeEvidenceContexts(contexts);
  const { textContexts, binaryContexts } = splitContextsByKind(runtimeContexts.length ? runtimeContexts : contexts);
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

function inferSourceLabel(text) {
  const combinedText = String(text || '');

  if (/\brequest\.(args|form|values)\.get\s*\(/i.test(combinedText)) {
    return 'HTTP 요청 파라미터(request.args/form/values)';
  }
  if (/\b(req|request)\.(body|json)\b/i.test(combinedText)) {
    return 'HTTP 요청 바디(req.body/request.json)';
  }
  if (/\b(req|request)\.(query|params)\b/i.test(combinedText)) {
    return 'HTTP query/path 파라미터(req.query/params)';
  }
  if (/\bcookies?\b|\bsession\b/i.test(combinedText)) {
    return '쿠키 또는 세션 값';
  }
  if (/\bupload\b|\bmultipart\b|\bfilename\b|\brequest\.files\b/i.test(combinedText)) {
    return '업로드된 파일 또는 파일명';
  }
  if (/\bargv\b|\bargc\b|\bgetenv\b/i.test(combinedText)) {
    return '프로세스 인자 또는 환경 변수';
  }
  if (/\bscanf\b|\bfgets\b|\bread\s*\(\s*0\s*,|\bstdin\b|\bmenu\b|\bchoice\b/i.test(combinedText)) {
    return '표준 입력 또는 메뉴 입력';
  }

  return '외부에서 제어 가능한 입력';
}

function inferSinkLabel(ruleId, text) {
  const combinedText = String(text || '');

  switch (ruleId) {
    case 'command-injection':
      if (/\bos\.system\b/i.test(combinedText)) return 'os.system 명령 실행';
      if (/\bpopen\b/i.test(combinedText)) return 'popen 명령 실행';
      if (/\bexecve?\b/i.test(combinedText)) return 'exec 계열 명령 실행';
      if (/\bsystem\b/i.test(combinedText)) return 'system 명령 실행';
      return '운영체제 명령 실행 함수';
    case 'sql-injection':
      if (/\bread_sql_query\b/i.test(combinedText)) return 'read_sql_query 쿼리 실행';
      if (/\bcursor\.execute\b/i.test(combinedText)) return 'cursor.execute 쿼리 실행';
      if (/\bsequelize\.query\b/i.test(combinedText)) return 'sequelize.query 쿼리 실행';
      if (/\bexecute\s*\(/i.test(combinedText)) return 'execute 계열 쿼리 실행';
      return '동적 SQL 쿼리 실행 지점';
    case 'nosql-injection':
      if (/\bfindOne\b/i.test(combinedText)) return 'findOne 조회';
      if (/\bfind\b/i.test(combinedText)) return 'find 조회';
      if (/\bupdateOne\b/i.test(combinedText)) return 'updateOne 갱신';
      if (/\baggregate\b/i.test(combinedText)) return 'aggregate 파이프라인 실행';
      return 'NoSQL 쿼리 실행 지점';
    case 'xss':
      if (/\brender_template_string\b/i.test(combinedText)) return 'render_template_string 템플릿 렌더링';
      if (/\bdangerouslySetInnerHTML\b/i.test(combinedText)) return 'dangerouslySetInnerHTML 렌더링';
      if (/\binnerHTML\s*=/i.test(combinedText)) return 'innerHTML DOM 렌더링';
      if (/\bMarkup\s*\(/i.test(combinedText) || /\|\s*safe\b/i.test(combinedText)) return 'HTML 안전 처리 우회 렌더링';
      return 'HTML 또는 스크립트 렌더링 지점';
    case 'path-traversal':
      if (/\bsend_file\b/i.test(combinedText)) return 'send_file 파일 응답';
      if (/\bFileResponse\b/i.test(combinedText)) return 'FileResponse 파일 응답';
      if (/\bopen\s*\(/i.test(combinedText)) return 'open 파일 열기';
      if (/\bfs\.(readFile|createReadStream)\b/i.test(combinedText)) return '파일 시스템 읽기';
      return '파일 경로를 사용하는 파일 접근 지점';
    case 'format-string':
      return 'printf/fprintf/snprintf 포맷 문자열 sink';
    case 'stack-overflow':
      return '고정 길이 버퍼 복사 또는 입력 sink';
    case 'arbitrary-write':
      return '공격자가 제어한 주소로의 write sink';
    case 'heap-corruption':
      return '힙 객체 재사용/해제/갱신 로직';
    case 'fsop':
      return 'FILE 구조체 또는 스트림 동작 지점';
    case 'hardcoded-secret':
      return '하드코딩된 비밀값이 사용되는 인증 또는 외부 연동 지점';
    default:
      return '민감한 동작이 수행되는 sink';
  }
}

function inferValidationAssessment(text) {
  const combinedText = String(text || '');

  if (/\b(sql_filter|sanitize|sanitiz|escape|escaped|validator|validate|allowlist|whitelist|blacklist|regex|session|csrf|auth|permission|role|hash)\b/i.test(combinedText)) {
    return '일부 필터나 검증 흔적은 보이지만, 그 검사가 실제로 구조를 안전하게 고정하는지는 추가 검증이 필요하다';
  }

  return '명시적인 입력 검증, allowlist, 권한 검사, 구조 고정 로직이 뚜렷하게 보이지 않는다';
}

function buildExpandedExplanation(rule, contexts) {
  const combinedText = contexts.map((context) => context.fullText || context.text).join('\n\n');
  const sourceLabel = inferSourceLabel(combinedText);
  const sinkLabel = inferSinkLabel(rule.id, combinedText);
  const validationText = inferValidationAssessment(combinedText);

  return compactReportText(
    `${rule.explanation} Source는 ${sourceLabel}, Sink는 ${sinkLabel}이며 검증 상태는 ${validationText}.`,
    { maxLength: 240, maxSentences: 2 },
  );
}

function buildExpandedAbuse(rule, contexts) {
  const combinedText = contexts.map((context) => context.fullText || context.text).join('\n\n');
  const sourceLabel = inferSourceLabel(combinedText);
  const sinkLabel = inferSinkLabel(rule.id, combinedText);
  const validationText = inferValidationAssessment(combinedText);
  return compactScenarioText(
    `1) 공격자가 ${sourceLabel}에 조작된 값을 넣는다. 2) 입력값이 ${sinkLabel}까지 도달한다. 3) ${rule.detail}`,
    { maxLength: 720, maxSentences: 6 },
  );
}

function buildExpandedRemediation(rule) {
  return compactReportText(rule.remediation, { maxLength: 220, maxSentences: 2 });
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

function extractRequestControlledVariableNames(text) {
  const names = new Set();
  const patterns = [
    /\b(?:const|let|var)\s+([a-zA-Z_]\w*)\s*=\s*request\.(args|form|values)\.get\s*\(/g,
    /\b(?:const|let|var)\s+([a-zA-Z_]\w*)\s*=\s*req\.(body|query|params)\.[a-zA-Z_]\w+/g,
    /\b(?:const|let|var)\s+([a-zA-Z_]\w*)\s*=\s*req\.(body|query|params)\[['"][^'"]+['"]\]/g,
  ];

  patterns.forEach((pattern) => {
    for (const match of String(text || '').matchAll(pattern)) {
      if (match[1]) {
        names.add(match[1]);
      }
    }
  });

  return Array.from(names);
}

function extractJsonBodyAliasNames(text) {
  const aliases = new Set();
  const patterns = [
    /\b(?:const|let|var)\s+([a-zA-Z_]\w*)\s*=\s*await\s+request\.json\s*\(/g,
    /\b(?:const|let|var)\s+([a-zA-Z_]\w*)\s*=\s*await\s+request\.json\b/g,
  ];

  patterns.forEach((pattern) => {
    for (const match of String(text || '').matchAll(pattern)) {
      if (match[1]) {
        aliases.add(match[1]);
      }
    }
  });

  return Array.from(aliases);
}

function hasDirectRequestControlledPathSink(text) {
  const combinedText = String(text || '');
  const sinkPattern = /\b(path\.(join|resolve)|open|send_file|FileResponse|fs\.(readFile|writeFile|createReadStream|createWriteStream))\s*\(/i;

  if (!sinkPattern.test(combinedText)) {
    return false;
  }

  if (
    /\b(path\.(join|resolve)|open|send_file|FileResponse|fs\.(readFile|writeFile|createReadStream|createWriteStream))\s*\([^)]*(req|request)\.(body|query|params|args|form|values)\b/i.test(combinedText)
  ) {
    return true;
  }

  const requestVariables = extractRequestControlledVariableNames(combinedText);
  if (requestVariables.some((name) => new RegExp(`\\b(path\\.(join|resolve)|open|send_file|FileResponse|fs\\.(readFile|writeFile|createReadStream|createWriteStream))\\s*\\([^)]*\\b${name}\\b`, 'i').test(combinedText))) {
    return true;
  }

  const jsonBodyAliases = extractJsonBodyAliasNames(combinedText);
  return jsonBodyAliases.some((alias) => new RegExp(`\\b(path\\.(join|resolve)|open|send_file|FileResponse|fs\\.(readFile|writeFile|createReadStream|createWriteStream))\\s*\\([^)]*\\b${alias}\\.`, 'i').test(combinedText));
}

function hasPathConfinementGuard(text) {
  const combinedText = String(text || '');

  return (
    /\bpath\.(resolve|normalize)\s*\(/i.test(combinedText)
    && (
      /if\s*\(\s*!\s*[a-zA-Z_]\w*\.startsWith\s*\(\s*[a-zA-Z_]\w*\s*\)\s*\)\s*{\s*return/i.test(combinedText)
      || /if\s*\(\s*path\.relative\s*\(\s*[a-zA-Z_]\w+\s*,\s*[a-zA-Z_]\w+\s*\)\.startsWith\s*\(\s*['"]\.\./i.test(combinedText)
      || /if\s*\(\s*!?\s*[a-zA-Z_]\w*\.includes\s*\(\s*['"]\.\.\//i.test(combinedText)
    )
  );
}

function hasPathTraversalFlow(text) {
  const combinedText = String(text || '');
  const hasPathRoute = /@app\.route\s*\(\s*["'][^"']*<path:([a-zA-Z_]\w*)>[^"']*["']\s*\)/i.test(combinedText);
  const hasRequestControlledPath = hasDirectRequestControlledPathSink(combinedText);
  const hasFileSink = (
    /\bopen\s*\(\s*[a-zA-Z_]\w+\s*\)/i.test(combinedText)
    || /\bsend_file\s*\(\s*[a-zA-Z_]\w+\s*\)/i.test(combinedText)
    || /\bFileResponse\s*\(\s*[a-zA-Z_]\w+\s*\)/i.test(combinedText)
    || /\bfs\.(readFile|writeFile|createReadStream|createWriteStream)\s*\(\s*[a-zA-Z_]\w+/i.test(combinedText)
    || /\bpath\.(join|resolve)\s*\([^)]*[a-zA-Z_]\w+/i.test(combinedText)
  );
  const hasTraversalTokenNearSink = (
    /\.\.[\\/]/.test(combinedText)
    || /\bpath\.(join|resolve)\s*\([^)]*(req|request|params|query|body|args|form|values)/i.test(combinedText)
    || /\b(open|send_file|FileResponse|fs\.(readFile|writeFile|createReadStream|createWriteStream))\s*\([^)]*(req|request|params|query|body|args|form|values)/i.test(combinedText)
  );

  return hasFileSink && ((hasPathRoute || hasRequestControlledPath) && hasTraversalTokenNearSink);
}

function hasExplicitProxyTrustGate(text) {
  return /\b(TRUST_PROXY_HEADERS|shouldTrustProxyHeaders|trustedHeaderOrigin|trust proxy|set\s*\(\s*['"]trust proxy['"])/i.test(String(text || ''));
}

function hasHostHeaderRedirectFlow(text) {
  const combinedText = String(text || '');
  const hasHeaderSource = (
    /\bx-forwarded-host\b/i.test(combinedText)
    || /\bx-forwarded-proto\b/i.test(combinedText)
    || /\bheaders\.get\s*\(\s*['"]host['"]\s*\)/i.test(combinedText)
    || /\bgetRequestHeader\s*\([^)]*['"]host['"]\s*\)/i.test(combinedText)
  );
  const hasAbsoluteUrlConstruction = (
    /https?:\/\/\$\{[^}]*host/i.test(combinedText)
    || /\bnew URL\s*\([^)]*(host|origin|redirect)/i.test(combinedText)
    || /\bnormalizeOrigin\s*\(\s*`?\$\{protocol/i.test(combinedText)
  );
  const hasRedirectSink = (
    /\bredirect[_-]?uri\b/i.test(combinedText)
    || /\bNextResponse\.redirect\b/i.test(combinedText)
    || /\bredirect\s*\(/i.test(combinedText)
    || /\blocation\s*:/i.test(combinedText)
    || /\bshareUrl\b/i.test(combinedText)
  );

  return hasHeaderSource && (hasAbsoluteUrlConstruction || hasRedirectSink);
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
        /\bexecve?\s*\(|\bsystem\s*\(|\bpopen\s*\(|\bCreateProcess(?:A|W)?\s*\(|\bos\.system\s*\(|\bchild_process\.(exec|execFile|spawn)\s*\(/i.test(combinedText)
        && /\b(argv|argc|getenv|request|req|input|param|query|body|command|cmd|user_input|userInput)\b/i.test(combinedText)
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
          || /\b([a-zA-Z_]\w*\.)?(query|execute)\s*\(\s*["'`][\s\S]{0,200}(SELECT|INSERT|UPDATE|DELETE)[\s\S]{0,200}["'`]\s*\+/i.test(combinedText)
          || /\b([a-zA-Z_]\w*\.)?(query|execute)\s*\(\s*[^)]*\+\s*req\.(body|query|params)/i.test(combinedText)
          || /\bsequelize\.query\s*\(\s*[^)]*\$\{/i.test(combinedText)
        )
        && (
          /\bread_sql_query\s*\(/i.test(combinedText)
          || /\bcursor\.execute\s*\(/i.test(combinedText)
          || /\bsequelize\.query\s*\(/i.test(combinedText)
          || /\b[a-zA-Z_]\w*\.(query|execute)\s*\(/i.test(combinedText)
          || /\b(mysql|postgres|sqlite|sqlite3|pandas|pd\.read_sql_query|jdbc|statement|preparedstatement)\b/i.test(combinedText)
        )
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
        && !hasPathConfinementGuard(combinedText)
        && (
          hasPathTraversalFlow(combinedText)
          || (
            matchCount >= 1
            && countMatchedPatterns(
              combinedText,
              [/\.\.[\\/]/, /\bpath\.(join|resolve)\b/i, /\bfs\.(readFile|writeFile|createReadStream|createWriteStream)\b/i, /\bopen\s*\(/i, /\bsend_file\s*\(/i, /\bFileResponse\s*\(/i],
            ) >= 2
            && hasDirectRequestControlledPathSink(combinedText)
          )
        )
      );
    case 'insecure-default-secret':
      return (
        matchCount >= 1
        && /\b(secret|token|key|password)\b/i.test(combinedText)
        && /\b(process\.env|os\.getenv|getenv)\b/i.test(combinedText)
        && /(\|\||\?\?:?)/.test(combinedText)
      );
    case 'host-header-poisoning':
      return hasHostHeaderRedirectFlow(combinedText) && !hasExplicitProxyTrustGate(combinedText);
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
  const runtimeContexts = getRuntimeEvidenceContexts(contexts)
    .filter((context) => (
      context.kind === 'text'
      && context.evidenceRole === 'runtime-source'
      && !isLikelySecurityToolingContext(context)
      && !isLikelyIllustrativeTextContext(context)
    ));
  const combinedText = runtimeContexts.map((context) => context.fullText || context.text).join('\n\n');
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
    const matchedContexts = runtimeContexts.filter((context) => (
      /\bread_sql_query\s*\(\s*f["']/i.test(context.text)
      || /\bexecute\s*\(\s*f["']/i.test(context.text)
      || /\bSELECT\b[\s\S]{0,240}\{[\s\S]{0,120}\}/i.test(context.text)
    ));
    const matchedGroup = groupContextsBySourceFile(matchedContexts).find((group) => verifyRuleEvidence(sqlRule, group));
    if (matchedGroup) {
      findings.push(createFindingFromVerifiedRule(sqlRule, matchedGroup));
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
    const matchedContexts = runtimeContexts.filter((context) => (
      /render_template_string\s*\(/i.test(context.text)
      || /\|\s*safe\b/i.test(context.text)
      || /\bMarkup\s*\(/i.test(context.text)
      || /return\s+f?["'][\s\S]{0,200}<script[\s\S]{0,200}["']/i.test(context.text)
      || hasDirectResponseReflection(context.text)
    ));
    const matchedGroup = groupContextsBySourceFile(matchedContexts).find((group) => verifyRuleEvidence(xssRule, group));
    if (matchedGroup) {
      findings.push(createFindingFromVerifiedRule(xssRule, matchedGroup));
    }
  }

  const pathTraversalRule = VULNERABILITY_RULES.find((rule) => rule.id === 'path-traversal');
  if (pathTraversalRule && hasPathTraversalFlow(combinedText)) {
    const matchedContexts = runtimeContexts.filter((context) => hasPathTraversalFlow(context.text));
    const matchedGroup = groupContextsBySourceFile(matchedContexts).find((group) => verifyRuleEvidence(pathTraversalRule, group));
    if (matchedGroup) {
      findings.push(createFindingFromVerifiedRule(pathTraversalRule, matchedGroup));
    }
  }

  return findings
    .filter(Boolean)
    .sort((left, right) => compareSeverity(left.severity, right.severity));
}

function collectVulnerabilityFindings(contexts) {
  const verifiedFindings = VULNERABILITY_RULES
    .map((rule) => {
      const matchedGroups = groupContextsBySourceFile(getRuleCandidateContexts(contexts, rule));
      const matchedGroup = matchedGroups.find((group) => verifyRuleEvidence(rule, group));
      if (!matchedGroup) {
        return null;
      }

      return createFindingFromVerifiedRule(rule, matchedGroup);
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

function selectNormalizedSummary({ parsedSummary, resultMode, findings }) {
  const fallbackSummary = summarizeFindings(findings, resultMode);
  const summary = String(parsedSummary || '').trim();
  if (!summary) {
    return fallbackSummary;
  }

  if (hasDefinitiveNoVulnerabilitySummary(summary)) {
    if (resultMode === 'recommendation') {
      return fallbackSummary;
    }

    if (resultMode === 'vulnerability') {
      return fallbackSummary;
    }
  }

  if (resultMode === 'recommendation' && mentionsConcreteVulnerabilitySummary(summary)) {
    return fallbackSummary;
  }

  return summary;
}

function summarizeFindings(findings, resultMode) {
  if (!findings.length) {
    return resultMode === 'recommendation'
      ? '자동 분석에서 확정 취약점을 끝까지 입증하지 못해 추가 검토가 필요합니다.'
      : '발견된 취약점이 없습니다.';
  }

  const names = findings.slice(0, 3).map((finding) => finding.title).join(', ');
  return `${resultMode === 'recommendation' ? '주요 보완 포인트' : '발견된 취약점'} : ${names}${findings.length > 3 ? ` 외 ${findings.length - 3}개` : ''}`;
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
    title: compactReportText(String(finding?.title || `Finding ${index + 1}`).trim(), { maxLength: 80, maxSentences: 1 }),
    confirmed: typeof finding?.confirmed === 'boolean' ? finding.confirmed : true,
    exploitability: finding?.exploitability ? normalizeExploitability(finding.exploitability) : '',
    severity: normalizeSeverity(String(finding?.severity || 'low').toLowerCase()),
    location: String(finding?.location || '관련 코드 구간').trim(),
    codeLocation: String(finding?.codeLocation || finding?.location || '관련 코드 구간').trim(),
    explanation: compactReportText(String(finding?.explanation || '설명이 없습니다.').trim(), { maxLength: 260, maxSentences: 2 }),
    detail: compactScenarioText(String(finding?.detail || '세부 설명이 없습니다.').trim(), { maxLength: 720, maxSentences: 6 }),
    remediation: compactReportText(String(finding?.remediation || '대응 방안이 제공되지 않았습니다.').trim(), { maxLength: 220, maxSentences: 2 }),
    poc: compactScenarioText(String(finding?.poc || '').trim(), { maxLength: 420, maxSentences: 5 }),
    abuse: '',
  });
}

function normalizeCodexRecommendationFinding(finding, index) {
  return buildStructuredFinding({
    id: `codex-recommendation-${index + 1}`,
    title: compactReportText(String(finding?.title || `보완 포인트 ${index + 1}`).trim(), { maxLength: 80, maxSentences: 1 }),
    confirmed: typeof finding?.confirmed === 'boolean' ? finding.confirmed : false,
    exploitability: '',
    severity: normalizeSeverity(String(finding?.severity || 'low').toLowerCase()),
    location: String(finding?.location || '관련 로직 구간').trim(),
    codeLocation: String(finding?.codeLocation || finding?.location || '관련 로직 구간').trim(),
    explanation: compactReportText(String(finding?.explanation || '보완 이유가 제공되지 않았습니다.').trim(), { maxLength: 260, maxSentences: 2 }),
    detail: compactScenarioText(String(finding?.detail || '실패 가능성 설명이 제공되지 않았습니다.').trim(), { maxLength: 520, maxSentences: 5 }),
    remediation: compactReportText(String(finding?.remediation || '구체적인 보완 방안이 제공되지 않았습니다.').trim(), { maxLength: 220, maxSentences: 2 }),
    poc: '',
    abuse: '',
  });
}

export function normalizeCodexReport(parsedReport, sourceFiles, contexts = []) {
  if (!parsedReport || !Array.isArray(parsedReport.findings)) {
    return null;
  }

  const requestedMode = String(parsedReport.resultMode || '').trim() === 'recommendation'
    ? 'recommendation'
    : 'vulnerability';
  const findings = requestedMode === 'recommendation'
    ? parsedReport.findings
      .map(normalizeCodexRecommendationFinding)
      .filter((finding) => hasCodexContextAnchor(finding, contexts))
    : parsedReport.findings
      .map((finding, index) => {
        const evidenceConfirmed = hasValidatedCodexEvidence(finding, contexts);
        const requestedConfirmed = typeof finding?.confirmed === 'boolean' ? finding.confirmed : true;
        return normalizeCodexFinding({
          ...finding,
          confirmed: requestedConfirmed && evidenceConfirmed,
        }, index);
      });
  const resultMode = requestedMode === 'vulnerability' && findings.length ? 'vulnerability' : 'recommendation';
  const finalFindings = findings;
  const applicationType = String(parsedReport.applicationType || '기능을 제공하는').trim();
  const normalizedTitle = String(parsedReport.title || `${applicationType} 서비스`).trim();
  const summary = compactReportText(
    selectNormalizedSummary({
      parsedSummary: parsedReport.summary,
      resultMode,
      findings: finalFindings,
    }),
    { maxLength: 140, maxSentences: 1 },
  );

  return {
    title: normalizedTitle.endsWith('서비스') ? normalizedTitle : `${normalizedTitle} 서비스`,
    applicationType,
    summary,
    applicationReport: normalizeApplicationReport({
      applicationType,
      applicationReport: String(parsedReport.applicationReport || '').trim(),
      sourceFiles: sourceFiles.map((file) => file.relativePath || file.originalName),
      joinedText: contexts.map((context) => context.fullText || context.text || '').join('\n\n'),
    }),
    resultMode,
    overallSeverity: calculateOverallSeverity(finalFindings),
    findingsCount: finalFindings.length,
    findings: finalFindings,
    sourceFiles,
  };
}

export function buildRuleBasedAnalysisReport({ contexts, sourceFiles }) {
  const classifiedContexts = normalizeAnalysisContexts(contexts);
  const runtimeContexts = getRuntimeEvidenceContexts(classifiedContexts);
  const analysisContexts = runtimeContexts.length ? runtimeContexts : classifiedContexts;
  const sourceFileNames = sourceFiles.map((file) => file.originalName);
  const primaryContextNames = analysisContexts.map((context) => context.sourceFile);
  const joinedText = analysisContexts.map((context) => context.fullText || context.text).join('\n\n');
  const applicationType = inferApplicationType(joinedText, sourceFileNames);
  const findings = collectVulnerabilityFindings(analysisContexts);
  const resultMode = findings.length ? 'vulnerability' : 'recommendation';
  const finalFindings = findings;

  return {
    title: buildReportTitle(applicationType, finalFindings, resultMode),
    applicationType,
    summary: summarizeFindings(finalFindings, resultMode),
    applicationReport: buildApplicationNarrative(
      applicationType,
      primaryContextNames.length ? primaryContextNames : sourceFileNames,
      joinedText,
    ),
    resultMode,
    overallSeverity: calculateOverallSeverity(finalFindings),
    findingsCount: finalFindings.length,
    findings: finalFindings,
    sourceFiles,
  };
}

export function selectPreferredAnalysisReport({ normalizedCodexReport, ruleBasedReport }) {
  if (normalizedCodexReport?.resultMode === 'vulnerability' && normalizedCodexReport.findings?.length) {
    return normalizedCodexReport;
  }

  if (ruleBasedReport?.resultMode === 'vulnerability' && ruleBasedReport.findings?.length) {
    return ruleBasedReport;
  }

  if (normalizedCodexReport) {
    return normalizedCodexReport;
  }

  if (ruleBasedReport?.resultMode === 'recommendation') {
    return ruleBasedReport;
  }

  return null;
}

function buildFallbackReport(acceptedFiles, reason = '', contexts = []) {
  const sourceFiles = acceptedFiles.map((file) => ({
    originalName: file.originalName,
    relativePath: file.relativePath || '',
    size: file.size || 0,
  }));
  const sourceFileNames = sourceFiles.map((file) => file.originalName);
  const joinedText = contexts.map((context) => context.fullText || context.text || '').join('\n\n');
  const applicationType = inferApplicationType(joinedText, sourceFileNames);
  const findings = [];
  const summary = compactReportText(
    `자동 분석이 전체 결과를 끝까지 확정하지 못했습니다. ${reason || '분석 프로세스를 다시 이어가야 합니다.'}`,
    { maxLength: 140, maxSentences: 2 },
  );

  return {
    title: `${applicationType} 서비스`,
    applicationType,
    summary,
    applicationReport: normalizeApplicationReport({
      applicationType,
      applicationReport: '',
      sourceFiles: sourceFiles.map((file) => file.relativePath || file.originalName),
      joinedText,
    }),
    resultMode: 'recommendation',
    overallSeverity: 'low',
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
  const contexts = await buildFileContexts(acceptedFiles, onProgress);
  const ruleBasedReport = buildRuleBasedAnalysisReport({ contexts, sourceFiles });
  const codexReport = await analyzeWithCodexExec({
    acceptedFiles,
    contexts,
    onProgress,
    suspectedFindings: ruleBasedReport.findings,
  });
  const normalizedCodexReport = normalizeCodexReport(codexReport, sourceFiles, contexts);
  const selectedReport = selectPreferredAnalysisReport({
    normalizedCodexReport,
    ruleBasedReport,
  });
  if (selectedReport) {
    return selectedReport;
  }

  console.error('[analysis/report] deep-analysis-unavailable', {
    sourceFiles: sourceFiles.map((file) => file.originalName),
    contextsCount: contexts.length,
  });

  onProgress?.({
    stage: '취약점 검증 중',
    progressPercent: 72,
    message: '심층 분석 결과를 끝까지 확정하지 못해 최소 리포트로 마무리합니다.',
  });

  return buildFallbackReport(
    acceptedFiles,
    '심층 분석 단계가 중단되어 최종 리포트를 끝까지 확정하지 못했습니다.',
    contexts,
  );
}

export async function generateAnalysisReport({ acceptedFiles, onProgress }) {
  try {
    return await Promise.race([
      generateAnalysisReportInternal({ acceptedFiles, onProgress }),
      new Promise((_, reject) => {
        setTimeout(() => reject(new Error('analysis-timeout')), ANALYSIS_TIMEOUT_MS);
      }),
    ]);
  } catch (error) {
    return buildFallbackReport(
      acceptedFiles,
      error instanceof Error && error.message === 'analysis-timeout'
        ? '심층 분석 프로세스가 장시간 응답하지 않아 전체 로직 검토를 끝내지 못했습니다.'
        : '분석 도중 일부 로직 경로를 끝까지 해석하지 못했습니다.'
    );
  }
}
