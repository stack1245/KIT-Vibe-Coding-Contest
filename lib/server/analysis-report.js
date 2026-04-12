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
const MAX_WALK_FILES = 5200;
const MAX_BINARY_STRINGS = 280;
const MAX_BINARY_SYMBOLS = 220;
const MAX_DISASSEMBLY_LINES = 240;
const MAX_ARCHIVE_CONTEXT_FILES = 320;
const MAX_ARCHIVE_LISTING_ENTRIES = 240;
const MAX_ARCHIVE_PATH_CANDIDATES = 1200;
const MAX_ARCHIVE_SCORE_PREVIEW_BYTES = 8192;
const MAX_INVESTIGATION_TARGETS = 16;
const MIN_ANALYSIS_RECHECK_TIMEOUT_MS = 4 * 60 * 1000;
const MAX_WORKSPACE_REVIEW_FILES = 72;
const FILE_REVIEW_BATCH_SIZE = 12;

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
    minScore: 2,
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

const SERVICE_TYPE_RULES = [
  {
    type: '코드 업로드와 GitHub 저장소 취약점 분석 웹 서비스',
    patterns: [/\bgithub\b/i, /\bupload\b/i, /\b(vulnerability|security|analysis|report)\b/i],
    minScore: 2,
  },
  {
    type: '영상 변환 웹 서비스',
    patterns: [/\b(video|ffmpeg|transcode|transcoding|subtitle|thumbnail|hls|m3u8|mp4|mov|avi)\b/i],
    minScore: 2,
  },
  {
    type: '모바일 쇼핑앱',
    patterns: [/\b(android|ios|react-native|flutter)\b/i, /\b(cart|product|order|payment|checkout|shop|shopping)\b/i],
    minScore: 2,
  },
  {
    type: '쇼핑 웹 서비스',
    patterns: [/\b(cart|product|order|payment|checkout|shop|shopping)\b/i],
    minScore: 1,
  },
  {
    type: '파일 업로드 웹 서비스',
    patterns: [/\bupload\b/i, /\b(download|file|storage|archive)\b/i],
    minScore: 2,
  },
  {
    type: '모바일 애플리케이션',
    patterns: [/\bandroidmanifest\b|\bactivity\b|\bfragment\b|\bintent\b|\breact-native\b|\bflutter\b/i],
    minScore: 1,
  },
  {
    type: '백엔드 API 서비스',
    patterns: [/\bexpress\b/i, /\brouter\.(get|post|put|delete)\b/i, /\bfastapi\b/i, /\bflask\b/i, /\b@RestController\b/i],
    minScore: 1,
  },
  {
    type: '메뉴 기반 네이티브 프로그램',
    patterns: [/\bmenu\b/i, /\bchoice\b/i, /\bscanf\b/i, /\bfgets\b/i, /\bread\s*\(\s*0\s*,/i],
    minScore: 2,
  },
];

const LEGACY_APP_TYPE_TO_SERVICE_TYPE = {
  '힙 메모리 객체를 관리하는': '메모리 조작형 네이티브 프로그램',
  '메뉴 입력을 받아 상태를 변경하는': '메뉴 기반 네이티브 프로그램',
  'API 요청을 처리하는': '백엔드 API 서비스',
  '인증과 데이터 처리를 수행하는': '인증 및 데이터 처리 서비스',
  '모바일 기능을 제공하는': '모바일 애플리케이션',
  '네트워크 시각화 기능을 제공하는': '네트워크 시각화 서비스',
};

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
  const ruleEngineMarkers = /\b(VULNERABILITY_RULES|collectVulnerabilityFindings|verifyRuleEvidence|buildStructuredFinding|createFindingFromRule|buildCodexFinalReportPrompt|buildCodexUnifiedAnalysisPrompt|buildCodexReconPrompt)\b/.test(safeText);
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
  const logicBearingServerPath = /(^|\/)(app\/api|lib\/server|auth|session|config|database|db|queries?|repositories?|services?|workers?|jobs?)(\/|$)/i.test(hints.normalizedPath);

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
  const securityBoundaryScore = countMatchedPatterns(safeText, [
    /\b(cookies?|headers)\b/i,
    /\b(getSession|commitSession|clearSession|setAuthenticatedSession|clearOAuthSession)\b/i,
    /\b(oauth|session|cookie|redirectUri|redirect|origin|host|x-forwarded-host|x-forwarded-proto)\b/i,
    /\b(process\.env|APP_BASE_URL|TRUST_PROXY_HEADERS|GITHUB_[A-Z0-9_]+|SESSION_SECRET)\b/i,
    /\b(new URL|normalizeOrigin|getRequestAppOrigin|getRequestHeader|NextResponse\.redirect)\b/i,
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
  const executionScore = codeScore + (frameworkScore * 2) + (entrypointScore * 2) + dataflowScore + securityBoundaryScore + (nativeCodeScore * 2);
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
      || (logicBearingServerPath && codeScore >= 3 && (dataflowScore > 0 || securityBoundaryScore >= 2))
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
      ? collectInterestingDisassemblyLines(lines.join('\n')).join('\n') || '/* 취약점을 직접 가리키는 디스어셈블 코드를 자동 추출하지 못했습니다. */'
      : '/* 취약점을 직접 가리키는 코드 조각을 자동 추출하지 못했습니다. */';
  }

  if (kind === 'binary') {
    return lines
      .slice(Math.max(0, matchedIndex - 2), matchedIndex + 6)
      .map((line) => line.replace(/\t/g, '  ').trimEnd())
      .filter(Boolean)
      .join('\n');
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

function normalizeMultilineSnippet(value) {
  return String(value || '')
    .replace(/\r\n/g, '\n')
    .replace(/\t/g, '  ')
    .split('\n')
    .map((line) => line.replace(/\s+$/g, ''))
    .join('\n')
    .trim();
}

function looksLikeAssemblySnippet(value) {
  return /0x[0-9a-f]+:|<[A-Za-z0-9_@.+-]+>|\b(call|lea|mov|cmp|test|jmp|je|jne|syscall|ret)\b/i.test(String(value || ''));
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

export async function buildFileContexts(acceptedFiles, onProgress) {
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
    'routes, handlers, controllers, services, auth/session code, query code, file-processing code, worker code, native entrypoints 등 핵심 로직 파일을 충분히 보기 전에는 "취약점 없음" 결론을 내리지 않는다.',
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
        'runtimeMap은 최대 12개까지만 작성한다',
        'logicFilesReviewed는 최대 40개까지만 작성한다',
        'entrypoints는 최대 20개까지만 작성한다',
        'importsAndModules는 최대 20개까지만 작성한다',
        'missingModules는 최대 12개까지만 작성한다',
        'routeOrHandlerInventory는 최대 20개까지만 작성한다',
        'securityMechanisms는 최대 12개까지만 작성한다',
        'highRiskRecheckTargets는 최대 12개까지만 작성한다',
        'coverageAssessment에는 vulnerability 또는 recommendation 결론을 내리기에 로직 파일 검토가 충분했는지 적는다',
        'attackSurfaces는 최대 12개까지만 작성한다',
        'candidateVulnerabilitiesNeedingProof는 최대 12개까지만 작성한다',
        'unresolvedAssumptions는 최대 10개까지만 작성한다',
        '장황한 서술 대신 짧고 사실적인 문장을 쓴다',
      ],
      uploadedFiles: manifest,
    }, null, 2),
  ].join('\n\n');
}

function normalizeWorkspaceReviewPath(value) {
  return normalizeSourcePath(String(value || '').trim()).replace(/^\.?\//, '');
}

function stripWorkspaceStoragePrefix(relativePath) {
  return normalizeWorkspaceReviewPath(relativePath)
    .replace(/^\d+-[^/]+__extracted\//, '')
    .replace(/^\d+-/, '');
}

function isAnalysisArtifactPath(relativePath) {
  return /(^|\/)analysis-(recon|review-batch-\d+|flow-model|invariants-\d+|report(?:-recommendation)?)\.(txt|json)$/i.test(
    normalizeWorkspaceReviewPath(relativePath),
  );
}

function chunkItems(items = [], chunkSize = 1) {
  const normalizedChunkSize = Math.max(1, Number(chunkSize) || 1);
  const chunks = [];

  for (let index = 0; index < items.length; index += normalizedChunkSize) {
    chunks.push(items.slice(index, index + normalizedChunkSize));
  }

  return chunks;
}

function findRequestedReviewPathMatch(pathValue, requestedFiles = []) {
  const normalizedPath = normalizeWorkspaceReviewPath(pathValue);

  if (!normalizedPath) {
    return '';
  }

  if (requestedFiles.includes(normalizedPath)) {
    return normalizedPath;
  }

  const suffixMatches = requestedFiles.filter((candidate) => (
    candidate.endsWith(normalizedPath)
    || normalizedPath.endsWith(candidate)
  ));

  return suffixMatches.length === 1 ? suffixMatches[0] : '';
}

function normalizeCompactStringList(value, { maxItems = 5, maxLength = 140 } = {}) {
  return (Array.isArray(value) ? value : [value])
    .map((item) => compactReportText(String(item || '').trim(), { maxLength, maxSentences: 2 }))
    .filter(Boolean)
    .slice(0, maxItems);
}

function buildReviewPathBoostSet({ contexts = [], reconnaissanceReport = null } = {}) {
  const boosts = new Set();
  const addBoost = (value) => {
    const normalized = normalizeInvestigationTargetPath(value);
    if (normalized) {
      boosts.add(normalized);
    }
  };

  getRuntimeEvidenceContexts(contexts)
    .filter((context) => !isLikelySecurityToolingContext(context) && !isLikelyIllustrativeTextContext(context))
    .forEach((context) => {
      addBoost(context.embeddedSourceFile || context.sourceFile);
    });

  (Array.isArray(reconnaissanceReport?.logicFilesReviewed) ? reconnaissanceReport.logicFilesReviewed : [])
    .forEach(addBoost);
  (Array.isArray(reconnaissanceReport?.highRiskRecheckTargets) ? reconnaissanceReport.highRiskRecheckTargets : [])
    .forEach(addBoost);
  (Array.isArray(reconnaissanceReport?.entrypoints) ? reconnaissanceReport.entrypoints : [])
    .forEach((entrypoint) => addBoost(entrypoint?.path));

  return boosts;
}

async function collectWorkspaceReviewTargets({ workspaceRoot, contexts = [], reconnaissanceReport = null }) {
  const reviewPathBoosts = buildReviewPathBoostSet({ contexts, reconnaissanceReport });
  const candidates = [];

  for (const candidatePath of walkDirectory(workspaceRoot)) {
    const relativePath = normalizeWorkspaceReviewPath(path.relative(workspaceRoot, candidatePath));

    if (!relativePath || isAnalysisArtifactPath(relativePath)) {
      continue;
    }

    const scoringPath = stripWorkspaceStoragePrefix(relativePath);
    const hints = getPathClassificationHints(scoringPath);
    if (hints.isAssetPath || hints.isStylePath) {
      continue;
    }

    const detectedKind = await detectFileKind(candidatePath);
    if (detectedKind !== 'text' && detectedKind !== 'binary') {
      continue;
    }

    let score = getInterestingArchiveCandidateScore(candidatePath, scoringPath);
    if (isLikelyLogicBearingArchivePath(scoringPath)) {
      score += 6;
    }
    if (hints.isConfigPath && /\b(auth|session|config|database|token|oauth|redirect|github)\b/i.test(scoringPath)) {
      score += 5;
    }
    if ([...reviewPathBoosts].some((boostPath) => scoringPath.endsWith(boostPath) || boostPath.endsWith(scoringPath))) {
      score += 8;
    }
    if (hints.isDocPath || hints.isExamplePath || hints.isBackupPath || hints.isTestPath) {
      score -= 8;
    }

    if (score <= 0 && !isLikelyLogicBearingArchivePath(scoringPath)) {
      continue;
    }

    candidates.push({
      path: relativePath,
      score,
      kind: detectedKind,
    });
  }

  return candidates
    .sort((left, right) => right.score - left.score || left.path.localeCompare(right.path))
    .slice(0, MAX_WORKSPACE_REVIEW_FILES)
    .map((candidate) => candidate.path);
}

function normalizeFileReviewItem(item, requestedFiles = []) {
  const matchedPath = findRequestedReviewPathMatch(item?.path, requestedFiles);
  if (!matchedPath) {
    return null;
  }

  return {
    path: matchedPath,
    reviewed: item?.reviewed !== false,
    role: compactReportText(String(item?.role || '역할 정리 누락').trim(), { maxLength: 180, maxSentences: 2 }),
    inputs: normalizeCompactStringList(item?.inputs, { maxItems: 4, maxLength: 120 }),
    stateChanges: normalizeCompactStringList(item?.stateChanges, { maxItems: 4, maxLength: 140 }),
    outboundCalls: normalizeCompactStringList(item?.outboundCalls, { maxItems: 4, maxLength: 120 }),
    trustBoundaries: normalizeCompactStringList(item?.trustBoundaries, { maxItems: 4, maxLength: 120 }),
    authOrPrivilege: normalizeCompactStringList(item?.authOrPrivilege, { maxItems: 4, maxLength: 120 }),
    notableSecurityChecks: normalizeCompactStringList(item?.notableSecurityChecks, { maxItems: 4, maxLength: 140 }),
    likelySecurityRelevantFlows: normalizeCompactStringList(item?.likelySecurityRelevantFlows, { maxItems: 4, maxLength: 160 }),
    unansweredQuestions: normalizeCompactStringList(item?.unansweredQuestions, { maxItems: 3, maxLength: 140 }),
  };
}

function normalizeCodexFileReviewBatch(parsedReport, requestedFiles = []) {
  const rawFiles = Array.isArray(parsedReport?.files) ? parsedReport.files : [];
  const normalizedMap = new Map();

  rawFiles.forEach((item) => {
    const normalizedItem = normalizeFileReviewItem(item, requestedFiles);
    if (normalizedItem && !normalizedMap.has(normalizedItem.path)) {
      normalizedMap.set(normalizedItem.path, normalizedItem);
    }
  });

  const files = requestedFiles.map((requestedPath) => normalizedMap.get(requestedPath) || {
    path: requestedPath,
    reviewed: false,
    role: '검토 결과가 누락되었습니다.',
    inputs: [],
    stateChanges: [],
    outboundCalls: [],
    trustBoundaries: [],
    authOrPrivilege: [],
    notableSecurityChecks: [],
    likelySecurityRelevantFlows: [],
    unansweredQuestions: ['이 파일 검토 결과가 응답에 포함되지 않았습니다.'],
  });

  return {
    batchSummary: compactReportText(String(parsedReport?.batchSummary || '').trim(), { maxLength: 220, maxSentences: 2 }),
    files,
    missingFiles: files.filter((file) => !file.reviewed).map((file) => file.path),
  };
}

function mergeFileReviewBatches(reports = []) {
  const merged = new Map();

  reports.forEach((report) => {
    const files = Array.isArray(report?.files) ? report.files : [];
    files.forEach((file) => {
      if (file?.path && !merged.has(file.path)) {
        merged.set(file.path, file);
      }
    });
  });

  return Array.from(merged.values());
}

function buildFileReviewDigest(fileReviews = []) {
  return fileReviews.map((review) => ({
    path: review.path,
    role: review.role,
    inputs: review.inputs,
    stateChanges: review.stateChanges,
    outboundCalls: review.outboundCalls,
    trustBoundaries: review.trustBoundaries,
    authOrPrivilege: review.authOrPrivilege,
    notableSecurityChecks: review.notableSecurityChecks,
    likelySecurityRelevantFlows: review.likelySecurityRelevantFlows,
    unansweredQuestions: review.unansweredQuestions,
  }));
}

function normalizeFlowList(value, { maxItems = 10, maxLength = 180 } = {}) {
  return (Array.isArray(value) ? value : [value])
    .map((item) => compactReportText(String(item || '').trim(), { maxLength, maxSentences: 2 }))
    .filter(Boolean)
    .slice(0, maxItems);
}

function normalizeFlowModel(parsedModel, fileReviews = []) {
  if (!parsedModel || typeof parsedModel !== 'object') {
    return null;
  }

  const reviewedFiles = new Set(fileReviews.map((review) => review.path));
  const normalizePath = (value) => findRequestedReviewPathMatch(value, [...reviewedFiles]) || '';

  return {
    serviceType: compactReportText(String(parsedModel.serviceType || parsedModel.applicationType || '').trim(), { maxLength: 90, maxSentences: 1 }),
    systemSummary: compactReportText(String(parsedModel.systemSummary || '').trim(), { maxLength: 260, maxSentences: 3 }),
    fileRoles: (Array.isArray(parsedModel.fileRoles) ? parsedModel.fileRoles : [])
      .map((item) => ({
        path: normalizePath(item?.path),
        role: compactReportText(String(item?.role || '').trim(), { maxLength: 140, maxSentences: 2 }),
      }))
      .filter((item) => item.path && item.role)
      .slice(0, 48),
    entrypoints: (Array.isArray(parsedModel.entrypoints) ? parsedModel.entrypoints : [])
      .map((item) => ({
        path: normalizePath(item?.path),
        input: compactReportText(String(item?.input || '').trim(), { maxLength: 120, maxSentences: 2 }),
        action: compactReportText(String(item?.action || '').trim(), { maxLength: 140, maxSentences: 2 }),
      }))
      .filter((item) => item.path)
      .slice(0, 24),
    trustBoundaries: normalizeFlowList(parsedModel.trustBoundaries, { maxItems: 16, maxLength: 160 }),
    privilegeBoundaries: normalizeFlowList(parsedModel.privilegeBoundaries, { maxItems: 16, maxLength: 160 }),
    stateStores: normalizeFlowList(parsedModel.stateStores, { maxItems: 16, maxLength: 160 }),
    crossFileFlows: (Array.isArray(parsedModel.crossFileFlows) ? parsedModel.crossFileFlows : [])
      .map((flow) => ({
        name: compactReportText(String(flow?.name || '').trim(), { maxLength: 120, maxSentences: 1 }),
        attackerInput: compactReportText(String(flow?.attackerInput || '').trim(), { maxLength: 120, maxSentences: 2 }),
        targetAction: compactReportText(String(flow?.targetAction || '').trim(), { maxLength: 140, maxSentences: 2 }),
        steps: normalizeFlowList(flow?.steps, { maxItems: 8, maxLength: 180 }),
        guardrails: normalizeFlowList(flow?.guardrails, { maxItems: 5, maxLength: 140 }),
      }))
      .filter((flow) => flow.name || flow.steps.length)
      .slice(0, 16),
    securityInvariants: (Array.isArray(parsedModel.securityInvariants) ? parsedModel.securityInvariants : [])
      .map((item) => ({
        name: compactReportText(String(item?.name || '').trim(), { maxLength: 120, maxSentences: 1 }),
        statement: compactReportText(String(item?.statement || '').trim(), { maxLength: 180, maxSentences: 2 }),
        files: normalizeFlowList(item?.files, { maxItems: 5, maxLength: 120 }),
      }))
      .filter((item) => item.name || item.statement)
      .slice(0, 20),
    unresolvedAreas: normalizeFlowList(parsedModel.unresolvedAreas, { maxItems: 12, maxLength: 180 }),
  };
}

function normalizeInvariantCandidate(candidate) {
  if (!candidate || typeof candidate !== 'object') {
    return null;
  }

  return {
    title: compactReportText(String(candidate.title || '').trim(), { maxLength: 120, maxSentences: 1 }),
    invariant: compactReportText(String(candidate.invariant || '').trim(), { maxLength: 180, maxSentences: 2 }),
    attackerInput: compactReportText(String(candidate.attackerInput || '').trim(), { maxLength: 120, maxSentences: 2 }),
    protectedAsset: compactReportText(String(candidate.protectedAsset || '').trim(), { maxLength: 120, maxSentences: 2 }),
    criticalPath: normalizeFlowList(candidate.criticalPath, { maxItems: 8, maxLength: 180 }),
    guardrailExpectation: compactReportText(String(candidate.guardrailExpectation || '').trim(), { maxLength: 180, maxSentences: 2 }),
    observedBehavior: compactReportText(String(candidate.observedBehavior || '').trim(), { maxLength: 180, maxSentences: 2 }),
    exploitEffect: compactReportText(String(candidate.exploitEffect || '').trim(), { maxLength: 180, maxSentences: 2 }),
    confidence: ['high', 'medium', 'low'].includes(String(candidate.confidence || '').trim().toLowerCase())
      ? String(candidate.confidence || '').trim().toLowerCase()
      : 'medium',
    needsRecheck: candidate.needsRecheck !== false,
    codeEvidence: (Array.isArray(candidate.codeEvidence) ? candidate.codeEvidence : [])
      .map((item) => ({
        path: compactReportText(String(item?.path || '').trim(), { maxLength: 160, maxSentences: 1 }),
        snippet: compactScenarioText(String(item?.snippet || '').trim(), { maxLength: 320, maxSentences: 4 }),
        reason: compactReportText(String(item?.reason || '').trim(), { maxLength: 160, maxSentences: 2 }),
      }))
      .filter((item) => item.path && item.snippet)
      .slice(0, 4),
  };
}

function normalizeInvariantAnalysis(parsedAnalysis) {
  if (!parsedAnalysis || typeof parsedAnalysis !== 'object') {
    return null;
  }

  return {
    serviceType: compactReportText(String(parsedAnalysis.serviceType || '').trim(), { maxLength: 90, maxSentences: 1 }),
    reasoningSummary: compactReportText(String(parsedAnalysis.reasoningSummary || '').trim(), { maxLength: 240, maxSentences: 3 }),
    brokenInvariants: (Array.isArray(parsedAnalysis.brokenInvariants) ? parsedAnalysis.brokenInvariants : [])
      .map(normalizeInvariantCandidate)
      .filter(Boolean),
    suspiciousButUnproven: (Array.isArray(parsedAnalysis.suspiciousButUnproven) ? parsedAnalysis.suspiciousButUnproven : [])
      .map(normalizeInvariantCandidate)
      .filter(Boolean),
    coverageGaps: normalizeFlowList(parsedAnalysis.coverageGaps, { maxItems: 12, maxLength: 180 }),
  };
}

function buildInvariantKey(candidate) {
  return normalizeComparableText([
    candidate?.title,
    candidate?.invariant,
    ...(Array.isArray(candidate?.criticalPath) ? candidate.criticalPath.slice(0, 3) : []),
  ].filter(Boolean).join('\n'));
}

function mergeInvariantAnalyses(...analyses) {
  const normalizedAnalyses = analyses.filter(Boolean);
  if (!normalizedAnalyses.length) {
    return null;
  }

  const seenBroken = new Set();
  const seenSuspicious = new Set();
  const brokenInvariants = [];
  const suspiciousButUnproven = [];

  normalizedAnalyses.forEach((analysis) => {
    (analysis.brokenInvariants || []).forEach((candidate) => {
      const key = buildInvariantKey(candidate);
      if (key && !seenBroken.has(key)) {
        seenBroken.add(key);
        brokenInvariants.push(candidate);
      }
    });

    (analysis.suspiciousButUnproven || []).forEach((candidate) => {
      const key = buildInvariantKey(candidate);
      if (key && !seenSuspicious.has(key) && !seenBroken.has(key)) {
        seenSuspicious.add(key);
        suspiciousButUnproven.push(candidate);
      }
    });
  });

  return {
    serviceType: normalizedAnalyses.find((analysis) => analysis.serviceType)?.serviceType || '',
    reasoningSummary: normalizedAnalyses.map((analysis) => analysis.reasoningSummary).filter(Boolean)[0] || '',
    brokenInvariants,
    suspiciousButUnproven,
    coverageGaps: Array.from(new Set(normalizedAnalyses.flatMap((analysis) => analysis.coverageGaps || []))).slice(0, 16),
  };
}

function inferInvariantFindingTitle(candidate) {
  const text = normalizeComparableText([
    candidate?.title,
    candidate?.invariant,
    candidate?.guardrailExpectation,
    candidate?.observedBehavior,
    candidate?.exploitEffect,
    ...(Array.isArray(candidate?.criticalPath) ? candidate.criticalPath : []),
    ...(Array.isArray(candidate?.codeEvidence) ? candidate.codeEvidence.map((item) => item?.path) : []),
  ].filter(Boolean).join('\n'));

  if (/(host|origin|x-forwarded|redirect uri|redirect_url|callback url|nexturl\.origin|request\.url)/i.test(text)) {
    return 'Host Header Poisoning';
  }
  if (/(csrf|cross-site|intent|explicit user intent|user intent|recent re-auth|reauth|sameSite|link intent|account link|oauth link)/i.test(text)) {
    return 'CSRF';
  }
  if (/(oauth|github|session|state|callback|account link|account binding|session principal)/i.test(text)) {
    return 'Auth Bypass';
  }
  if (/(owner|ownership|userid|userid|accountid|report id|share token|resource owner)/i.test(text)) {
    return 'IDOR';
  }
  if (/(path|upload|download|archive|filesystem|readfile|writereadstream|createwritestream)/i.test(text)) {
    return 'Path Traversal';
  }
  if (/(secret|token|session secret|api key|hardcoded)/i.test(text)) {
    return 'Hardcoded Secret';
  }

  return compactReportText(String(candidate?.title || '보안 취약점').trim(), { maxLength: 60, maxSentences: 1 }) || '보안 취약점';
}

function inferInvariantSeverity(candidate) {
  const text = normalizeComparableText([
    candidate?.protectedAsset,
    candidate?.observedBehavior,
    candidate?.exploitEffect,
    ...(Array.isArray(candidate?.criticalPath) ? candidate.criticalPath : []),
  ].filter(Boolean).join('\n'));

  if (/(account takeover|세션 탈취|권한 상승|관리자|admin|token takeover|임의 코드 실행|code execution|전체 데이터|private repository)/i.test(text)) {
    return 'high';
  }
  if (/(redirect|origin|callback|oauth|github|session|state|권한|인증|민감 데이터)/i.test(text)) {
    return 'medium';
  }

  return 'low';
}

function buildInvariantCodeEvidence(candidate) {
  return (Array.isArray(candidate?.codeEvidence) ? candidate.codeEvidence : [])
    .map((item) => ({
      path: String(item?.path || '').trim(),
      snippet: String(item?.snippet || '').trim(),
      reason: String(item?.reason || '').trim(),
    }))
    .filter((item) => item.path && item.snippet);
}

function createFindingFromInvariantCandidate(candidate, index = 0, confirmed = true) {
  const title = inferInvariantFindingTitle(candidate);
  const codeEvidence = buildInvariantCodeEvidence(candidate);
  const primaryEvidence = codeEvidence[0] || { path: '관련 코드 구간', snippet: '핵심 코드 스니펫을 생성하지 못했습니다.', reason: '' };
  const location = codeEvidence.length
    ? codeEvidence.map((item) => item.path).slice(0, 4).join(', ')
    : '관련 코드 구간';
  const criticalPath = Array.isArray(candidate?.criticalPath) ? candidate.criticalPath.filter(Boolean) : [];
  const explanation = compactReportText(
    String(candidate?.invariant || candidate?.title || '보안 불변식 위반이 확인되었습니다.').trim(),
    { maxLength: 900, maxSentences: 6 },
  );
  const detail = compactScenarioText(
    [
      candidate?.attackerInput ? `1) 공격자는 ${String(candidate.attackerInput).trim()} 를 제어하거나 그 값의 형식과 내용을 바꿀 수 있다.` : '',
      criticalPath.length ? `2) 실제 코드 흐름은 ${criticalPath.join(' -> ')} 순서로 이어지며, 이 경로를 따라 입력이 보안 민감 동작 쪽으로 이동한다.` : '',
      candidate?.guardrailExpectation ? `3) 원래는 ${String(candidate.guardrailExpectation).trim()} 같은 보안 조건이 유지되어야 한다.` : '',
      candidate?.observedBehavior ? `4) 하지만 실제 코드에서는 ${String(candidate.observedBehavior).trim()} 상태가 되며, 방어 조건이 기대한 시점에 적용되지 않거나 아예 빠져 있다.` : '',
      candidate?.exploitEffect ? `5) 그 결과 ${String(candidate.exploitEffect).trim()} 영향이 생기고, 공격자는 권한 우회, 데이터 노출, 상태 변조 같은 결과를 노릴 수 있다.` : '',
      '6) 교육적으로는 단순히 한 줄이 문제라는 식으로 보기보다, 입력이 들어온 시점부터 검증, 상태 저장, 후속 호출, 최종 privileged action까지 어떤 순서로 이어지는지 보는 것이 중요하다.',
    ].filter(Boolean).join('\n'),
    { maxLength: 1800, maxSentences: 12 },
  );
  const remediation = compactReportText(
    [
      candidate?.guardrailExpectation ? `먼저 ${String(candidate.guardrailExpectation).trim()} 조건을 코드로 강제해야 한다.` : '',
      candidate?.protectedAsset ? `보호 대상은 ${String(candidate.protectedAsset).trim()} 이므로, 이 자원에 닿기 전 세션 주체와 요청 주체, 소유권, redirect/origin 출처를 다시 확인해야 한다.` : '',
      '실무적으로는 취약점이 드러난 함수 하나만 고치는 것으로 끝내지 말고, 같은 상태값이나 같은 세션 정보가 지나가는 다른 엔드포인트와 콜백 경로도 함께 점검해야 한다.',
      '교차 파일 흐름에서는 엔트리포인트, 세션/토큰 저장소, callback 처리, DB 갱신, redirect 생성 순서로 방어 조건이 끊기지 않게 점검하는 편이 좋다. 가능하면 권한 확인과 상태 검증을 공통 함수로 모아 우회 경로를 줄이는 것이 더 안전하다.',
    ].filter(Boolean).join('\n\n'),
    { maxLength: 1500, maxSentences: 10 },
  );

  return {
    id: `invariant-finding-${index + 1}`,
    title,
    severity: inferInvariantSeverity(candidate),
    confirmed,
    location,
    codeLocation: primaryEvidence.snippet,
    explanation,
    detail,
    remediation,
    patchExample: '',
  };
}

function buildInvariantBackedReport({ invariantAnalysis, serviceType = '', resultMode = 'vulnerability' } = {}) {
  const brokenFindings = (Array.isArray(invariantAnalysis?.brokenInvariants) ? invariantAnalysis.brokenInvariants : [])
    .map((candidate, index) => createFindingFromInvariantCandidate(candidate, index, true));
  const suspiciousFindings = (Array.isArray(invariantAnalysis?.suspiciousButUnproven) ? invariantAnalysis.suspiciousButUnproven : [])
    .map((candidate, index) => createFindingFromInvariantCandidate(candidate, index + brokenFindings.length, false));
  const findings = resultMode === 'vulnerability' ? brokenFindings : suspiciousFindings;
  const applicationType = serviceType || invariantAnalysis?.serviceType || '';

  return {
    title: '',
    applicationType,
    applicationReport: '',
    resultMode,
    summary: compactReportText(String(invariantAnalysis?.reasoningSummary || '').trim(), { maxLength: 180, maxSentences: 2 }),
    findings,
  };
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

  if (String(parsedReport.resultMode || '').trim() === 'vulnerability') {
    return false;
  }

  return suspectedFindings.length > 0 || investigationTargets.length > 0 || hasWeakRecommendationPayload(parsedReport);
}

export function buildCodexFileReviewPrompt({
  manifest,
  reconnaissance,
  filesToReview = [],
  batchIndex = 1,
  totalBatches = 1,
}) {
  return [
    'You are in the file-review phase of a security analysis workflow.',
    'The current working directory contains the uploaded files and extracted runtime files.',
    'Do not start from vulnerability names. Your job is to understand what each requested file actually does.',
    'Open every requested file in this batch before responding.',
    'For each file, identify its runtime role, external inputs, state changes, outbound calls, trust boundaries, privilege/auth relevance, important security checks, and the code flows that look security-relevant.',
    'Pay special attention to transient session values, callback state, mode flags, ownership ids, redirect targets, or other temporary values that later authorize a privileged action in another file.',
    'If a file creates or consumes session-carried intent for login, linking, reset, sharing, admin actions, or redirects, call that out explicitly.',
    'Do not skip any requested file. If a file cannot be read or does not look runtime-relevant, still return an entry and explain why.',
    'Treat README prose, tests, fixtures, examples, prompt backups, analyzer rules, and scanner signatures as reference-only unless the file is an actual runtime file in this batch.',
    `This is file-review batch ${batchIndex}/${totalBatches}.`,
    'Return Korean JSON only.',
    'Reconnaissance notes:',
    reconnaissance || 'No reconnaissance notes were produced.',
    JSON.stringify({
      requestedFiles: filesToReview,
      schema: {
        batchSummary: 'string',
        files: [
          {
            path: 'exactly one path from requestedFiles',
            reviewed: 'boolean',
            role: 'string',
            inputs: ['string'],
            stateChanges: ['string'],
            outboundCalls: ['string'],
            trustBoundaries: ['string'],
            authOrPrivilege: ['string'],
            notableSecurityChecks: ['string'],
            likelySecurityRelevantFlows: ['string'],
            unansweredQuestions: ['string'],
          },
        ],
      },
      constraints: [
        'files 배열에는 requestedFiles의 모든 경로가 정확히 한 번씩 있어야 한다',
        'path는 requestedFiles에 있는 원문 경로를 그대로 사용한다',
        '취약점 이름 위주 체크리스트로 쓰지 말고 파일 역할과 흐름을 먼저 쓴다',
        '각 배열 필드는 최대 4개까지만 쓴다',
      ],
      uploadedFiles: manifest,
    }, null, 2),
  ].join('\n\n');
}

export function buildCodexFlowSynthesisPrompt({
  manifest,
  reconnaissance,
  fileReviews = [],
  investigationTargets = [],
}) {
  return [
    'You are in the cross-file flow synthesis phase of a security analysis workflow.',
    'Use the reviewed-file notes to reconstruct how the service actually works across files.',
    'Do not start from vulnerability names. Reconstruct entrypoints, state stores, trust boundaries, privilege boundaries, cross-file flows, and security invariants.',
    'Every cross-file flow must be grounded in the reviewed files.',
    'Security invariants should be statements like "the callback must stay bound to the same session principal" or "redirect URLs must come from trusted origins", not vulnerability taxonomy labels.',
    'Model whether temporary session state or callback state is being treated as proof of user intent for a later privileged action.',
    'Model whether a GET-reachable or cross-site reachable step can arm later privileged behavior without a fresh confirmation step.',
    'Return Korean JSON only.',
    'Reconnaissance notes:',
    reconnaissance || 'No reconnaissance notes were produced.',
    investigationTargets.length
      ? `High-risk files:\n${JSON.stringify(investigationTargets, null, 2)}`
      : 'High-risk files: []',
    JSON.stringify({
      reviewedFiles: buildFileReviewDigest(fileReviews),
      schema: {
        serviceType: 'string',
        systemSummary: 'string',
        fileRoles: [
          {
            path: 'string',
            role: 'string',
          },
        ],
        entrypoints: [
          {
            path: 'string',
            input: 'string',
            action: 'string',
          },
        ],
        trustBoundaries: ['string'],
        privilegeBoundaries: ['string'],
        stateStores: ['string'],
        crossFileFlows: [
          {
            name: 'string',
            attackerInput: 'string',
            targetAction: 'string',
            steps: ['string'],
            guardrails: ['string'],
          },
        ],
        securityInvariants: [
          {
            name: 'string',
            statement: 'string',
            files: ['string'],
          },
        ],
        unresolvedAreas: ['string'],
      },
      constraints: [
        'crossFileFlows는 실제 reviewedFiles에서 설명 가능한 단계만 넣는다',
        'securityInvariants는 취약점 이름 대신 보안 불변식 문장으로 작성한다',
        '장황한 설명 대신 짧고 사실적인 문장을 쓴다',
      ],
      uploadedFiles: manifest,
    }, null, 2),
  ].join('\n\n');
}

export function buildCodexInvariantAnalysisPrompt({
  manifest,
  reconnaissance,
  fileReviews = [],
  flowModel = null,
  sweepIndex = 1,
  previousAnalysis = null,
}) {
  return [
    'You are in the invariant-analysis phase of a security review.',
    'Do not start from a vulnerability checklist.',
    'Use the reviewed files and cross-file flow model to find broken security invariants, attacker-controlled paths, privilege mismatches, ownership/order bugs, unsafe trust assumptions, or data-exposure paths.',
    'A broken invariant must explain the attacker input, the protected asset, the expected guardrail, what the code actually does, and why the path is plausible.',
    'Look for cases where temporary session state, callback state, returnTo values, mode flags, or ownership ids are reused as authority for a later privileged action without a fresh proof of intent.',
    'Also look for cases where the first step is GET-reachable or otherwise cross-site reachable, but a later callback or follow-up request performs account linking, session binding, password reset, redirect approval, or other privileged mutation.',
    sweepIndex === 1
      ? 'This is invariant analysis pass #1. Focus on surfacing concrete broken invariants grounded in code and flow.'
      : 'This is invariant analysis pass #2. Challenge pass #1, remove weak claims, revisit missed flows, and add any broken invariants that were overlooked.',
    previousAnalysis
      ? `Previous invariant analysis:\n${JSON.stringify(previousAnalysis, null, 2)}`
      : 'Previous invariant analysis: none',
    'Return Korean JSON only.',
    'Reconnaissance notes:',
    reconnaissance || 'No reconnaissance notes were produced.',
    JSON.stringify({
      reviewedFiles: buildFileReviewDigest(fileReviews),
      flowModel,
      schema: {
        serviceType: 'string',
        reasoningSummary: 'string',
        brokenInvariants: [
          {
            title: 'string',
            invariant: 'string',
            attackerInput: 'string',
            protectedAsset: 'string',
            criticalPath: ['string'],
            guardrailExpectation: 'string',
            observedBehavior: 'string',
            exploitEffect: 'string',
            confidence: '"high" | "medium" | "low"',
            needsRecheck: 'boolean',
            codeEvidence: [
              {
                path: 'string',
                snippet: 'string',
                reason: 'string',
              },
            ],
          },
        ],
        suspiciousButUnproven: ['same shape as brokenInvariants'],
        coverageGaps: ['string'],
      },
      constraints: [
        'brokenInvariants는 코드와 흐름으로 설명 가능한 항목만 넣는다',
        '취약점 이름보다 깨진 보안 불변식 자체를 먼저 설명한다',
        '각 codeEvidence는 실제 파일 경로와 핵심 코드 스니펫을 포함해야 한다',
      ],
      uploadedFiles: manifest,
    }, null, 2),
  ].join('\n\n');
}

export function buildCodexUnifiedAnalysisPrompt({
  manifest,
  runtimeFileHints = [],
}) {
  return [
    'You are generating the final security report for an educational vulnerability-analysis product.',
    'The current working directory contains the uploaded files and any extracted archive contents.',
    'This workflow has only two stages: upload filtering has already finished, and now you must perform the full code analysis, vulnerability search, educational explanation, and final report writing in this single run.',
    'Do not rely on a vulnerability checklist or static signature table. Read the code, reconstruct the real runtime behavior, and reason about actual cross-file flows.',
    'Start by identifying which files are truly runtime-relevant. Treat README prose, tests, fixtures, examples, prompt backups, analyzer rules, scanner signatures, and explanatory comments as reference-only unless they are part of the real executable path.',
    'Runtime file hints are only hints. Use them as a starting point, but verify the code yourself and search for any additional runtime-relevant files you need.',
    'You must open and read the runtime-relevant files before concluding that no vulnerability exists.',
    'First understand what each runtime file does, what input it accepts, what state it changes, what other files it calls, and which trust or privilege boundary it touches.',
    'Then reconstruct the real cross-file flows such as request -> validation -> session/token/state -> callback -> database update -> redirect/response.',
    'Do not narrow the analysis to named vulnerability classes too early. Focus on broken security invariants, authorization mismatches, ownership bugs, unsafe trust assumptions, stale session intent, callback misuse, redirect/origin mistakes, and attacker-controlled data reaching privileged actions.',
    'Pay special attention to temporary session values, callback state, mode flags, ownership ids, redirect targets, oauth state, returnTo values, and any temporary value that later authorizes a privileged action.',
    'If a first step is GET-reachable or cross-site reachable, verify whether a later callback or follow-up request performs account linking, session binding, password reset, redirect approval, sharing, or another privileged mutation without a fresh proof of user intent.',
    'Perform the vulnerability search in two internal sweeps inside this same run.',
    'Sweep 1: after understanding the runtime files and flows, traverse the runtime-relevant files and cross-file paths once to find trustworthy vulnerabilities. If the code genuinely contains vulnerabilities, aim to surface at least 2.',
    'Sweep 2: if sweep 1 proves fewer than 2 trustworthy vulnerabilities, start over from the runtime files and flows, challenge your first assumptions, revisit missed files and cross-file state transitions, and try to surface at least 1 trustworthy vulnerability.',
    'If sweep 1 or sweep 2 proves at least 1 real vulnerability, return a vulnerability report.',
    'Only if both sweeps fail to prove a trustworthy vulnerability should you switch to recommendation mode and provide practical security hardening advice.',
    'The top-level title must be a user-facing product or solution label, not an internal behavior label and not a vulnerability name.',
    'Good examples: "모바일 쇼핑 서비스 리포트", "영상 처리 솔루션 리포트", "코드 보안 점검 솔루션 리포트".',
    'Avoid logic-labeled titles such as "메뉴 기반 네이티브 프로그램...", "상태를 변경하는 서비스...", "API 요청을 처리하는 서비스...", or long behavior-first labels such as "코드 업로드와 GitHub 저장소 취약점 분석 웹 서비스 취약점 리포트".',
    'applicationReport must have exactly two sentences. Sentence 1 must explain the service in plain language so a non-developer can understand it. Sentence 2 must explain the same service from a developer perspective and may mention endpoints, handlers, or functions.',
    'Each finding title must be a short concise vulnerability or security issue name only, such as "XSS", "SQL Injection", "CSRF", "IDOR", "Auth Bypass", "Host Header Poisoning", or another short name that fits the code evidence.',
    'Do not use vague titles like "입력 검증" or "설정 분리" unless you are in recommendation mode and no real vulnerability was proven after both sweeps.',
    'Every vulnerability finding must cite exact file paths and real code snippets from the runtime code. Do not use placeholder snippets.',
    'Every finding must be educational and use these five sections: 1) 취약점 설명 2) 취약점 원인 분석 3) 파일 경로 및 핵심 코드 4) 취약점 해결 방안 5) 패치 코드 예시.',
    'In 1) 취약점 설명, explain what the vulnerability itself is in a study-friendly way. Define the vulnerability, explain how it works, what kind of attacker behavior it enables, and why developers care about it. This section must not start with code-specific details; it must first teach the vulnerability itself.',
    'In 2) 취약점 원인 분석, explain the full code path and why the issue becomes exploitable in the real program. Track the real input, state, function calls, validation gaps, and final security impact in order. Do not just point at one line.',
    'In 4) 취약점 해결 방안, explain how to fix the issue in practice. Explain where to change the code, why that change closes the vulnerability, what a stronger defense looks like, and what additional checks or architecture changes would make the fix more complete.',
    'Make every section detailed enough for education. Prefer longer, clearer explanations over short summaries. The report should feel like study material, not a terse scan result.',
    'In 5) 패치 코드 예시, include both "현재 코드:" and "패치 예시 코드:".',
    'If you are in recommendation mode, still provide concrete and practical security advice findings rather than an empty result.',
    'Return Korean JSON only.',
    JSON.stringify({
      runtimeFileHints,
      schema: {
        title: 'string ending with "취약점 리포트" or "보안 조언 리포트"',
        applicationType: 'string describing the service category',
        applicationReport: 'exactly two sentences',
        resultMode: '"vulnerability" | "recommendation"',
        summary: 'string',
        logicFilesReviewed: ['string'],
        findings: [
          {
            title: 'short simple name only',
            severity: '"high" | "medium" | "low"',
            confirmed: 'boolean',
            location: 'file path summary',
            codeLocation: 'core code snippet',
            explanation: '1) 취약점 설명 - 취약점 자체의 정의와 원리',
            detail: '2) 취약점 원인 분석 - 실제 코드 흐름과 성립 이유',
            remediation: '4) 취약점 해결 방안 - 실무적인 수정 방법과 왜 안전해지는지',
            patchExample: '5) 패치 코드 예시',
          },
        ],
      },
      constraints: [
        'logicFilesReviewed must list the runtime files you actually inspected',
        'If resultMode is vulnerability, findings must contain at least 1 item backed by real code evidence',
        'If resultMode is recommendation, findings must contain practical security-advice items and must not be empty',
        'title must be a user-facing solution or service label, not a vulnerability name',
        'title must not use internal logic labels such as 메뉴 기반 네이티브 프로그램, 상태를 변경하는, API 요청을 처리하는, 코드 업로드와 GitHub 저장소 취약점 분석 웹 서비스',
        'applicationReport sentence 1 must be user-facing and easy to understand',
        'applicationReport sentence 2 must be developer-facing',
        'patchExample must contain both "현재 코드:" and "패치 예시 코드:"',
      ],
      uploadedFiles: manifest,
    }, null, 2),
  ].join('\n\n');
}

export function buildCodexFinalReportPrompt({
  manifest,
  reconnaissance,
  fileReviews = [],
  flowModel = null,
  invariantAnalysis = null,
}) {
  return [
    'You are generating the final security report for an educational vulnerability-analysis product.',
    'This final stage comes after per-file review, cross-file flow synthesis, and invariant analysis.',
    'Do not invent vulnerabilities. If the invariant analysis did not prove a real issue, switch to recommendation mode.',
    'The top-level title must describe what kind of service this is, not how it behaves internally and not what vulnerability it has.',
    'Good examples: "모바일 쇼핑앱 취약점 리포트", "영상 변환 웹 서비스 취약점 리포트", "코드 업로드와 GitHub 저장소 취약점 분석 웹 서비스 취약점 리포트".',
    'Avoid logic-labeled titles such as "메뉴 기반 네이티브 프로그램..." or "상태를 변경하는 서비스...".',
    'applicationReport must have exactly two sentences. Sentence 1 must be easy for non-developers to understand. Sentence 2 must explain the service from a developer perspective and may mention endpoints, handlers, or functions.',
    'Each finding title must be a short concise vulnerability or security issue name only.',
    'Each finding must be educational and use the five sections: 1) 취약점 설명 2) 취약점 원인 분석 3) 파일 경로 및 핵심 코드 4) 취약점 해결 방안 5) 패치 코드 예시.',
    'Return Korean JSON only.',
    'Reconnaissance notes:',
    reconnaissance || 'No reconnaissance notes were produced.',
    JSON.stringify({
      reviewedFiles: buildFileReviewDigest(fileReviews),
      flowModel,
      invariantAnalysis,
      schema: {
        title: 'string ending with "취약점 리포트" or "보안 조언 리포트"',
        applicationType: 'string describing the service category',
        applicationReport: 'exactly two sentences',
        resultMode: '"vulnerability" | "recommendation"',
        summary: 'string',
        findings: [
          {
            title: 'short simple name only',
            severity: '"high" | "medium" | "low"',
            confirmed: 'boolean',
            location: 'file path summary',
            codeLocation: 'core code snippet',
            explanation: '1) 취약점 설명',
            detail: '2) 취약점 원인 분석',
            remediation: '4) 취약점 해결 방안',
            patchExample: '5) 패치 코드 예시',
          },
        ],
      },
      constraints: [
        'title must describe the service category, not the vulnerability name',
        'title must not use internal logic labels such as 메뉴 기반 네이티브 프로그램, 상태를 변경하는, API 요청을 처리하는',
        'applicationReport sentence 1 must be easy for non-developers',
        'applicationReport sentence 2 must explain developer-facing implementation context',
        'If no trustworthy vulnerability was proven, set resultMode to recommendation and provide practical security advice findings',
        'patchExample must contain both "현재 코드:" and "패치 예시 코드:"',
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
    'Report BOTH confirmed vulnerabilities AND suspected/potential ones. Do not omit a finding just because evidence is partial.',
    'For suspected findings, clearly state "의심 단계" or "추가 검증 필요" in the detail field.',
    'Aim for at least 3-5 findings. Include low-severity issues such as missing headers, weak configs, or verbose error messages.',
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

function getParsedReportFindingCount(report) {
  return Array.isArray(report?.findings) ? report.findings.length : 0;
}

function isParsedVulnerabilityReport(report) {
  return String(report?.resultMode || '').trim() === 'vulnerability' && getParsedReportFindingCount(report) > 0;
}

function buildMergedFindingKey(finding) {
  return normalizeComparableText([
    finding?.title,
    finding?.location,
    stripCodeLocationLineNumbers(finding?.codeLocation || ''),
  ].filter(Boolean).join('\n'));
}

function mergeVulnerabilitySweepReports(...reports) {
  const vulnerabilityReports = reports.filter((report) => isParsedVulnerabilityReport(report));
  if (!vulnerabilityReports.length) {
    return null;
  }

  const baseReport = [...vulnerabilityReports]
    .sort((left, right) => getParsedReportFindingCount(right) - getParsedReportFindingCount(left))[0];
  const seen = new Set();
  const mergedFindings = [];

  vulnerabilityReports.forEach((report) => {
    report.findings.forEach((finding) => {
      const key = buildMergedFindingKey(finding);
      if (!key || seen.has(key)) {
        return;
      }
      seen.add(key);
      mergedFindings.push(finding);
    });
  });

  return {
    ...baseReport,
    resultMode: 'vulnerability',
    findings: mergedFindings,
    summary: baseReport.summary || '',
  };
}

async function analyzeWithCodexExec({ acceptedFiles, contexts = [], onProgress }) {
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
  const finalReportOutputFile = path.join(workspaceRoot, 'analysis-report.json');
  const totalTimeoutMs = Number(process.env.ANALYSIS_CODEX_TIMEOUT_MS || 28 * 60 * 1000);

  try {
    onProgress?.({
      stage: '로직 분석 중',
      progressPercent: 38,
      message: '실행 로직 파일을 추리고, 전체 코드 흐름을 한 번에 복원할 준비를 하고 있습니다.',
    });
    const reviewTargets = await collectWorkspaceReviewTargets({
      workspaceRoot,
      contexts,
    });

    onProgress?.({
      stage: '취약점 검증 중',
      progressPercent: 56,
      message: '단일 심층 프롬프트로 파일 이해, 교차 파일 흐름 복원, 취약점 탐색, 보고서 작성을 함께 수행하고 있습니다.',
    });

    await runCodexExecPass({
      workspaceRoot,
      outputFile: finalReportOutputFile,
      prompt: buildCodexUnifiedAnalysisPrompt({
        manifest,
        runtimeFileHints: reviewTargets,
      }),
      onProgress,
      passLabel: 'codex-unified-analysis',
      stage: '취약점 검증 중',
      progressPercent: 74,
      timeoutMs: totalTimeoutMs,
    });

    const finalReport = fs.existsSync(finalReportOutputFile)
      ? extractJsonObject(fs.readFileSync(finalReportOutputFile, 'utf8'))
      : null;
    if (finalReport && Array.isArray(finalReport.findings)) {
      return {
        ...finalReport,
        analysisMeta: {
          passType: 'single-pass-unified-analysis',
          hintedRuntimeFileCount: reviewTargets.length,
        },
      };
    }

    console.error('[analysis/codex] invalid-final-report-json', {
      finalReportOutputFile,
      exists: fs.existsSync(finalReportOutputFile),
      outputPreview: fs.existsSync(finalReportOutputFile)
        ? fs.readFileSync(finalReportOutputFile, 'utf8').slice(0, 1200)
        : '',
    });

    return null;
  } catch (error) {
    console.error('[analysis/codex] failed', {
      error: error instanceof Error ? error.message : String(error),
      workspaceRoot,
      finalReportOutputExists: fs.existsSync(finalReportOutputFile),
      finalPreview: fs.existsSync(finalReportOutputFile)
        ? fs.readFileSync(finalReportOutputFile, 'utf8').slice(0, 1200)
        : '',
    });
    return null;
  } finally {
    fs.rmSync(workspaceRoot, { recursive: true, force: true });
  }
}

function inferApplicationType(joinedText, sourceFiles) {
  const fileJoined = sourceFiles.join('\n');
  const signalText = [joinedText, fileJoined].filter(Boolean).join('\n');
  const bestServiceType = SERVICE_TYPE_RULES
    .map((rule) => ({
      ...rule,
      score: rule.patterns.reduce((total, pattern) => total + (pattern.test(signalText) ? 1 : 0), 0),
    }))
    .sort((left, right) => right.score - left.score)[0];

  if (bestServiceType && bestServiceType.score >= (bestServiceType.minScore || 1)) {
    return bestServiceType.type;
  }

  const bestLegacyType = APP_TYPE_RULES
    .map((rule) => ({
      ...rule,
      score: rule.patterns.reduce((total, pattern) => total + (pattern.test(joinedText) || pattern.test(fileJoined) ? 1 : 0), 0),
    }))
    .sort((left, right) => right.score - left.score)[0];

  if (bestLegacyType && bestLegacyType.score >= (bestLegacyType.minScore || 1)) {
    return LEGACY_APP_TYPE_TO_SERVICE_TYPE[bestLegacyType.type] || `${bestLegacyType.type} 서비스`;
  }

  if (/\b(next|react|vue|svelte|html|http|api)\b/i.test(signalText)) {
    return '웹 서비스';
  }

  if (/\b(android|ios|react-native|flutter)\b/i.test(signalText)) {
    return '모바일 애플리케이션';
  }

  if (/\b(menu|choice|stdin|scanf|fgets|malloc|free)\b/i.test(signalText)) {
    return '메뉴 기반 네이티브 프로그램';
  }

  return '소프트웨어 서비스';
}

function getServiceInferenceInputs(contexts = [], sourceFiles = []) {
  const filteredContexts = getRuntimeEvidenceContexts(contexts)
    .filter((context) => !isLikelySecurityToolingContext(context) && !isLikelyIllustrativeTextContext(context));
  const filteredJoinedText = filteredContexts
    .map((context) => context.fullText || context.text || '')
    .join('\n\n');
  const filteredSourceFiles = Array.from(new Set(
    filteredContexts
      .map((context) => context.embeddedSourceFile || context.sourceFile)
      .filter(Boolean),
  ));
  const safeFallbackSourceFiles = sourceFiles
    .map((file) => (typeof file === 'string' ? file : file.relativePath || file.originalName || ''))
    .filter(Boolean)
    .filter((value) => !/(^|\/)(analysis-report|upload-screening|analysis-job-runner|scanner|screening|rules?)(\.|\/|$)/i.test(value));

  return {
    joinedText: filteredJoinedText,
    sourceFiles: filteredSourceFiles.length ? filteredSourceFiles : safeFallbackSourceFiles,
  };
}

function sanitizeReportedApplicationType(value) {
  return String(value || '')
    .replace(/\s+추가 검토\s+리포트$/u, '')
    .replace(/\s+(취약점|보안 조언)\s+리포트$/u, '')
    .replace(/\s+분석\s+리포트$/u, '')
    .replace(/\s+리포트$/u, '')
    .trim();
}

function isUsableReportedApplicationType(value) {
  const normalized = sanitizeReportedApplicationType(value);
  if (!normalized) {
    return false;
  }

  if (/(보안 조언|분석 결과|구조 복원|파일 리뷰|불변식)/u.test(normalized)) {
    return false;
  }

  if (/(메뉴 입력을 받아 상태를 변경하는|API 요청을 처리하는|인증과 데이터 처리를 수행하는)/u.test(normalized)) {
    return false;
  }

  return normalized.length <= 80;
}

function resolveApplicationType({ parsedReport = null, contexts = [], sourceFiles = [] } = {}) {
  const parsedApplicationType = sanitizeReportedApplicationType(parsedReport?.applicationType || '');
  if (isUsableReportedApplicationType(parsedApplicationType)) {
    return parsedApplicationType;
  }

  const parsedTitleApplicationType = sanitizeReportedApplicationType(parsedReport?.title || '');
  if (isUsableReportedApplicationType(parsedTitleApplicationType)) {
    return parsedTitleApplicationType;
  }

  const serviceInferenceInputs = getServiceInferenceInputs(contexts, sourceFiles);
  return inferApplicationType(serviceInferenceInputs.joinedText, serviceInferenceInputs.sourceFiles);
}

function collectServiceBehaviorPoints(text) {
  const points = [];
  const pushPoint = (message) => {
    if (!points.includes(message)) {
      points.push(message);
    }
  };

  if (/\bmenu\b|\bchoice\b|\bstdin\b|\bscanf\b|\bfgets\b|\bread\s*\(\s*0\s*,/i.test(text)) {
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

function buildUserFacingServiceSentence(applicationType, text) {
  switch (applicationType) {
    case '코드 업로드와 GitHub 저장소 취약점 분석 웹 서비스':
      return '이 서비스는 사용자가 코드 파일이나 GitHub 저장소를 올려 보안 문제를 점검받고 결과를 확인할 수 있는 웹 서비스입니다.';
    case '영상 변환 웹 서비스':
      return '이 서비스는 사용자가 영상을 올리면 형식을 바꾸거나 변환 결과를 내려받을 수 있는 웹 서비스입니다.';
    case '모바일 쇼핑앱':
      return '이 서비스는 사용자가 상품을 보고 장바구니에 담고 주문이나 결제를 진행할 수 있는 모바일 애플리케이션입니다.';
    case '쇼핑 웹 서비스':
      return '이 서비스는 사용자가 상품을 둘러보고 주문이나 결제를 진행할 수 있는 웹 서비스입니다.';
    case '파일 업로드 웹 서비스':
      return '이 서비스는 사용자가 파일을 올리고 처리 결과를 확인하거나 내려받을 수 있는 웹 서비스입니다.';
    case '모바일 애플리케이션':
      return '이 서비스는 사용자가 여러 화면을 오가며 기능을 이용하고 데이터를 확인할 수 있는 모바일 애플리케이션입니다.';
    case '백엔드 API 서비스':
      return '이 서비스는 화면이나 외부 시스템에서 보낸 요청을 받아 데이터를 조회하거나 바꾸는 웹 서비스입니다.';
    case '메뉴 기반 네이티브 프로그램':
      return '이 프로그램은 사용자가 메뉴를 선택하면서 데이터를 만들고 수정하고 삭제할 수 있는 콘솔 프로그램입니다.';
    default: {
      const points = collectServiceBehaviorPoints(text);
      const joinedPoints = points.length
        ? points.join(' ')
        : '사용자가 입력을 보내고 결과를 확인할 수 있는 소프트웨어';
      return `이 서비스는 ${joinedPoints} 형태로 동작하는 프로그램입니다.`;
    }
  }
}

function buildDeveloperPerspectiveSentence(text) {
  const responsibilities = [];
  const pushResponsibility = (value) => {
    if (value && !responsibilities.includes(value)) {
      responsibilities.push(value);
    }
  };

  if (/\bapp\/api\b|\brouter\.(get|post|put|delete)\b|\bapp\.(get|post|put|delete)\b|\bNextResponse\b|\bfastapi\b|\bflask\b|\b@RestController\b/i.test(text)) {
    pushResponsibility('요청 수신');
  }
  if (/\blogin\b|\bsignup\b|\bsession\b|\bcookie\b|\btoken\b|\boauth\b|\bpassword\b/i.test(text)) {
    pushResponsibility('인증 처리');
  }
  if (/\bupload\b|\bdownload\b|\barchive\b|\bfile\b|\bpath\b/i.test(text)) {
    pushResponsibility('파일 처리');
  }
  if (/\bgithub\b/i.test(text)) {
    pushResponsibility('GitHub 연동');
  }
  if (/\bquery\b|\bexecute\b|\bdb\b|\bsqlite\b|\bpostgres\b|\bmongo\b/i.test(text)) {
    pushResponsibility('데이터 저장');
  }
  if (/\bjob\b|\bqueue\b|\bworker\b|\bbackground\b|\bcron\b/i.test(text)) {
    pushResponsibility('백그라운드 작업');
  }
  if (/\bmenu\b|\bchoice\b|\bstdin\b|\bscanf\b|\bfgets\b/i.test(text)) {
    pushResponsibility('메뉴 입력 처리');
  }

  const responsibilityText = responsibilities.slice(0, 4).join(', ') || '입력 처리와 상태 변경';

  if (/\bapp\/api\b|\brouter\.(get|post|put|delete)\b|\bapp\.(get|post|put|delete)\b|\bNextResponse\b|\bfastapi\b|\bflask\b|\b@RestController\b/i.test(text)) {
    return `또한 주요 엔드포인트와 서버 함수가 ${responsibilityText}를 담당하고, 관련 처리 함수가 입력 검증과 상태 변경 흐름을 나눠서 수행합니다.`;
  }

  if (/\bandroidmanifest\b|\bactivity\b|\bfragment\b|\bintent\b|\breact-native\b|\bflutter\b/i.test(text)) {
    return `또한 화면 전환 로직과 내부 처리 함수가 ${responsibilityText}를 담당하고, 저장 및 네트워크 호출 흐름을 함께 처리합니다.`;
  }

  if (/\bmenu\b|\bchoice\b|\bstdin\b|\bscanf\b|\bfgets\b/i.test(text)) {
    return `또한 메뉴 처리 함수와 입력 처리 함수가 ${responsibilityText}를 담당하고, 각 선택지에 따라 상태 변경 로직을 실행합니다.`;
  }

  return `또한 주요 처리 함수가 ${responsibilityText}를 담당하고, 입력 검증과 상태 변경 흐름을 내부 로직에서 처리합니다.`;
}

function buildApplicationNarrative(applicationType, sourceFiles, joinedText) {
  const signalText = [joinedText, sourceFiles.join('\n')].filter(Boolean).join('\n');
  const userFacingSentence = buildUserFacingServiceSentence(applicationType, signalText);
  const developerSentence = buildDeveloperPerspectiveSentence(signalText);

  return compactReportText(
    `${userFacingSentence} ${developerSentence}`,
    { maxLength: 320, maxSentences: 2 },
  );
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
    patchExample: '',
    abuse: '',
  };
}

function normalizeFindingTitle(value, fallbackTitle = '취약점') {
  const title = String(value || '').trim();
  if (!title) {
    return fallbackTitle;
  }

  const normalized = title.toLowerCase();
  if (/fsop/.test(normalized)) return 'FSOP';
  if (/heap/.test(normalized) && /corruption/.test(normalized)) return 'Heap Corruption';
  if (/buffer overflow|stack overflow/.test(normalized)) return 'Buffer Overflow';
  if (/format string/.test(normalized)) return 'Format String';
  if (/arbitrary write/.test(normalized)) return 'Arbitrary Write';
  if (/command injection/.test(normalized)) return 'Command Injection';
  if (/sql injection|sqli/.test(normalized)) return 'SQL Injection';
  if (/nosql injection/.test(normalized)) return 'NoSQL Injection';
  if (/\bxss\b|cross-site scripting/.test(normalized)) return 'XSS';
  if (/path traversal/.test(normalized)) return 'Path Traversal';
  if (/host header poisoning/.test(normalized)) return 'Host Header Poisoning';
  if (/insecure default secret/.test(normalized)) return 'Insecure Default Secret';
  if (/hardcoded secret/.test(normalized)) return 'Hardcoded Secret';
  if (/idor/.test(normalized)) return 'IDOR';
  if (/auth bypass|authorization bypass/.test(normalized)) return 'Auth Bypass';
  if (/ssrf/.test(normalized)) return 'SSRF';

  return compactReportText(title, { maxLength: 60, maxSentences: 1 });
}

function buildEducationalExplanationPrimer(title) {
  switch (normalizeFindingTitle(title || '')) {
    case 'FSOP':
      return 'FSOP는 File Stream Oriented Programming의 약자로, glibc의 `FILE` 구조체나 표준 스트림 객체(`stdin`, `stdout`, `stderr`)를 손상시켜 프로그램의 제어 흐름을 바꾸는 메모리 손상 계열 취약점이다. 겉보기에는 단순 출력이나 파일 입출력처럼 보이지만, 내부적으로는 함수 포인터, vtable, 버퍼 포인터, 플래그 비트 같은 민감한 상태가 함께 움직이기 때문에 스트림 객체가 오염되면 출력 함수 하나가 임의 코드 실행의 발판이 될 수 있다. 공격자는 보통 힙 손상이나 임의 쓰기 primitive를 먼저 만든 다음, 그 결과로 `FILE` 구조체의 특정 필드를 덮어써서 정상 입출력 경로를 악성 제어 흐름으로 바꾼다. 교육적으로는 "출력 함수가 위험한가?"가 아니라, "출력 함수가 참조하는 내부 객체가 이미 깨졌는가?"를 이해하는 것이 핵심이다.';
    case 'Heap Corruption':
      return 'Heap Corruption은 힙 메모리를 다루는 과정에서 청크 경계, 메타데이터, 포인터, 길이 값이 깨져 이후 할당과 해제 동작이 비정상적으로 바뀌는 취약점이다. 대표적으로 use-after-free, double free, heap overflow, invalid free가 여기에 포함되며, 공격자는 메모리 재사용 순서를 조작해 임의 쓰기나 가짜 객체 주입으로 이어가려 한다. 힙 취약점의 위험성은 "지금 당장 크래시가 나는가"보다, "다음 malloc/free에서 어떤 주소가 연결되는가"에 달려 있는 경우가 많다. 교육적으로는 힙을 단순한 저장 공간이 아니라, 할당기 메타데이터와 포인터 관계까지 포함한 상태 기계로 이해해야 한다.';
    case 'Buffer Overflow':
      return 'Buffer Overflow는 고정 길이 메모리 버퍼보다 긴 데이터를 기록하면서 인접 메모리까지 덮어쓰는 취약점이다. 이 문제는 스택 버퍼에서 발생하면 저장된 프레임 포인터나 리턴 주소가 손상될 수 있고, 힙 버퍼에서 발생하면 인접 객체나 할당기 메타데이터가 깨질 수 있다. 공격자는 이 성질을 이용해 프로그램 흐름을 바꾸거나, 보호된 상태 값을 덮어쓰거나, 이후 메모리 관리 동작을 자신에게 유리하게 왜곡하려 한다. 교육적으로는 "버퍼 크기"와 "실제 복사 길이"가 반드시 함께 관리되어야 하며, 입력을 받는 함수 하나만 보는 것이 아니라 그 길이 값이 어디서 왔고 누가 검증했는지를 끝까지 따라가야 한다.';
    case 'Format String':
      return 'Format String 취약점은 사용자 입력이 `printf`류 함수의 "출력할 데이터"가 아니라 "포맷 문자열 자체"로 해석될 때 발생한다. 공격자는 `%p`, `%x`, `%s`, `%n` 같은 포맷 지정자를 이용해 스택 값을 읽거나 메모리 주소를 누출하고, 심지어 특정 주소에 값을 쓰는 공격까지 시도할 수 있다. 이 취약점은 화면에 문자열을 한 번 출력하는 평범한 기능처럼 보여도, 실제로는 포맷 문자열 해석기가 공격자 입력을 명령처럼 처리하는 셈이기 때문에 매우 위험하다. 교육적으로는 사용자 입력을 `printf(user_input)`처럼 첫 번째 인자로 넘기는 습관 자체가 왜 위험한지 이해하는 것이 중요하다.';
    case 'Command Injection':
      return 'Command Injection은 공격자 입력이 운영체제 명령의 일부로 해석되어 원래 의도하지 않은 명령까지 실행되게 만드는 취약점이다. 예를 들어 파일명, 호스트명, 옵션 값처럼 보이는 입력이라도 쉘 해석 단계에서 `;`, `&&`, `|`, `$()` 같은 구문이 섞이면 프로그램 바깥의 명령 실행으로 이어질 수 있다. 이 취약점의 본질은 "입력이 명령의 데이터가 아니라 명령 구조의 일부가 되어 버리는 것"이며, 그래서 단순한 문자열 치환이나 블랙리스트로는 방어가 불완전한 경우가 많다. 교육적으로는 외부 명령 호출 자체보다, 입력이 쉘 문자열 결합을 거치는지, allowlist가 있는지, 인자를 배열로 분리했는지가 핵심이다.';
    case 'SQL Injection':
      return 'SQL Injection은 공격자 입력이 SQL 쿼리의 "값"으로만 쓰여야 하는데, 실제로는 쿼리의 구조 자체를 바꾸게 되는 취약점이다. 예를 들어 숫자 ID나 검색어처럼 보여야 하는 위치에 `OR 1=1`, `UNION SELECT`, 주석 구문 같은 SQL 조각이 들어가면, 애플리케이션이 의도한 WHERE 절이나 인증 조건이 완전히 바뀔 수 있다. 그 결과 로그인 우회, 임의 데이터 조회, 수정, 삭제, 권한 상승 같은 문제가 발생할 수 있다. 교육적으로는 문자열 결합 자체가 문제의 출발점이며, 입력 검증이 조금 있더라도 최종적으로 쿼리 구조를 파라미터 바인딩으로 고정하지 않으면 여전히 위험하다는 점을 이해해야 한다.';
    case 'NoSQL Injection':
      return 'NoSQL Injection은 MongoDB 같은 문서형 데이터베이스에서 공격자 입력이 단순 값이 아니라 쿼리 연산자나 필터 구조로 해석될 때 발생한다. 예를 들어 `{ "$ne": null }`, `{ "$gt": "" }` 같은 연산자가 그대로 들어가면 애플리케이션은 단순 문자열 비교를 생각했더라도 실제로는 조건 우회나 인증 우회가 생길 수 있다. SQL처럼 눈에 보이는 쿼리 문자열 결합이 없어도, 객체 구조 자체를 공격자가 조작할 수 있으면 같은 종류의 논리 오염이 일어난다는 점이 중요하다. 교육적으로는 "객체를 통째로 받아서 DB에 넘기는 패턴"이 왜 위험한지 이해해야 한다.';
    case 'XSS':
      return 'XSS는 Cross-Site Scripting의 약자로, 공격자가 넣은 스크립트나 악성 HTML이 다른 사용자의 브라우저에서 실행되도록 만드는 취약점이다. 대표적으로 `<script>` 태그, 이벤트 핸들러(`onerror`, `onclick`), `javascript:` URL, SVG 기반 스크립트 같은 입력이 HTML 문맥으로 해석되면 브라우저는 이를 단순 텍스트가 아니라 실행 가능한 코드로 받아들일 수 있다. 이 문제는 세션 탈취, 계정 도용, 화면 변조, 관리자 기능 대리 실행, 피싱 UI 삽입 같은 문제로 이어질 수 있으며, 저장형, 반사형, DOM 기반 XSS로 나뉘기도 한다. 교육적으로는 "사용자 입력을 HTML로 해석하는 순간"이 핵심 위험 지점이며, 텍스트로 렌더링할 것인지 HTML로 렌더링할 것인지를 먼저 구분해야 한다.';
    case 'Path Traversal':
      return 'Path Traversal은 공격자가 파일 경로나 파일명을 조작해 원래 허용된 디렉터리 바깥의 파일에 접근하려는 취약점이다. 대표적으로 `../` 시퀀스, 절대 경로, 심볼릭 링크 우회, 이중 URL 인코딩 같은 기법이 사용되며, 다운로드 기능이나 정적 파일 제공 기능에서 자주 문제를 일으킨다. 공격자는 이를 이용해 설정 파일, 비밀키, 시스템 파일, 다른 사용자의 업로드 파일까지 읽거나 덮어쓰려 할 수 있다. 교육적으로는 입력 문자열에 `..`가 있는지만 검사하는 것으로 끝나지 않고, 최종 경로를 정규화한 뒤 기준 디렉터리 안에 남아 있는지를 확인해야 안전하다.';
    case 'Host Header Poisoning':
      return 'Host Header Poisoning은 서버가 요청의 Host 또는 X-Forwarded-* 계열 헤더를 신뢰해서 절대 URL, 리다이렉트 URL, OAuth callback URL, 공유 링크 같은 보안 민감 값을 만들 때 발생하는 취약점이다. 공격자는 사용자가 보게 될 링크나 인증 흐름의 기준 도메인을 오염시켜 open redirect, OAuth 흐름 오염, 링크 위조, 캐시 오염 같은 문제를 노릴 수 있다. 특히 인증 시스템이나 비밀번호 재설정 링크, 외부 연동 callback URL처럼 "이 도메인이 정말 우리 서비스 도메인인가"가 중요한 기능에서는 피해가 더 커진다. 교육적으로는 "절대 URL은 요청에서 배우는 값이 아니라 서버가 이미 알고 있어야 하는 값"이라는 원칙이 중요하다.';
    case 'Insecure Default Secret':
      return 'Insecure Default Secret은 운영 환경에서 반드시 바뀌어야 하는 비밀값이 안전하지 않은 기본값으로 남아 있는 취약점이다. 예를 들어 세션 서명 키, JWT 비밀키, 관리자 초기 비밀번호가 `change-me`, `secret`, `default-key` 같은 예측 가능한 값으로 유지되면 공격자는 코드를 읽거나 문서를 추측하는 것만으로 위조 토큰이나 세션을 만들 수 있다. 교육적으로는 "환경 변수를 쓴다"는 사실만으로 안전해지는 것이 아니라, 값이 없을 때 안전하지 않은 fallback을 허용하지 않는 것이 핵심이다.';
    case 'Hardcoded Secret':
      return 'Hardcoded Secret은 토큰, 비밀번호, API 키, 세션 키 같은 민감한 비밀값이 소스코드나 빌드 산출물에 직접 박혀 있는 취약점이다. 이런 값은 저장소 유출, 로그 노출, 프론트엔드 번들 분석, 디버그 정보만으로도 바로 악용될 수 있으며, 공개 저장소에 한 번 올라간 비밀은 삭제하더라도 이미 복제되었을 가능성이 크다. 교육적으로는 비밀은 코드가 아니라 별도 비밀 관리 체계에 있어야 하며, 이미 노출된 값은 삭제가 아니라 회전까지 해야 한다.';
    case 'IDOR':
      return 'IDOR는 Insecure Direct Object Reference의 약자로, 사용자가 직접 지정한 식별자만 바꿔서 다른 사람의 데이터나 자원에 접근할 수 있게 되는 취약점이다. 예를 들어 `reportId=5`를 `reportId=6`으로 바꾸는 것만으로 다른 사용자의 리포트를 볼 수 있다면 전형적인 IDOR다. 많은 개발자가 "UUID를 쓰면 안전하다"고 오해하지만, 식별자가 길고 추측하기 어려워도 서버가 소유권을 다시 확인하지 않으면 본질은 그대로다. 교육적으로는 "ID가 난수냐 아니냐"보다, 서버가 매 요청마다 현재 사용자와 대상 자원의 소유권 관계를 다시 확인하는지가 더 중요하다.';
    case 'Auth Bypass':
      return 'Auth Bypass는 인증 또는 권한 검증이 있어야 하는 기능이 잘못된 상태 판단, 세션 처리, 예외 흐름, 순서 오류 때문에 우회되는 취약점이다. 사용자는 정상적으로는 볼 수 없거나 실행할 수 없는 기능을 인증 없이 사용하거나 더 높은 권한으로 접근하게 될 수 있다. 이 문제는 종종 "로그인은 되어 있다"는 사실만 확인하고 끝낼 때 발생하며, 세션 주체와 실제 자원 소유자, 현재 단계의 사용자 의도, 역할 검증이 서로 분리되어 있을 때 특히 잘 생긴다. 교육적으로는 로그인 여부만 보는 것이 아니라, "이 요청의 주체가 정말 이 자원과 동작을 수행할 권한이 있는가"를 단계별로 검증해야 한다.';
    case 'SSRF':
      return 'SSRF는 Server-Side Request Forgery의 약자로, 서버가 공격자가 지정한 URL이나 호스트로 대신 요청을 보내게 되는 취약점이다. 그 결과 공격자는 내부망, 메타데이터 서비스, 관리자 전용 API, 클라우드 인스턴스 정보 같은 외부에서 직접 접근할 수 없는 자원에 우회 접근을 시도할 수 있다. 이 취약점은 "서버가 외부 URL을 받아서 가져와 주는 기능"이 편리하다는 이유로 자주 도입되며, 목적지 검증이 약하면 서버가 내부망 스캐너나 프록시로 악용될 수 있다. 교육적으로는 목적지 allowlist, 프로토콜 제한, DNS 재해석 방지까지 함께 고려해야 한다.';
    case 'CSRF':
      return 'CSRF는 Cross-Site Request Forgery의 약자로, 사용자가 의도하지 않았는데 이미 로그인된 브라우저의 권한을 이용해 다른 사이트의 요청이 실행되도록 만드는 취약점이다. 공격자는 피해자가 로그인된 상태라는 점을 악용해 설정 변경, 계정 연결, 결제, 글 작성, 비밀번호 변경 같은 상태 변경 요청을 대신 수행하게 만들 수 있다. 많은 경우 사용자는 클릭 한 번도 하지 않았는데 이미지 로드, 자동 제출 폼, 숨겨진 요청만으로 상태 변경이 일어날 수 있다. 교육적으로는 단순히 POST만 사용한다고 막히지 않으며, CSRF 토큰, SameSite 쿠키, 재인증, 사용자 의도 확인이 함께 필요하다.';
    default:
      return '';
  }
}

function buildEducationalExplanationText(title, explanation) {
  const primer = buildEducationalExplanationPrimer(title);
  const specific = String(explanation || '').trim();

  if (!primer) {
    return specific || '설명이 없습니다.';
  }

  if (!specific) {
    return primer;
  }

  if (specific.length >= 240) {
    return specific;
  }

  return [
    primer,
    `이번 코드 기준으로 보면 ${specific}`,
  ].join('\n\n');
}

function buildFindingCodeSection(location, codeLocation) {
  const normalizedLocation = String(location || '위치 정보가 없습니다.').trim();
  const normalizedCode = normalizeMultilineSnippet(codeLocation || location || '핵심 코드 정보가 없습니다.');
  const looksLikeAssembly = looksLikeAssemblySnippet(normalizedCode);
  const pseudoCode = looksLikeAssembly ? normalizeMultilineSnippet(toPseudoCFromAssembly(normalizedCode)) : '';

  return [
    '파일 경로:',
    normalizedLocation,
    '',
    '핵심 코드:',
    normalizedCode,
    ...(pseudoCode ? ['', '보조 해석:', pseudoCode] : []),
  ].join('\n');
}

function buildPatchExampleText(title, codeLocation, remediation = '') {
  const findingTitle = normalizeFindingTitle(title, '보안 항목');
  const currentCode = String(codeLocation || '// 관련 코드가 제공되지 않았습니다.').trim();
  let patchedCode = `// ${findingTitle}를 줄이기 위해 입력 검증과 안전한 처리 흐름을 추가합니다.\n// ${String(remediation || '관련 로직에 검증, 권한 확인, 안전한 API 사용을 적용합니다.').trim()}`;

  switch (findingTitle) {
    case 'SQL Injection':
      patchedCode = `const id = Number(req.query.id);\nif (!Number.isInteger(id)) {\n  throw new Error('invalid id');\n}\nreturn db.query('SELECT * FROM users WHERE id = ?', [id]);`;
      break;
    case 'NoSQL Injection':
      patchedCode = `const username = String(req.body.username || '');\nconst password = String(req.body.password || '');\nreturn users.findOne({ username, password });`;
      break;
    case 'XSS':
      patchedCode = `const safeHtml = sanitizeHtml(userContent, { allowedTags: ['b', 'i', 'p'] });\nreturn <div>{safeHtml}</div>; // 가능하면 텍스트 렌더링을 우선합니다.`;
      break;
    case 'Path Traversal':
      patchedCode = `const baseDir = path.resolve(UPLOAD_ROOT_DIR);\nconst resolvedPath = path.resolve(baseDir, requestedPath);\nif (!resolvedPath.startsWith(baseDir)) {\n  throw new Error('invalid path');\n}\nreturn fs.readFileSync(resolvedPath);`;
      break;
    case 'Command Injection':
      patchedCode = `const target = allowlistedTargets[req.body.target];\nif (!target) {\n  throw new Error('invalid target');\n}\nreturn execFile('/usr/bin/tool', ['--target', target]);`;
      break;
    case 'Host Header Poisoning':
      patchedCode = `function getTrustedOrigin() {\n  const configuredOrigin = String(process.env.APP_BASE_URL || '').trim();\n  if (!configuredOrigin) {\n    throw new Error('APP_BASE_URL is required');\n  }\n  return configuredOrigin;\n}\n\nexport function getRequestAppOrigin() {\n  return getTrustedOrigin();\n}\n\nexport function getGitHubConfig() {\n  const redirectUri = new URL('/auth/github/callback', getTrustedOrigin()).toString();\n  return {\n    redirectUri,\n  };\n}\n\n// GitHub OAuth route/callback도 request 기반 origin이 아니라 고정된 APP_BASE_URL만 사용해야 합니다.`;
      break;
    case 'Insecure Default Secret':
    case 'Hardcoded Secret':
      patchedCode = `const secret = process.env.SESSION_SECRET;\nif (!secret) {\n  throw new Error('SESSION_SECRET is required');\n}\nreturn secret;`;
      break;
    case 'Buffer Overflow':
      patchedCode = `if (input.length >= sizeof(buffer)) {\n  return error;\n}\nsnprintf(buffer, sizeof(buffer), '%s', input);`;
      break;
    case 'Format String':
      patchedCode = `printf('%s', user_input);`;
      break;
    case 'FSOP':
    case 'Heap Corruption':
    case 'Arbitrary Write':
      patchedCode = `// 객체 생명주기를 분리하고 해제 후 재사용을 막습니다.\nif (index < 0 || index >= items.length) {\n  return error;\n}\nif (!items[index]) {\n  return error;\n}\n// 해제 후 포인터를 즉시 NULL 처리하고 중복 해제를 막습니다.`;
      break;
    default:
      break;
  }

  return [
    '현재 코드:',
    currentCode,
    '',
    '패치 예시 코드:',
    patchedCode,
  ].join('\n');
}

function buildStructuredFinding(finding) {
  const locationText = Array.isArray(finding.locations)
    ? finding.locations.slice(0, 5).join(', ')
    : finding.location;
  const formattedLocation = formatFindingLocation(locationText || finding.location, finding.codeLocation);
  const rawExploitability = String(finding?.exploitability || '').trim();
  const exploitability = rawExploitability ? normalizeExploitability(rawExploitability) : '';
  const normalizedTitle = normalizeFindingTitle(finding?.title || '취약점');
  const patchExample = String(finding?.patchExample || '').trim() || buildPatchExampleText(normalizedTitle, finding.codeLocation, finding.remediation);
  const codeSection = buildFindingCodeSection(formattedLocation || finding.location, finding.codeLocation);
  const educationalExplanation = buildEducationalExplanationText(normalizedTitle, finding.explanation);

  return {
    ...finding,
    title: normalizedTitle,
    exploitability,
    location: formattedLocation,
    codeLocation: finding.codeLocation || formattedLocation || finding.location,
    patchExample,
    poc: String(finding?.poc || '').trim(),
    explanation: educationalExplanation,
    description: [
      `[${normalizedTitle || '취약점'}]`,
      `1) 취약점 설명\n${educationalExplanation || '설명이 없습니다.'}`,
      `2) 취약점 원인 분석\n${finding.detail || '원인 분석 정보가 없습니다.'}`,
      `3) 파일 경로 및 핵심 코드\n${codeSection}`,
      `4) 취약점 해결 방안\n${finding.remediation || '수정 방안 정보가 없습니다.'}`,
      `5) 패치 코드 예시\n${patchExample}`,
      ...(exploitability ? [`- 성립 여부: ${exploitability}`] : []),
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

function inferSourceLabel(ruleId, text) {
  const combinedText = String(text || '');

  if (ruleId === 'host-header-poisoning') {
    if (/\bx-forwarded-host\b|\bx-forwarded-proto\b/i.test(combinedText)) {
      return 'Host/X-Forwarded-* 요청 헤더와 request URL origin';
    }
    if (/\brequest(?:\?)?\.(?:nextUrl(?:\?)?\.origin|url)\b/i.test(combinedText)) {
      return 'request.nextUrl.origin 또는 request.url 같은 요청 origin 값';
    }
  }

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

  return '직접 확인된 외부 입력 경로를 특정하지 못한 값';
}

function inferSinkLabel(ruleId, text) {
  const combinedText = String(text || '');

  switch (ruleId) {
    case 'host-header-poisoning':
      if (/\bgetGitHubConfig\b/i.test(combinedText) && /\bredirectUri\b/i.test(combinedText)) {
        return 'getGitHubConfig()가 만드는 GitHub OAuth redirectUri';
      }
      if (/\bNextResponse\.redirect\b|\bredirect\s*\(/i.test(combinedText)) {
        return '절대 redirect URL 또는 OAuth callback URL 생성 지점';
      }
      return '절대 URL, redirect URL, OAuth callback URL 생성 지점';
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

function inferValidationAssessment(ruleId, text) {
  const combinedText = String(text || '');

  if (ruleId === 'host-header-poisoning') {
    if (hasUntrustedRequestOriginRedirectFlow(combinedText)) {
      return 'TRUST_PROXY_HEADERS 관련 게이트가 일부 보이더라도 request.nextUrl.origin 또는 request.url 기반 origin이 먼저 선택되어, redirect 기준 origin이 신뢰된 서버 설정으로 고정되지 않는다';
    }

    if (hasHostHeaderRedirectFlow(combinedText) && !hasExplicitProxyTrustGate(combinedText)) {
      return 'Host/X-Forwarded-* 값을 신뢰 가능한 프록시가 정제했는지 확인하는 명시적 게이트가 없다';
    }

    return '일부 프록시 신뢰 로직은 보이지만, redirect 기준 origin이 고정 설정값으로 강제되지 않아 우회 가능성을 추가 검증해야 한다';
  }

  if (/\b(sql_filter|sanitize|sanitiz|escape|escaped|validator|validate|allowlist|whitelist|blacklist|regex|session|csrf|auth|permission|role|hash)\b/i.test(combinedText)) {
    return '일부 필터나 검증 흔적은 보이지만, 그 검사가 실제로 구조를 안전하게 고정하는지는 추가 검증이 필요하다';
  }

  return '명시적인 입력 검증, allowlist, 권한 검사, 구조 고정 로직이 뚜렷하게 보이지 않는다';
}

function buildExpandedExplanation(rule, contexts) {
  const combinedText = contexts.map((context) => context.fullText || context.text).join('\n\n');
  const sourceLabel = inferSourceLabel(rule.id, combinedText);
  const sinkLabel = inferSinkLabel(rule.id, combinedText);
  const validationText = inferValidationAssessment(rule.id, combinedText);

  if (rule.id === 'host-header-poisoning') {
    return [
      buildEducationalExplanationPrimer(rule.name),
      `이번 코드에서는 ${sourceLabel}가 getRequestAppOrigin()으로 들어가고, getGitHubConfig()가 그 값을 GitHub OAuth redirectUri로 사용한다.`,
      `즉, 브라우저가 보는 외부 도메인 정보와 OAuth callback 기준 도메인이 서버 고정 설정이 아니라 요청 기반 값에 의해 영향을 받을 수 있으며, 현재 검증 상태는 ${validationText}.`,
    ].join('\n\n');
  }

  return [
    buildEducationalExplanationPrimer(rule.name),
    `이번 코드에서는 source가 ${sourceLabel}, sink가 ${sinkLabel}이며, 검증 상태는 ${validationText}.`,
  ].filter(Boolean).join('\n\n');
}

function buildExpandedAbuse(rule, contexts) {
  const combinedText = contexts.map((context) => context.fullText || context.text).join('\n\n');
  const sourceLabel = inferSourceLabel(rule.id, combinedText);
  const sinkLabel = inferSinkLabel(rule.id, combinedText);
  const validationText = inferValidationAssessment(rule.id, combinedText);

  if (rule.id === 'host-header-poisoning') {
    return [
      `1) 공격자는 ${sourceLabel}를 조작해 서버가 인식하는 외부 origin을 바꾸려 한다.`,
      '2) lib/server/config.js의 getHeaderOrigin()과 getRequestAppOrigin()이 이 값을 읽어 애플리케이션 기준 origin을 계산한다.',
      '3) getGitHubConfig()는 계산된 origin을 이용해 `/auth/github/callback` 절대 URL을 만들고, app/auth/github/route.js 및 app/auth/github/callback/route.js는 이 redirectUri를 GitHub OAuth 흐름에서 사용한다.',
      `4) 즉, 값이 ${validationText} 상태로 ${sinkLabel}까지 이어지며, 공격자가 인증 흐름의 기준 도메인에 개입할 여지가 생긴다.`,
      `5) 그 결과 ${rule.detail}`,
      '6) 교육적으로는 이 문제를 "헤더 하나를 신뢰했다"에서 끝내지 말고, 요청에서 들어온 origin 정보가 어디서 저장되고, 어떤 절대 URL 생성 함수로 전달되며, 그 URL이 다시 어떤 인증 또는 redirect 흐름에서 소비되는지까지 함께 봐야 한다.',
    ].join('\n');
  }

  return [
      `1) 공격자는 ${sourceLabel}에 조작된 값을 넣거나, 정상 입력처럼 보이는 값을 악의적인 형태로 만든다.`,
      `2) 애플리케이션은 이 값을 ${validationText} 상태로 받아들인 뒤, 최종적으로 ${sinkLabel}까지 전달한다.`,
      `3) 이 과정에서 입력이 단순 데이터가 아니라 쿼리 구조, HTML, 경로, 명령, 포맷 문자열, 메모리 상태 같은 보안 민감 요소에 영향을 주게 된다.`,
      `4) 그 결과 ${rule.detail}`,
      '5) 교육적으로는 취약점이 성립하는 지점을 한 줄에서 찾는 습관보다, 입력이 어떤 전처리를 거쳤는지, 어떤 검증이 빠졌는지, 그리고 마지막 sink가 왜 위험한지를 단계적으로 따라가는 습관이 더 중요하다.',
  ].join('\n');
}

function buildExpandedRemediation(rule) {
  if (rule.id === 'host-header-poisoning') {
    return '절대 URL과 OAuth callback URL은 요청 헤더나 `request.nextUrl.origin`에서 만들지 말고, `APP_BASE_URL` 같은 서버 고정 설정에서만 생성해야 한다. 프록시 헤더는 신뢰 가능한 리버스 프록시가 정제하는 환경에서만 명시적으로 허용하고, `getRequestAppOrigin()` 같은 함수가 request 기반 origin을 우선 선택하지 않도록 흐름을 고정하는 편이 안전하다. 실무적으로는 "origin 계산 함수" 하나에서 모든 기준 도메인을 통제하고, OAuth·공유 링크·비밀번호 재설정 링크가 모두 그 함수를 통해서만 만들어지게 제한하는 것이 좋다.';
  }

  return [
    rule.remediation,
    '실무적으로는 취약점을 만든 입력 지점만 고치는 것으로 끝내지 말고, 같은 데이터가 통과하는 다른 경로까지 함께 점검해야 한다. 또한 검증 로직, 권한 확인, 안전한 API 사용, 로그/모니터링 기준을 같이 정리해야 재발을 줄일 수 있다.',
    '교육적으로는 "이 한 줄을 이렇게 바꾸면 끝"이라는 접근보다, 왜 기존 코드가 위험했고 왜 수정 후에는 위험이 줄어드는지까지 함께 이해해야 한다. 즉 입력을 데이터로만 다루도록 구조를 바꾸는지, 권한 확인 시점을 앞당기는지, 신뢰할 수 없는 값을 아예 고정 설정으로 대체하는지까지 설명 가능한 수정이어야 한다.',
  ].filter(Boolean).join('\n\n');
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

function extractClientControlledVariableNames(text) {
  const aliases = new Set();
  const patterns = [
    /\b(?:const|let|var)\s+([a-zA-Z_]\w*)\s*=\s*searchParams\.get\s*\(/g,
    /\b(?:const|let|var)\s+([a-zA-Z_]\w*)\s*=\s*params\.[a-zA-Z_]\w*/g,
    /\b(?:const|let|var)\s+([a-zA-Z_]\w*)\s*=\s*params\[['"][^'"]+['"]\]/g,
    /\b(?:const|let|var)\s+([a-zA-Z_]\w*)\s*=\s*formData\.get\s*\(/g,
    /\b(?:const|let|var)\s+([a-zA-Z_]\w*)\s*=\s*new URLSearchParams\s*\(/g,
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

function hasRequestControlledHtmlSinkFlow(text) {
  const combinedText = String(text || '');

  if (!/\bdangerouslySetInnerHTML\b|innerHTML\s*=|\bv-html\b|document\.write\s*\(|render_template_string\s*\(/i.test(combinedText)) {
    return false;
  }

  if (
    /\bdangerouslySetInnerHTML\s*=\s*\{\{[\s\S]{0,160}__html\s*:\s*[^}\n]*(req|request)\.(body|query|params)\b/i.test(combinedText)
    || /\bdangerouslySetInnerHTML\s*=\s*\{\{[\s\S]{0,160}__html\s*:\s*[^}\n]*(searchParams\.get\s*\(|params\.[a-zA-Z_]\w*|params\[['"][^'"]+['"]\]|formData\.get\s*\()/i.test(combinedText)
    || /\binnerHTML\s*=\s*[^;\n]*(req|request)\.(body|query|params)\b/i.test(combinedText)
    || /\binnerHTML\s*=\s*[^;\n]*(searchParams\.get\s*\(|params\.[a-zA-Z_]\w*|params\[['"][^'"]+['"]\]|formData\.get\s*\()/i.test(combinedText)
    || /\bdocument\.write\s*\([^)]*(req|request)\.(body|query|params)\b/i.test(combinedText)
    || /\bdocument\.write\s*\([^)]*(searchParams\.get\s*\(|params\.[a-zA-Z_]\w*|params\[['"][^'"]+['"]\]|formData\.get\s*\()/i.test(combinedText)
    || /\brender_template_string\s*\([^)]*(request\.(args|form|values)|req\.(body|query|params))\b/i.test(combinedText)
  ) {
    return true;
  }

  const controlledNames = Array.from(new Set([
    ...extractRequestControlledVariableNames(combinedText),
    ...extractJsonBodyAliasNames(combinedText),
    ...extractClientControlledVariableNames(combinedText),
  ]));

  return controlledNames.some((name) => (
    new RegExp(`\\bdangerouslySetInnerHTML\\s*=\\s*\\{\\{[\\s\\S]{0,160}__html\\s*:\\s*[^}\\n]*\\b${name}(?:\\.[a-zA-Z_]\\w*)?\\b`, 'i').test(combinedText)
    || new RegExp(`\\binnerHTML\\s*=\\s*[^;\\n]*\\b${name}(?:\\.[a-zA-Z_]\\w*)?\\b`, 'i').test(combinedText)
    || new RegExp(`\\bdocument\\.write\\s*\\([^)]*\\b${name}(?:\\.[a-zA-Z_]\\w*)?\\b`, 'i').test(combinedText)
    || new RegExp(`\\brender_template_string\\s*\\([^)]*\\b${name}(?:\\.[a-zA-Z_]\\w*)?\\b`, 'i').test(combinedText)
  ));
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

function hasUntrustedRequestOriginRedirectFlow(text) {
  const combinedText = String(text || '');
  const derivesRequestOrigin = (
    /\brequestOrigin\s*=\s*normalizeOrigin\s*\(\s*request(?:\?)?\.(?:nextUrl(?:\?)?\.origin|url)\b/i.test(combinedText)
    || /\brequestOrigin\s*=\s*request(?:\?)?\.(?:nextUrl(?:\?)?\.origin|url)\s*(\|\||\?\?)/i.test(combinedText)
    || /\brequestOrigin\s*=\s*request(?:\?)?\.(?:nextUrl(?:\?)?\.origin|url)\b/i.test(combinedText)
    || /\bnormalizeOrigin\s*\(\s*request(?:\?)?\.(?:nextUrl(?:\?)?\.origin|url)\b/i.test(combinedText)
    || /\bnew URL\s*\(\s*request\.url\s*\)\.origin\b/i.test(combinedText)
  );
  const returnsRequestOrigin = (
    /\bif\s*\(\s*requestOrigin\s*&&\s*!isLoopbackOrigin\s*\(\s*requestOrigin\s*\)\s*\)\s*{\s*return\s+requestOrigin\s*;?\s*}/i.test(combinedText)
    || /\breturn\s+requestOrigin\b/i.test(combinedText)
  );
  const usesOriginForOauthOrRedirect = (
    /\bredirectUri\b/i.test(combinedText)
    || /\bauth\/github\/callback\b/i.test(combinedText)
    || /\bredirect\s*\(/i.test(combinedText)
    || /\bNextResponse\.redirect\b/i.test(combinedText)
    || /\bshareUrl\b/i.test(combinedText)
  );

  return derivesRequestOrigin && returnsRequestOrigin && usesOriginForOauthOrRedirect;
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
          hasRequestControlledHtmlSinkFlow(combinedText)
          || (/\|\s*safe\b/i.test(combinedText) && /\b(request|req|params|query|form|searchParams)\b/i.test(combinedText))
          || (/\bMarkup\s*\(/i.test(combinedText) && /\b(request|req|params|query|form|searchParams)\b/i.test(combinedText))
          || (/return\s+f?["'][\s\S]{0,160}<script[\s\S]{0,160}["']/i.test(combinedText) && /\b(request|req|params|query|form|searchParams)\b/i.test(combinedText))
          || hasDirectResponseReflection(combinedText)
        )
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
      return (
        (hasHostHeaderRedirectFlow(combinedText) && !hasExplicitProxyTrustGate(combinedText))
        || hasUntrustedRequestOriginRedirectFlow(combinedText)
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
      const candidateContexts = getRuleCandidateContexts(contexts, rule);
      const matchedGroup = groupContextsBySourceFile(candidateContexts).find((group) => verifyRuleEvidence(rule, group));
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
      location: '프로젝트 전반',
      codeLocation: '/* 요청을 받는 컨트롤러, 라우터, 입력 파서, 버퍼 복사 지점 전체를 우선 점검해야 한다. */',
      explanation: '입력 검증 부족은 외부 입력의 타입, 길이, 형식을 충분히 제한하지 않아 이후 다른 취약점으로 이어지기 쉬운 상태를 뜻한다. 교육 관점에서는 많은 취약점이 사실상 이 단계의 실패에서 시작되므로, 어떤 값이 어디까지 들어와도 되는지 먼저 명확히 정의하는 습관이 중요하다. 예를 들어 문자열 길이, 정수 범위, 허용 문자 집합, 필수 필드 여부가 코드마다 제각각이면 이후 다른 방어 로직이 있어도 우회가 쉬워질 수 있다.',
      detail: '검증이 약하면 악성 문자열이나 비정상 길이 데이터가 내부 로직으로 그대로 전달되어 SQL Injection, XSS, 메모리 손상 같은 문제의 발판이 될 수 있다. 예를 들어 웹 서비스에서는 요청 파라미터가 그대로 쿼리나 HTML 렌더링으로 이어질 수 있고, 네이티브 서비스에서는 길이 검증이 빠진 입력이 버퍼 처리까지 이어질 수 있다. 이번 항목은 특정 취약점 확정이 아니라, 서비스 전반에서 가장 먼저 보완해야 하는 공통 위험 지점으로 이해하는 편이 맞다.',
      remediation: '요청 단위 검증 레이어를 두고 타입, 길이, 허용 문자, 예외 처리 기준을 일관되게 강제해야 한다. 실무에서는 컨트롤러마다 따로 막기보다 공통 validator, schema, DTO, parser 단계에서 먼저 거르는 편이 유지보수와 재발 방지에 유리하다. 교육용으로는 "검증 전 입력", "검증 후 입력", "검증 실패 응답"을 나눠 비교하면서 어느 단계에서 데이터가 걸러지는지 확인해보는 것이 좋다.',
    },
    {
      id: 'baseline-hardening-1',
      title: '설정 분리',
      severity: 'low',
      location: '프로젝트 전반',
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
      ? '두 차례 취약점 탐색에서 확정 취약점을 입증하지 못해 보안적으로 보완하면 좋은 점을 정리했습니다.'
      : '발견된 취약점이 없습니다.';
  }

  const names = findings.slice(0, 3).map((finding) => finding.title).join(', ');
  return `${resultMode === 'recommendation' ? '보안 조언' : '발견된 취약점'} : ${names}${findings.length > 3 ? ` 외 ${findings.length - 3}개` : ''}`;
}

function sanitizeReportedTitle(value) {
  return String(value || '')
    .replace(/\s+추가 검토\s+리포트$/u, '')
    .replace(/\s+(취약점|보안 조언)\s+리포트$/u, '')
    .replace(/\s+분석\s+리포트$/u, '')
    .replace(/\s+리포트$/u, '')
    .trim();
}

function isUsableReportedTitle(value) {
  const normalized = sanitizeReportedTitle(value);
  if (!normalized) {
    return false;
  }

  if (/(메뉴 기반 네이티브 프로그램|상태를 변경하는 서비스|API 요청을 처리하는 서비스|메뉴 입력을 받아 상태를 변경하는|API 요청을 처리하는|인증과 데이터 처리를 수행하는)/u.test(normalized)) {
    return false;
  }

  if (/(취약점 분석 웹 서비스|구조 복원|파일 리뷰|불변식|분석 결과)/u.test(normalized)) {
    return false;
  }

  return normalized.length <= 80;
}

function buildReportTitle(applicationType, findings, resultMode, preferredTitle = '') {
  const normalizedPreferredTitle = sanitizeReportedTitle(preferredTitle);
  if (isUsableReportedTitle(normalizedPreferredTitle)) {
    return `${normalizedPreferredTitle} 리포트`;
  }

  return `${applicationType} 리포트`;
}

function buildReviewPendingTitle(applicationType, preferredTitle = '') {
  const normalizedPreferredTitle = sanitizeReportedTitle(preferredTitle);
  if (isUsableReportedTitle(normalizedPreferredTitle)) {
    return `${normalizedPreferredTitle} 추가 검토 리포트`;
  }

  return `${applicationType} 추가 검토 리포트`;
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
    title: normalizeFindingTitle(String(finding?.title || `Finding ${index + 1}`).trim(), `Finding ${index + 1}`),
    confirmed: typeof finding?.confirmed === 'boolean' ? finding.confirmed : true,
    exploitability: finding?.exploitability ? normalizeExploitability(finding.exploitability) : '',
    severity: normalizeSeverity(String(finding?.severity || 'low').toLowerCase()),
    location: String(finding?.location || '관련 코드 구간').trim(),
    codeLocation: String(finding?.codeLocation || finding?.location || '관련 코드 구간').trim(),
    explanation: compactReportText(String(finding?.explanation || '취약점 설명이 제공되지 않았습니다.').trim(), { maxLength: 900, maxSentences: 6 }),
    detail: compactScenarioText(String(finding?.detail || '원인 분석이 제공되지 않았습니다.').trim(), { maxLength: 1200, maxSentences: 8 }),
    remediation: compactReportText(String(finding?.remediation || '대응 방안이 제공되지 않았습니다.').trim(), { maxLength: 900, maxSentences: 6 }),
    patchExample: compactScenarioText(String(finding?.patchExample || '').trim(), { maxLength: 1200, maxSentences: 12 }),
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
    explanation: compactReportText(String(finding?.explanation || '보안 조언 설명이 제공되지 않았습니다.').trim(), { maxLength: 900, maxSentences: 6 }),
    detail: compactScenarioText(String(finding?.detail || '현재 위험과 원인 분석이 제공되지 않았습니다.').trim(), { maxLength: 1200, maxSentences: 8 }),
    remediation: compactReportText(String(finding?.remediation || '구체적인 보완 방안이 제공되지 않았습니다.').trim(), { maxLength: 900, maxSentences: 6 }),
    patchExample: compactScenarioText(String(finding?.patchExample || '').trim(), { maxLength: 1200, maxSentences: 12 }),
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
  const serviceInferenceInputs = getServiceInferenceInputs(contexts, sourceFiles);
  const joinedText = serviceInferenceInputs.joinedText;
  const inferredApplicationType = inferApplicationType(joinedText, serviceInferenceInputs.sourceFiles);
  const applicationType = resolveApplicationType({ parsedReport, contexts, sourceFiles }) || inferredApplicationType;
  const summary = compactReportText(
    selectNormalizedSummary({
      parsedSummary: parsedReport.summary,
      resultMode,
      findings: finalFindings,
    }),
    { maxLength: 140, maxSentences: 1 },
  );

  return {
    title: buildReportTitle(applicationType, finalFindings, resultMode, parsedReport?.title || ''),
    applicationType,
    summary,
    applicationReport: normalizeApplicationReport({
      applicationType,
      applicationReport: String(parsedReport.applicationReport || '').trim(),
      sourceFiles: serviceInferenceInputs.sourceFiles,
      joinedText,
    }),
    resultMode,
    overallSeverity: calculateOverallSeverity(finalFindings),
    findingsCount: finalFindings.length,
    findings: finalFindings,
    analysisMeta: parsedReport.analysisMeta || null,
    sourceFiles,
  };
}

export function buildRuleBasedAnalysisReport({ contexts, sourceFiles, includeRecommendations = true }) {
  const classifiedContexts = normalizeAnalysisContexts(contexts);
  const runtimeContexts = getRuntimeEvidenceContexts(classifiedContexts);
  const analysisContexts = runtimeContexts.length ? runtimeContexts : classifiedContexts;
  const sourceFileNames = sourceFiles.map((file) => file.originalName);
  const primaryContextNames = analysisContexts.map((context) => context.sourceFile);
  const serviceInferenceInputs = getServiceInferenceInputs(analysisContexts, sourceFiles);
  const joinedText = serviceInferenceInputs.joinedText || analysisContexts.map((context) => context.fullText || context.text).join('\n\n');
  const applicationType = inferApplicationType(joinedText, serviceInferenceInputs.sourceFiles.length ? serviceInferenceInputs.sourceFiles : sourceFileNames);
  const vulnerabilityFindings = collectVulnerabilityFindings(analysisContexts);
  if (!vulnerabilityFindings.length && !includeRecommendations) {
    return null;
  }

  const findings = vulnerabilityFindings.length
    ? vulnerabilityFindings
    : buildRecommendations(joinedText, primaryContextNames.length ? primaryContextNames : sourceFileNames);
  const normalizedResultMode = vulnerabilityFindings.length ? 'vulnerability' : 'recommendation';
  const finalFindings = findings;

  return {
    title: buildReportTitle(applicationType, finalFindings, normalizedResultMode),
    applicationType,
    summary: summarizeFindings(finalFindings, normalizedResultMode),
    applicationReport: buildApplicationNarrative(
      applicationType,
      serviceInferenceInputs.sourceFiles.length ? serviceInferenceInputs.sourceFiles : (primaryContextNames.length ? primaryContextNames : sourceFileNames),
      joinedText,
    ),
    resultMode: normalizedResultMode,
    overallSeverity: calculateOverallSeverity(finalFindings),
    findingsCount: finalFindings.length,
    findings: finalFindings,
    sourceFiles,
  };
}

export function selectPreferredAnalysisReport({ normalizedCodexReport, ruleBasedReport }) {
  if (
    normalizedCodexReport?.resultMode === 'vulnerability'
    && Array.isArray(normalizedCodexReport?.findings)
    && normalizedCodexReport.findings.length > 0
  ) {
    return normalizedCodexReport;
  }

  if (
    normalizedCodexReport
    && !(normalizedCodexReport.resultMode === 'recommendation'
      && ruleBasedReport?.resultMode === 'vulnerability'
      && Array.isArray(ruleBasedReport?.findings)
      && ruleBasedReport.findings.length > 0)
  ) {
    return normalizedCodexReport;
  }

  if (ruleBasedReport) {
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
  const serviceInferenceInputs = getServiceInferenceInputs(contexts, sourceFiles);
  const joinedText = serviceInferenceInputs.joinedText;
  const applicationType = inferApplicationType(joinedText, serviceInferenceInputs.sourceFiles);
  const findings = buildRecommendations(joinedText, serviceInferenceInputs.sourceFiles.length ? serviceInferenceInputs.sourceFiles : sourceFiles.map((file) => file.relativePath || file.originalName));
  const summary = compactReportText(
    `자동 분석이 전체 결과를 끝까지 확정하지 못했습니다. ${reason || '분석 프로세스를 다시 이어가야 합니다.'}`,
    { maxLength: 140, maxSentences: 2 },
  );

  return {
    title: buildReviewPendingTitle(applicationType),
    applicationType,
    summary,
    applicationReport: normalizeApplicationReport({
      applicationType,
      applicationReport: '',
      sourceFiles: serviceInferenceInputs.sourceFiles,
      joinedText,
    }),
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
  const contexts = await buildFileContexts(acceptedFiles, onProgress);
  const ruleBasedReport = buildRuleBasedAnalysisReport({ contexts, sourceFiles, includeRecommendations: false });
  const ruleBasedRecommendationReport = buildRuleBasedAnalysisReport({ contexts, sourceFiles, includeRecommendations: true });
  const codexReport = await analyzeWithCodexExec({
    acceptedFiles,
    contexts,
    onProgress,
  });
  const normalizedCodexReport = normalizeCodexReport(codexReport, sourceFiles, contexts);
  const selectedReport = selectPreferredAnalysisReport({
    normalizedCodexReport,
    ruleBasedReport,
  });
  if (selectedReport) {
    if (
      selectedReport === normalizedCodexReport
      && normalizedCodexReport?.resultMode === 'recommendation'
      && Number(normalizedCodexReport?.findingsCount || normalizedCodexReport?.findings?.length || 0) === 0
      && ruleBasedRecommendationReport?.findings?.length
    ) {
      return ruleBasedRecommendationReport;
    }

    return selectedReport;
  }

  if (ruleBasedRecommendationReport?.findings?.length) {
    return ruleBasedRecommendationReport;
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
