# Phase Vuln Coach

Phase Vuln Coach는 Next.js App Router 기반의 웹 애플리케이션입니다. 랜딩 페이지, 로컬 계정 인증, GitHub OAuth, 관리자 페이지, 이메일 인증 기반 회원가입, SQLite 기반 사용자 저장소를 포함합니다.

## 실행 방법

### 1. 환경 변수 준비

루트 경로에서 `.env.example`을 복사해 `.env`를 만든 뒤 값을 채웁니다.

```env
APP_BASE_URL=http://localhost:3000
SESSION_SECRET=replace-with-a-long-random-secret

GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
GITHUB_REDIRECT_URI=http://localhost:3000/auth/github/callback
GITHUB_SCOPE=read:user user:email

ADMIN_EMAILS=

SMTP_HOST=
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=
SMTP_PASS=
SMTP_FROM=Phase Vuln Coach <no-reply@example.com>
```

### 2. 의존성 설치

```bash
npm install
```

### 3. 개발 서버 실행

```bash
npm run dev
```

프로덕션 실행은 아래 명령을 사용합니다.

```bash
npm start
```

## 환경 변수 설명

### App

- `APP_BASE_URL`: OAuth 콜백과 절대 URL 계산에 사용하는 기본 주소
- `SESSION_SECRET`: 세션 서명 키. 운영 환경에서는 반드시 긴 난수 문자열 사용

### GitHub OAuth

- `GITHUB_CLIENT_ID`: GitHub OAuth App Client ID
- `GITHUB_CLIENT_SECRET`: GitHub OAuth App Client Secret
- `GITHUB_REDIRECT_URI`: GitHub OAuth 콜백 주소
- `GITHUB_SCOPE`: 기본 권한 범위. 일반적으로 `read:user user:email`

### Admin

- `ADMIN_EMAILS`: 관리자 이메일 목록. 쉼표로 여러 개 입력 가능

### SMTP

- `SMTP_HOST`: 메일 서버 주소
- `SMTP_PORT`: 메일 서버 포트
- `SMTP_SECURE`: SSL 직결 여부. `465`는 보통 `true`, `587`은 보통 `false`
- `SMTP_USER`: SMTP 로그인 계정
- `SMTP_PASS`: SMTP 비밀번호 또는 앱 비밀번호
- `SMTP_FROM`: 발신자 표시 이름과 주소

## Gmail SMTP 참고

Gmail은 일반 계정 비밀번호로 SMTP 로그인이 막힐 수 있습니다. 2단계 인증을 사용하는 개인 계정이라면 `SMTP_PASS`에 Google 앱 비밀번호를 넣어야 합니다.

앱 비밀번호 메뉴가 보이지 않거나 `myaccount.google.com/apppasswords`에서 접근이 안 되면 아래 가능성을 먼저 확인하세요.

- 학교/회사 Workspace 계정이라 관리자 정책으로 비활성화된 경우
- 2단계 인증은 켜져 있지만 계정 정책상 앱 비밀번호 사용이 제한된 경우
- Gmail 대신 다른 SMTP 서비스가 더 적합한 경우

## 주요 기능

- 메인 랜딩 페이지와 섹션 네비게이션
- 이메일/비밀번호 회원가입 및 로그인
- 이메일 인증 코드 발송 후 확인 기반 회원가입
- GitHub OAuth 로그인
- 기존 로컬 계정에 GitHub 계정 연동
- 대시보드, 분석 페이지, 관리자 페이지
- 관리자 이메일 기반 회원 목록 조회 및 삭제
- SQLite 기반 계정 저장

## SQLite DB 및 스키마

- 런타임 DB 파일: `data/phase-vuln-coach.sqlite`
- 스키마 파일: `db/schema.sql`
- 마이그레이션 디렉터리: `db/migrations`
- 실제 초기화 코드: `lib/server/database.js`

애플리케이션이 시작되면 `lib/server/database.js`가 `db/schema.sql`을 읽어 최신 스냅샷 스키마를 초기화합니다. 기존 DB가 이미 있으면 `db/migrations` 아래의 SQL 파일을 순서대로 적용해 스키마를 최신 상태로 맞춥니다. `data/`는 `.gitignore`에 포함되어 있으므로 실제 DB 파일은 커밋되지 않고, 스키마와 migration만 Git에 포함됩니다.

현재 포함된 테이블은 아래 두 개입니다.

- `users`: 이메일 계정, GitHub 연동 정보, 인증 방식, 생성/수정 시각 저장
- `email_verifications`: 이메일 인증 코드 해시와 만료 시각 저장
- `schema_migrations`: 적용된 migration 이력 저장

현재 `users` 테이블에는 마지막 로그인 시각 확인을 위한 `last_login_at` 컬럼도 포함됩니다.

## 보안 강화

- 로그인, 회원가입, 이메일 인증 요청/확인 API에 IP + 이메일 기준 rate limit이 적용됩니다.
- 관리자 사용자 목록 조회/삭제 API에도 rate limit이 적용됩니다.
- 로그인 성공 시 마지막 로그인 시각이 SQLite에 저장됩니다.

## 테스트

```bash
npm test
```

기본 테스트는 아래 범위를 검증합니다.

- 스키마 스냅샷 기반 DB 초기화
- 기존 SQLite DB에 대한 migration 적용
- 회원가입 인증 세션 헬퍼 동작
- rate limit 윈도우 동작

## 프로젝트 구조

```text
.
├─ app/
│  ├─ api/
│  ├─ admin/
│  ├─ analysis/
│  ├─ auth/
│  ├─ dashboard/
│  ├─ login/
│  ├─ globals.css
│  ├─ layout.js
│  └─ page.js
├─ components/
├─ db/
│  ├─ migrations/
│  └─ schema.sql
├─ data/
├─ lib/
│  ├─ client/
│  └─ server/
├─ public/
│  └─ assets/
├─ .env.example
├─ next.config.mjs
└─ package.json
```

## 주요 라우트

### 페이지

- `/`: 메인 페이지
- `/login`: 로그인/회원가입 페이지
- `/dashboard`: 로그인 사용자 전용 대시보드
- `/analysis`: 로그인 사용자 전용 분석 페이지
- `/admin`: 관리자 전용 페이지

### 인증 API

- `GET /api/auth/config`
- `GET /api/auth/session`
- `POST /api/auth/signup`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `POST /api/auth/email-verification/request`
- `POST /api/auth/email-verification/confirm`
- `DELETE /api/auth/account`

### GitHub OAuth

- `GET /auth/github`
- `GET /auth/github/callback`

### 관리자 API

- `GET /api/admin/users`
- `DELETE /api/admin/users/:id`

## 인증 흐름 요약

### 이메일 회원가입

1. 회원가입 탭에서 이메일 입력
2. 인증 요청 버튼으로 메일 발송
3. 모달에서 6자리 인증 코드 입력
4. 인증 성공 후 비밀번호 입력란 활성화
5. 회원가입 완료 시 세션 생성 후 대시보드 이동

### GitHub 로그인

1. 로그인 또는 회원가입 탭에서 GitHub 버튼 클릭
2. GitHub OAuth 인증 진행
3. 기존 GitHub 계정이면 로그인, 신규면 사용자 생성 후 로그인

### GitHub 연동

1. 로컬 계정으로 로그인
2. 대시보드에서 GitHub 연동 진행
3. 동일 GitHub 계정이 다른 사용자에 연결돼 있지 않으면 현재 계정에 연결

## 현재 구조 메모

- 정적 자산은 `public/assets` 아래에서 `/assets/*` 경로로 제공합니다.
- 인증과 관리자 기능은 Next.js Route Handler와 `lib/server` 유틸로 분리되어 있습니다.
- SQLite 스키마는 `db/schema.sql`에 버전 관리되며, 런타임 DB 파일은 커밋되지 않습니다.
- 이메일 인증 완료 상태에는 만료 시간이 적용됩니다.
- 기본 보안 헤더는 `next.config.mjs`에서 설정합니다.
