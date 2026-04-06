# Phase Vuln Coach

Phase Vuln Coach는 랜딩 페이지, 로컬 계정 인증, GitHub OAuth, 관리자 페이지, 이메일 인증 기반 회원가입을 포함한 Node.js 웹 애플리케이션입니다.

## 실행 방법

### 1. 환경 변수 준비

루트 경로에서 `.env.example`을 복사해 `.env`를 만든 뒤 값을 채웁니다.

```env
PORT=3000
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

- `PORT`: 서버 포트
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

## 프로젝트 구조

```text
.
├─ server.js
├─ data/
├─ src/
│  ├─ assets/
│  │  ├─ css/
│  │  ├─ images/
│  │  ├─ js/
│  │  └─ video/
│  ├─ pages/
│  └─ server/
│     ├─ app.js
│     └─ database.js
├─ .env.example
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

## 현재 최적화 포인트

- 정적 자산 경로를 `src/assets` 아래로 통일
- 세션 기반 인증 상태와 관리자 권한 분리
- 이메일 인증 완료 상태에 만료 시간 적용
- 메인 페이지 로그아웃 실패 처리에서 브라우저 `alert` 제거
- 서버 기본 보안 헤더 추가