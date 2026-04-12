function buildFallbackPatchExample(comment, code) {
  return [
    '현재 코드:',
    `/* ${comment} */`,
    '',
    '패치 예시 코드:',
    code,
  ].join('\n');
}

function stripSectionHeadingPrefix(value, patterns = []) {
  let text = String(value || '').trim();
  if (!text) {
    return text;
  }

  patterns.forEach((pattern) => {
    text = text.replace(pattern, '').trim();
  });

  return text;
}

function normalizeDisplayFinding(finding) {
  if (!finding || typeof finding !== 'object') {
    return finding;
  }

  return {
    ...finding,
    explanation: stripSectionHeadingPrefix(finding.explanation, [
      /^\s*1[\.\)]\s*취약점\s*설명\s*/u,
    ]),
    detail: stripSectionHeadingPrefix(finding.detail, [
      /^\s*2[\.\)]\s*취약점\s*원인\s*분석\s*/u,
    ]),
    remediation: stripSectionHeadingPrefix(finding.remediation, [
      /^\s*4[\.\)]\s*취약점\s*해결\s*방안\s*/u,
    ]),
  };
}

export function buildDisplayRecommendationFindings() {
  return [
    {
      id: 'display-recommendation-input-validation',
      title: '입력 검증',
      severity: 'medium',
      confirmed: false,
      location: '프로젝트 전반',
      codeLocation: '/* 요청을 받는 엔드포인트, 입력 파서, 상태 변경 함수 앞단에서 공통 입력 검증을 먼저 수행해야 합니다. */',
      explanation: '입력 검증 부족은 외부에서 들어오는 값의 타입, 길이, 형식, 허용 범위를 충분히 제한하지 않아 이후 다른 취약점으로 이어질 수 있는 상태를 뜻합니다. 교육 관점에서는 많은 취약점이 이 단계의 실패에서 시작되므로, 어떤 값이 어디까지 들어와도 되는지 먼저 정의하는 습관이 중요합니다.',
      detail: '자동 분석이 확정 취약점을 만들지 못한 경우에도, 사용자 입력이 요청 파서와 상태 변경 로직을 거쳐 저장, 조회, 렌더링, 외부 연동까지 이동하는 흐름은 우선 점검해야 합니다. 검증 규칙이 엔드포인트마다 제각각이면 이후 SQL Injection, XSS, 권한 우회 같은 문제가 연쇄적으로 발생하기 쉬워집니다.',
      remediation: '요청 단위 검증 레이어를 두고 타입, 길이, 허용 문자, 필수 필드 여부를 일관되게 강제해야 합니다. 실무에서는 컨트롤러나 핸들러마다 따로 막기보다 공통 schema, DTO, validator, parser 단계에서 먼저 걸러서 동일한 규칙을 재사용하는 편이 안전합니다.',
      patchExample: buildFallbackPatchExample(
        '요청을 받는 엔드포인트와 상태 변경 함수 앞단에서 공통 입력 검증이 보장되지 않습니다.',
        [
          'const inputSchema = z.object({',
          '  name: z.string().min(1).max(80),',
          '  repoUrl: z.string().url().optional(),',
          '});',
          '',
          'export async function handleRequest(request) {',
          '  const payload = inputSchema.parse(await request.json());',
          '  return processValidatedInput(payload);',
          '}',
        ].join('\n'),
      ),
    },
    {
      id: 'display-recommendation-config-separation',
      title: '설정 분리',
      severity: 'low',
      confirmed: false,
      location: '프로젝트 전반',
      codeLocation: '/* 환경 변수, 시크릿, 운영 설정, 디버그 로그는 기능 코드와 분리해 관리해야 합니다. */',
      explanation: '설정 분리 부족은 비밀값, 운영 설정, 로그 정책이 같은 위치에서 섞여 관리되어 노출이나 오작동 위험이 커진 상태를 뜻합니다. 실제 서비스에서는 기능 코드보다 운영 설정이 먼저 새는 경우도 많기 때문에, 인증 키와 환경 설정을 별도 관리 체계로 분리하는 것이 중요합니다.',
      detail: '자동 분석이 특정 exploit를 확정하지 못했더라도, 환경 변수와 시크릿 주입, 로그 출력, 외부 서비스 연동 설정이 코드와 뒤섞여 있으면 저장소 유출이나 잘못된 배포 설정만으로도 운영 위험이 커질 수 있습니다. 개발, 테스트, 운영 환경의 보안 수준이 분리돼 있는지 먼저 점검해야 합니다.',
      remediation: '환경 변수, 시크릿 저장소, 운영 로그 정책을 분리하고 민감값은 코드나 로그에 직접 남기지 않아야 합니다. 이미 노출된 값은 삭제만 할 것이 아니라 회전해야 하며, 로그에는 토큰, 쿠키, 인증 헤더가 남지 않도록 마스킹 규칙을 적용하는 편이 좋습니다.',
      patchExample: buildFallbackPatchExample(
        '민감한 설정과 운영값을 기능 코드와 분리해 관리해야 합니다.',
        [
          'const config = {',
          "  githubClientId: process.env.GITHUB_CLIENT_ID || '',",
          "  githubClientSecret: process.env.GITHUB_CLIENT_SECRET || '',",
          "  sessionSecret: process.env.SESSION_SECRET || '',",
          '};',
          '',
          'if (!config.githubClientId || !config.githubClientSecret || !config.sessionSecret) {',
          "  throw new Error('required secret is missing');",
          '}',
        ].join('\n'),
      ),
    },
  ];
}

export function normalizeReportForDisplay(report) {
  if (!report) {
    return report;
  }

  const findings = Array.isArray(report.findings)
    ? report.findings.filter(Boolean).map(normalizeDisplayFinding)
    : [];
  if (findings.length || report.resultMode === 'vulnerability') {
    return {
      ...report,
      findings,
      findingsCount: Number(report.findingsCount || findings.length || 0),
    };
  }

  const synthesizedFindings = buildDisplayRecommendationFindings();

  return {
    ...report,
    overallSeverity: report.overallSeverity === 'high' || report.overallSeverity === 'medium'
      ? report.overallSeverity
      : 'medium',
    findings: synthesizedFindings,
    findingsCount: synthesizedFindings.length,
    summary: String(report.summary || '').trim()
      || '자동 분석이 확정 취약점을 만들지 못해 프로젝트 전반의 보완 포인트를 정리했습니다.',
  };
}
