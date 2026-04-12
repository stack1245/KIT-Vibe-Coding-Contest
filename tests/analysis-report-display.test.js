import { describe, expect, it } from 'vitest';
import { normalizeReportForDisplay } from '../lib/analysis-report-display';
import { formatAnalysisReport } from '../lib/server/database';

describe('analysis report display fallback', () => {
  it('fills recommendation findings when a report is otherwise empty', () => {
    const normalized = normalizeReportForDisplay({
      id: 'report-1',
      title: '코드 업로드와 GitHub 저장소 취약점 분석 웹 서비스 추가 검토 리포트',
      applicationType: '코드 업로드와 GitHub 저장소 취약점 분석 웹 서비스',
      summary: '자동 분석이 전체 결과를 끝까지 확정하지 못했습니다.',
      applicationReport: '이 서비스는 코드와 저장소를 올려 점검 결과를 확인하는 웹 서비스입니다. 또한 서버 엔드포인트와 처리 함수가 업로드, 인증, 외부 연동을 처리합니다.',
      resultMode: 'recommendation',
      overallSeverity: 'low',
      findingsCount: 0,
      findings: [],
      sourceFiles: [],
    });

    expect(normalized.findingsCount).toBe(2);
    expect(normalized.findings.map((finding) => finding.title)).toEqual(['입력 검증', '설정 분리']);
    expect(normalized.findings.every((finding) => finding.location === '프로젝트 전반')).toBe(true);
  });

  it('upgrades legacy fallback reports loaded from the database into visible recommendation findings', () => {
    const report = formatAnalysisReport({
      id: 7,
      user_id: 1,
      title: '코드 업로드와 GitHub 저장소 취약점 분석 웹 서비스 보안 조언 리포트',
      application_type: '코드 업로드와 GitHub 저장소 취약점 분석 웹 서비스',
      summary: '업로드 분석 시간이 길어 추가 검토가 필요합니다.',
      application_report: '이 서비스는 코드와 저장소를 올려 점검 결과를 확인하는 웹 서비스입니다. 또한 서버 엔드포인트와 처리 함수가 업로드, 인증, 외부 연동을 처리합니다.',
      result_mode: 'recommendation',
      overall_severity: 'low',
      findings_count: 1,
      findings_json: JSON.stringify([
        {
          id: 'fallback-review-0',
          title: '업로드 분석 시간이 길어 추가 검토가 필요',
        },
      ]),
      source_files_json: '[]',
      share_enabled: 0,
      share_token: '',
      created_at: '2026-04-12T10:00:00.000Z',
      updated_at: '2026-04-12T10:00:00.000Z',
    });

    expect(report.findingsCount).toBe(2);
    expect(report.findings[0].title).toBe('입력 검증');
    expect(report.summary).toContain('추가 검토가 필요합니다');
  });

  it('strips duplicated section headings from finding bodies for display', () => {
    const normalized = normalizeReportForDisplay({
      id: 'report-2',
      title: '테스트 리포트',
      applicationType: '테스트 서비스',
      summary: '발견된 취약점 : XSS',
      applicationReport: '이 서비스는 테스트용 서비스입니다. 또한 처리 함수가 테스트 흐름을 담당합니다.',
      resultMode: 'vulnerability',
      overallSeverity: 'medium',
      findingsCount: 1,
      findings: [
        {
          id: 'finding-1',
          title: 'XSS',
          severity: 'medium',
          location: 'app/page.js:10',
          explanation: '1) 취약점 설명 XSS는 브라우저에서 악성 스크립트가 실행되게 하는 취약점이다.',
          detail: '2) 취약점 원인 분석 사용자 입력이 HTML로 렌더링된다.',
          remediation: '4) 취약점 해결 방안 사용자 입력을 텍스트로 렌더링해야 한다.',
        },
      ],
      sourceFiles: [],
    });

    expect(normalized.findings[0].explanation.startsWith('1)')).toBe(false);
    expect(normalized.findings[0].detail.startsWith('2)')).toBe(false);
    expect(normalized.findings[0].remediation.startsWith('4)')).toBe(false);
  });
});
