import { describe, expect, it } from 'vitest';
import { buildFindingQuizKey, buildPhaseFlagFromHex, isQuizEligibleFinding } from '../lib/report-quiz';
import {
  buildReportFindingQuizPrompt,
  normalizeGeneratedQuiz,
  sanitizeQuizForClient,
  gradeFindingQuiz,
} from '../lib/server/report-quiz';

describe('report quiz helpers', () => {
  it('builds stable quiz keys and eligibility from findings', () => {
    const finding = {
      id: 'finding-7',
      title: 'CSRF',
      location: 'app/api/profile/route.js:18',
      severity: 'high',
    };

    expect(buildFindingQuizKey(finding, 0)).toContain('finding-7');
    expect(isQuizEligibleFinding(finding)).toBe(true);
    expect(isQuizEligibleFinding({ ...finding, severity: 'medium' })).toBe(false);
    expect(buildPhaseFlagFromHex('1a2b3c4d5e')).toBe('Phase{1a2b3c4d5e}');
  });

  it('builds a prompt that requires 10 questions and 2 per report section', () => {
    const prompt = buildReportFindingQuizPrompt({
      report: {
        title: '코드 보안 점검 솔루션 리포트',
        applicationType: '코드 보안 점검 서비스',
      },
      finding: {
        title: 'CSRF',
        severity: 'high',
        explanation: '설명',
        detail: '원인',
        location: 'app/api/profile/route.js:18',
        codeLocation: 'router.post("/profile")',
        remediation: '패치 조언',
        patchExample: '현재 코드:\nfoo\n\n패치 예시 코드:\nbar',
      },
      findingKey: 'csrf-finding',
    });

    expect(prompt).toContain('Generate exactly 10 questions.');
    expect(prompt).toContain('exactly 2 questions from each of these five sections');
    expect(prompt).toContain('Every question must be objective multiple-choice with exactly 5 choices.');
  });

  it('normalizes generated quiz payloads and strips answers from client output', () => {
    const payload = {
      title: 'CSRF 학습 퀴즈',
      description: '설명',
      questions: [
        { id: 'q1', sourceSection: '취약점 설명', prompt: '1', choices: ['a', 'b', 'c', 'd', 'e'], answerIndex: 0, explanation: 'x' },
        { id: 'q2', sourceSection: '취약점 설명', prompt: '2', choices: ['a', 'b', 'c', 'd', 'e'], answerIndex: 1, explanation: 'x' },
        { id: 'q3', sourceSection: '취약점 발생 원인', prompt: '3', choices: ['a', 'b', 'c', 'd', 'e'], answerIndex: 2, explanation: 'x' },
        { id: 'q4', sourceSection: '취약점 발생 원인', prompt: '4', choices: ['a', 'b', 'c', 'd', 'e'], answerIndex: 3, explanation: 'x' },
        { id: 'q5', sourceSection: '취약점 위치', prompt: '5', choices: ['a', 'b', 'c', 'd', 'e'], answerIndex: 4, explanation: 'x' },
        { id: 'q6', sourceSection: '취약점 위치', prompt: '6', choices: ['a', 'b', 'c', 'd', 'e'], answerIndex: 0, explanation: 'x' },
        { id: 'q7', sourceSection: '패치 조언', prompt: '7', choices: ['a', 'b', 'c', 'd', 'e'], answerIndex: 1, explanation: 'x' },
        { id: 'q8', sourceSection: '패치 조언', prompt: '8', choices: ['a', 'b', 'c', 'd', 'e'], answerIndex: 2, explanation: 'x' },
        { id: 'q9', sourceSection: '패치 코드', prompt: '9', choices: ['a', 'b', 'c', 'd', 'e'], answerIndex: 3, explanation: 'x' },
        { id: 'q10', sourceSection: '패치 코드', prompt: '10', choices: ['a', 'b', 'c', 'd', 'e'], answerIndex: 4, explanation: 'x' },
      ],
    };

    const quiz = normalizeGeneratedQuiz(payload, {
      finding: { title: 'CSRF' },
      findingKey: 'csrf-finding',
    });
    const clientQuiz = sanitizeQuizForClient(quiz);

    expect(quiz.questions).toHaveLength(10);
    expect(clientQuiz.questions).toHaveLength(10);
    expect(clientQuiz.questions[0].answerIndex).toBeUndefined();
  });

  it('grades answer sets and reports incorrect questions', () => {
    const quiz = {
      questions: [
        { id: 'q1', answerIndex: 0 },
        { id: 'q2', answerIndex: 2 },
      ],
    };

    const wrong = gradeFindingQuiz(quiz, { q1: 0, q2: 1 });
    const correct = gradeFindingQuiz(quiz, { q1: 0, q2: 2 });

    expect(wrong.correct).toBe(false);
    expect(wrong.incorrectQuestionIds).toEqual(['q2']);
    expect(correct.correct).toBe(true);
  });
});
