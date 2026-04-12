import 'server-only';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { buildFindingQuizKey, buildPhaseFlagFromHex, isQuizEligibleFinding } from '../report-quiz';

const QUIZ_SECTION_NAMES = ['취약점 설명', '취약점 발생 원인', '취약점 위치', '패치 조언', '패치 코드'];

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

function sanitizeChoice(value) {
  return String(value || '').replace(/\s+/g, ' ').trim();
}

function sanitizeQuestionPrompt(value) {
  return String(value || '').trim();
}

function buildSectionSource(finding) {
  return {
    '취약점 설명': String(finding?.explanation || '').trim(),
    '취약점 발생 원인': String(finding?.detail || '').trim(),
    '취약점 위치': String([
      `파일 경로: ${finding?.location || '위치 정보 없음'}`,
      '핵심 코드:',
      String(finding?.codeLocation || '').trim(),
    ].join('\n')).trim(),
    '패치 조언': String(finding?.remediation || '').trim(),
    '패치 코드': String(finding?.patchExample || '').trim(),
  };
}

export function buildReportFindingQuizPrompt({ report, finding, findingKey }) {
  const sectionSource = buildSectionSource(finding);

  return [
    'You are generating an educational multiple-choice quiz from a single vulnerability report finding.',
    'Do not use static templates. Read the provided report and finding content, and write a fresh quiz that matches this specific vulnerability.',
    'The quiz must help a learner study the vulnerability itself, why it happened in this code, where it happened, how to patch it, and what the patch code means.',
    'Generate exactly 10 questions.',
    'You must create exactly 2 questions from each of these five sections: 취약점 설명, 취약점 발생 원인, 취약점 위치, 패치 조언, 패치 코드.',
    'Every question must be objective multiple-choice with exactly 5 choices.',
    'Randomize the correct answer position across questions. Do not always place the correct answer in the same index.',
    'Make the questions educational, specific to the provided finding, and study-friendly.',
    'Do not ask trick questions. Each question should have one clearly correct answer grounded in the report text.',
    'Return Korean JSON only.',
    JSON.stringify({
      report: {
        title: report?.title || '',
        applicationType: report?.applicationType || '',
        applicationReport: report?.applicationReport || '',
        summary: report?.summary || '',
      },
      finding: {
        key: findingKey,
        title: finding?.title || '',
        severity: finding?.severity || '',
        sections: sectionSource,
      },
      schema: {
        title: 'quiz title',
        description: 'short description',
        questions: [
          {
            id: 'string',
            sourceSection: '"취약점 설명" | "취약점 발생 원인" | "취약점 위치" | "패치 조언" | "패치 코드"',
            prompt: 'string',
            choices: ['string', 'string', 'string', 'string', 'string'],
            answerIndex: '0-4 integer',
            explanation: 'string',
          },
        ],
      },
      constraints: [
        'questions must contain exactly 10 items',
        'sourceSection counts must be exactly 2 per section',
        'choices must contain exactly 5 items',
        'answerIndex must point to one of the 5 choices',
        'explanation must teach why the correct answer is correct',
      ],
    }, null, 2),
  ].join('\n\n');
}

function normalizeQuizQuestion(question, index = 0) {
  const choices = Array.isArray(question?.choices)
    ? question.choices.map(sanitizeChoice).filter(Boolean).slice(0, 5)
    : [];
  const answerIndex = Number(question?.answerIndex);
  const sourceSection = QUIZ_SECTION_NAMES.includes(String(question?.sourceSection || '').trim())
    ? String(question.sourceSection).trim()
    : '';

  if (!sourceSection || choices.length !== 5 || !Number.isInteger(answerIndex) || answerIndex < 0 || answerIndex >= choices.length) {
    return null;
  }

  return {
    id: String(question?.id || `question-${index + 1}`).trim() || `question-${index + 1}`,
    sourceSection,
    prompt: sanitizeQuestionPrompt(question?.prompt),
    choices,
    answerIndex,
    explanation: String(question?.explanation || '').trim(),
  };
}

export function normalizeGeneratedQuiz(payload, { finding, findingKey }) {
  if (!payload || typeof payload !== 'object') {
    return null;
  }

  const questions = Array.isArray(payload.questions)
    ? payload.questions.map((question, index) => normalizeQuizQuestion(question, index)).filter(Boolean)
    : [];

  if (questions.length !== 10) {
    return null;
  }

  const counts = questions.reduce((accumulator, question) => {
    accumulator[question.sourceSection] = (accumulator[question.sourceSection] || 0) + 1;
    return accumulator;
  }, {});

  if (QUIZ_SECTION_NAMES.some((sectionName) => counts[sectionName] !== 2)) {
    return null;
  }

  return {
    title: String(payload.title || `${finding?.title || '취약점'} 학습 퀴즈`).trim(),
    description: String(payload.description || `${finding?.title || '취약점'} 관련 객관식 문제 10개`).trim(),
    findingKey,
    vulnerabilityTitle: String(finding?.title || '').trim(),
    questions,
  };
}

export function sanitizeQuizForClient(quiz) {
  return {
    title: String(quiz?.title || '').trim(),
    description: String(quiz?.description || '').trim(),
    findingKey: String(quiz?.findingKey || '').trim(),
    vulnerabilityTitle: String(quiz?.vulnerabilityTitle || '').trim(),
    questions: Array.isArray(quiz?.questions)
      ? quiz.questions.map((question) => ({
          id: question.id,
          sourceSection: question.sourceSection,
          prompt: question.prompt,
          choices: Array.isArray(question.choices) ? [...question.choices] : [],
        }))
      : [],
  };
}

function runQuizCodex(prompt, outputFile, workdir, timeoutMs = 4 * 60 * 1000) {
  return new Promise((resolve, reject) => {
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
      workdir,
    ];

    const model = process.env.ANALYSIS_CODEX_MODEL || process.env.UPLOAD_CODEX_MODEL || 'gpt-5.4';
    if (model) {
      args.push('--model', model);
    }

    args.push('-');

    const child = spawn('codex', args, {
      cwd: workdir,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: process.env,
    });

    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      reject(new Error(`quiz-generation-timeout:${timeoutMs}`));
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
      reject(new Error(`quiz-generation-exit:${code}`));
    });
  });
}

export async function generateFindingQuiz({ report, finding, findingIndex = 0 }) {
  if (!isQuizEligibleFinding(finding)) {
    throw new Error('high 심각도 취약점만 실습 문제를 생성할 수 있습니다.');
  }

  if (!String(process.env.CODEX_HOME || process.env.HOME || '').trim()) {
    throw new Error('Codex 실행 환경을 찾지 못했습니다.');
  }

  const findingKey = buildFindingQuizKey(finding, findingIndex);
  const workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'phase-report-quiz-'));
  const outputFile = path.join(workspaceRoot, 'report-quiz.json');

  try {
    await runQuizCodex(
      buildReportFindingQuizPrompt({ report, finding, findingKey }),
      outputFile,
      workspaceRoot,
    );

    const parsed = fs.existsSync(outputFile)
      ? extractJsonObject(fs.readFileSync(outputFile, 'utf8'))
      : null;
    const quiz = normalizeGeneratedQuiz(parsed, { finding, findingKey });

    if (!quiz) {
      throw new Error('유효한 퀴즈 JSON을 생성하지 못했습니다.');
    }

    const flagHex = crypto.randomBytes(5).toString('hex');

    return {
      findingKey,
      sessionToken: crypto.randomBytes(18).toString('hex'),
      flagHex,
      flagValue: buildPhaseFlagFromHex(flagHex),
      quiz,
    };
  } finally {
    fs.rmSync(workspaceRoot, { recursive: true, force: true });
  }
}

export function gradeFindingQuiz(quiz, answers = {}) {
  const questions = Array.isArray(quiz?.questions) ? quiz.questions : [];
  const incorrectQuestionIds = [];

  questions.forEach((question) => {
    const submitted = Number(answers?.[question.id]);
    if (!Number.isInteger(submitted) || submitted !== Number(question.answerIndex)) {
      incorrectQuestionIds.push(question.id);
    }
  });

  return {
    correct: questions.length > 0 && incorrectQuestionIds.length === 0,
    incorrectQuestionIds,
    totalQuestions: questions.length,
  };
}
