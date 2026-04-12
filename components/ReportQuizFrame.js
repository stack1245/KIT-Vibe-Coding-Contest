'use client';

import { useMemo, useState } from 'react';
import { fetchJson } from '../lib/client/fetch-json';
import styles from './ReportQuizFrame.module.css';

async function copyToClipboard(value) {
  if (navigator.clipboard?.writeText && window.isSecureContext) {
    await navigator.clipboard.writeText(String(value || ''));
    return;
  }

  const textArea = document.createElement('textarea');
  textArea.value = String(value || '');
  textArea.setAttribute('readonly', 'true');
  textArea.style.position = 'fixed';
  textArea.style.top = '-9999px';
  document.body.appendChild(textArea);
  textArea.focus();
  textArea.select();
  document.execCommand('copy');
  document.body.removeChild(textArea);
}

export default function ReportQuizFrame({ sessionToken, status = 'ready', quiz = null }) {
  const [answers, setAnswers] = useState({});
  const [grading, setGrading] = useState(false);
  const [flag, setFlag] = useState('');
  const [message, setMessage] = useState('');
  const [incorrectQuestionIds, setIncorrectQuestionIds] = useState([]);

  const questionCount = Array.isArray(quiz?.questions) ? quiz.questions.length : 0;
  const answeredCount = useMemo(
    () => Object.values(answers).filter((value) => Number.isInteger(Number(value))).length,
    [answers],
  );

  function handleChoiceChange(questionId, choiceIndex) {
    setAnswers((current) => ({
      ...current,
      [questionId]: Number(choiceIndex),
    }));
  }

  async function handleSubmitAnswers() {
    if (grading) {
      return;
    }

    if (answeredCount !== questionCount) {
      setMessage('모든 문항에 답을 선택한 뒤 제출해 주세요.');
      return;
    }

    setGrading(true);
    setMessage('');

    try {
      const payload = await fetchJson(`/api/analysis/quizzes/${sessionToken}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ answers }),
      });

      if (payload.correct) {
        setFlag(payload.flag || '');
        setIncorrectQuestionIds([]);
        setMessage(payload.message || '모든 문제를 맞췄습니다.');
        return;
      }

      setFlag('');
      setIncorrectQuestionIds(Array.isArray(payload.incorrectQuestionIds) ? payload.incorrectQuestionIds : []);
      setMessage(payload.message || '틀린 문항이 있습니다.');
    } catch (error) {
      setMessage(error.message || '문제 채점에 실패했습니다.');
    } finally {
      setGrading(false);
    }
  }

  return (
    <div className={styles.framePage}>
      <div className={styles.frameInner}>
        <div className={styles.header}>
          <div>
            <p className={styles.eyebrow}>phase quiz</p>
            <h1 className={styles.title}>{quiz?.title || '실습 문제'}</h1>
          </div>
          <div className={styles.metaCard}>
            <strong>{questionCount}문항</strong>
            <span>{answeredCount}/{questionCount} 답변</span>
          </div>
        </div>

        <p className={styles.description}>
          {quiz?.description || '취약점 리포트 내용을 바탕으로 만든 객관식 문제입니다. 모든 문제를 맞추면 플래그가 표시됩니다.'}
        </p>

        {status === 'solved' ? (
          <div className={styles.successPanel}>이미 플래그 제출이 완료된 실습 문제입니다.</div>
        ) : null}

        <div className={styles.questionList}>
          {(Array.isArray(quiz?.questions) ? quiz.questions : []).map((question, index) => (
            <article
              key={question.id}
              className={`${styles.questionCard} ${incorrectQuestionIds.includes(question.id) ? styles.questionCardIncorrect : ''}`}
            >
              <div className={styles.questionHead}>
                <span className={styles.questionNumber}>Q{index + 1}</span>
                <span className={styles.questionSection}>{question.sourceSection}</span>
              </div>
              <h2 className={styles.questionPrompt}>{question.prompt}</h2>
              <div className={styles.choiceList}>
                {question.choices.map((choice, choiceIndex) => {
                  const checked = Number(answers?.[question.id]) === choiceIndex;

                  return (
                    <label key={`${question.id}-${choiceIndex}`} className={`${styles.choiceItem} ${checked ? styles.choiceItemSelected : ''}`}>
                      <input
                        type="radio"
                        name={question.id}
                        value={choiceIndex}
                        checked={checked}
                        onChange={() => handleChoiceChange(question.id, choiceIndex)}
                      />
                      <span>{choice}</span>
                    </label>
                  );
                })}
              </div>
            </article>
          ))}
        </div>

        <div className={styles.footer}>
          <button type="button" className={styles.submitButton} onClick={handleSubmitAnswers} disabled={grading || !questionCount}>
            {grading ? '채점 중...' : '문제 제출'}
          </button>
          {message ? <div className={styles.message}>{message}</div> : null}
        </div>

        {flag ? (
          <div className={styles.flagPanel}>
            <strong>플래그</strong>
            <code>{flag}</code>
            <p>이 값을 복사한 뒤 원래 리포트 화면으로 돌아가 플래그 제출창에 입력하세요.</p>
            <button type="button" className={styles.copyButton} onClick={() => copyToClipboard(flag)}>
              플래그 복사
            </button>
          </div>
        ) : null}
      </div>
    </div>
  );
}
