import ReportQuizFrame from '../../../../components/ReportQuizFrame';
import { sanitizeQuizForClient } from '../../../../lib/server/report-quiz';

export default async function AnalysisQuizPage({ params }) {
  const [{ getSessionUser }, databaseModule, { getSession }] = await Promise.all([
    import('../../../../lib/server/auth'),
    import('../../../../lib/server/database'),
    import('../../../../lib/server/session'),
  ]);

  const session = await getSession();
  const user = getSessionUser(session);
  const resolvedParams = await params;
  const quizSession = databaseModule.findReportQuizSessionByToken(resolvedParams?.token);

  if (!user || !quizSession || quizSession.userId !== user.id) {
    return (
      <div style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: '#050608',
        color: '#d7dde5',
        fontFamily: 'system-ui, sans-serif',
        padding: '24px',
      }}>
        실습 문제를 불러오지 못했습니다.
      </div>
    );
  }

  return (
    <ReportQuizFrame
      sessionToken={quizSession.sessionToken}
      status={quizSession.status}
      quiz={sanitizeQuizForClient(quizSession.quiz)}
    />
  );
}
