"use client";

export default function DashboardStyles() {
  return (
    <style jsx global>{`
      :root {
        --line: var(--line-soft);
      }

      .dashboard-page {
        min-height: 100vh;
        color: var(--text-main);
        font-family: Pretendard, 'SUIT', 'Noto Sans KR', sans-serif;
        background:
          radial-gradient(circle at top, rgba(255, 255, 255, 0.08), transparent 16%),
          radial-gradient(circle at 82% 12%, rgba(255, 255, 255, 0.04), transparent 22%),
          linear-gradient(to bottom, #040506, #090b0d 100%);
      }

      .dashboard-shell {
        min-height: 100vh;
        padding: 32px 28px 42px;
      }

      .dashboard-head {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 16px;
        margin: 0 auto 28px;
        max-width: 1160px;
        padding: 14px 18px;
        border: 1px solid rgba(255, 255, 255, 0.06);
        border-radius: 999px;
        background: rgba(255, 255, 255, 0.028);
        box-shadow: var(--shadow-md);
        backdrop-filter: blur(16px);
      }

      .dashboard-home {
        color: var(--text-title);
        font-size: 18px;
        font-weight: 800;
        letter-spacing: -0.02em;
      }

      .dashboard-links {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        color: var(--text-sub);
      }

      .dashboard-links a {
        padding: 10px 14px;
        border: 1px solid transparent;
        border-radius: 999px;
      }

      .dashboard-links a:hover {
        color: var(--text-title);
        border-color: rgba(255, 255, 255, 0.08);
        background: rgba(255, 255, 255, 0.04);
      }

      .dashboard-card {
        max-width: 1160px;
        margin: 0 auto;
        padding: 34px;
        border: 1px solid var(--line);
        border-radius: var(--radius-xl);
        background: linear-gradient(180deg, rgba(255, 255, 255, 0.055), rgba(255, 255, 255, 0.03));
        box-shadow: var(--shadow-lg);
        backdrop-filter: blur(20px);
      }

      .dashboard-eyebrow {
        margin-bottom: 10px;
        color: var(--text-sub);
        font-size: 12px;
        letter-spacing: 0.18em;
        text-transform: uppercase;
      }

      .dashboard-card h1 {
        margin: 0;
        color: var(--text-title);
        font-size: clamp(32px, 5vw, 52px);
        letter-spacing: -0.05em;
      }

      .dashboard-subtext {
        margin-top: 12px;
        color: var(--text-sub);
        line-height: 1.75;
        max-width: 720px;
      }

      .dashboard-grid {
        display: grid;
        grid-template-columns: repeat(2, minmax(280px, 1fr));
        gap: 18px;
        margin-top: 28px;
      }

      .dashboard-grid.single {
        grid-template-columns: 1fr;
      }

      .dashboard-panel {
        padding: 24px;
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: var(--radius-lg);
        background: linear-gradient(180deg, rgba(255, 255, 255, 0.05), rgba(255, 255, 255, 0.025));
        box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.025);
      }

      .dashboard-panel-danger {
        border-color: rgba(248, 113, 113, 0.18);
        background: rgba(127, 29, 29, 0.14);
      }

      .dashboard-panel h2 {
        margin: 0 0 14px;
        color: var(--text-title);
        font-size: 21px;
        letter-spacing: -0.03em;
      }

      .dashboard-list {
        display: flex;
        flex-direction: column;
        gap: 12px;
        margin: 0;
        padding: 0;
        list-style: none;
      }

      .dashboard-list li {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        padding-bottom: 12px;
        border-bottom: 1px solid rgba(255, 255, 255, 0.06);
      }

      .dashboard-list li:last-child {
        padding-bottom: 0;
        border-bottom: none;
      }

      .dashboard-list span {
        color: var(--text-sub);
      }

      .dashboard-list strong {
        color: var(--text-title);
        text-align: right;
      }

      .dashboard-panel-text {
        color: var(--text-sub);
        line-height: 1.75;
      }

      .dashboard-actions {
        display: flex;
        flex-wrap: wrap;
        gap: 12px;
        margin-top: 20px;
      }

      .dashboard-button {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-height: 48px;
        padding: 0 18px;
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 16px;
        background: rgba(255, 255, 255, 0.94);
        color: #000000;
        font-size: 14px;
        font-weight: 700;
        cursor: pointer;
        box-shadow: 0 10px 24px rgba(255, 255, 255, 0.06);
      }

      .dashboard-button:hover:not(:disabled) {
        transform: translateY(-1px);
      }

      .dashboard-button.secondary {
        background: rgba(255, 255, 255, 0.03);
        color: var(--text-title);
      }

      .dashboard-button.danger {
        background: rgba(239, 68, 68, 0.9);
        border-color: rgba(248, 113, 113, 0.28);
        color: #ffffff;
      }

      .dashboard-button:disabled {
        opacity: 0.56;
        cursor: default;
      }

      .ui-toast {
        position: fixed;
        top: 24px;
        right: 24px;
        z-index: 120;
        max-width: min(calc(100vw - 32px), 360px);
        padding: 14px 16px;
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 18px;
        background: rgba(18, 18, 20, 0.92);
        color: var(--text-title);
        box-shadow: 0 24px 60px rgba(0, 0, 0, 0.45);
        backdrop-filter: blur(18px);
        opacity: 0;
        pointer-events: none;
        transform: translateY(-10px);
        transition: opacity 0.22s ease, transform 0.22s ease;
      }

      .ui-toast.is-visible {
        opacity: 1;
        transform: translateY(0);
      }

      .ui-toast.success {
        border-color: rgba(52, 211, 153, 0.28);
        background: rgba(6, 78, 59, 0.9);
      }

      .ui-toast.error {
        border-color: rgba(248, 113, 113, 0.28);
        background: rgba(127, 29, 29, 0.9);
      }

      .ui-confirm {
        position: fixed;
        inset: 0;
        z-index: 140;
        display: grid;
        place-items: center;
        padding: 20px;
      }

      .ui-confirm-backdrop {
        position: absolute;
        inset: 0;
        background: rgba(0, 0, 0, 0.62);
        backdrop-filter: blur(8px);
      }

      .ui-confirm-card {
        position: relative;
        width: min(100%, 420px);
        padding: 24px;
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 24px;
        background: rgba(12, 12, 14, 0.96);
        box-shadow: var(--shadow-lg);
      }

      .ui-confirm-eyebrow {
        margin-bottom: 10px;
        color: var(--text-sub);
        font-size: 12px;
        letter-spacing: 0.18em;
        text-transform: uppercase;
      }

      .ui-confirm-title {
        margin: 0;
        color: var(--text-title);
        font-size: 28px;
        letter-spacing: -0.04em;
      }

      .ui-confirm-message {
        margin-top: 12px;
        color: var(--text-sub);
        line-height: 1.7;
      }

      .ui-confirm-actions {
        display: flex;
        justify-content: flex-end;
        gap: 12px;
        margin-top: 22px;
      }

      .admin-toolbar {
        justify-content: space-between;
        align-items: center;
        margin-bottom: 18px;
      }

      .admin-user-list {
        display: grid;
        gap: 14px;
      }

      .admin-user-card {
        padding: 20px;
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 20px;
        background: rgba(255, 255, 255, 0.022);
      }

      .admin-user-card > div:first-child {
        display: flex;
        flex-direction: column;
        gap: 6px;
        margin-bottom: 14px;
      }

      .admin-user-card strong {
        color: var(--text-title);
        font-size: 18px;
      }

      .admin-user-card p {
        margin: 0;
        color: var(--text-sub);
      }

      .admin-user-meta {
        margin-bottom: 16px;
      }

      @media (max-width: 820px) {
        .dashboard-shell {
          padding: 18px;
        }

        .dashboard-head {
          flex-direction: column;
          align-items: flex-start;
          border-radius: 28px;
        }

        .dashboard-grid {
          grid-template-columns: 1fr;
        }

        .ui-confirm-actions {
          flex-direction: column-reverse;
        }
      }
    `}</style>
  );
}