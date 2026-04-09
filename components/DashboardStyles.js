"use client";

export default function DashboardStyles() {
  return (
    <style jsx global>{`
      :root {
        --line: var(--line-soft);
      }

      .dashboard-page {
        position: relative;
        overflow: hidden;
        min-height: 100vh;
        color: var(--text-main);
        font-family: Pretendard, 'SUIT', 'Noto Sans KR', sans-serif;
        background:
          radial-gradient(circle at top, rgba(255, 255, 255, 0.08), transparent 16%),
          radial-gradient(circle at 82% 12%, rgba(255, 255, 255, 0.04), transparent 22%),
          linear-gradient(to bottom, #040506, #090b0d 100%);
      }

      .dashboard-video-backdrop,
      .dashboard-video-backdrop video,
      .page-video-overlay,
      .page-video-fade {
        position: absolute;
        inset: 0;
      }

      .dashboard-video-backdrop {
        z-index: 0;
        overflow: hidden;
      }

      .dashboard-video-backdrop video {
        width: 100%;
        height: 100%;
        object-fit: cover;
        filter: grayscale(100%) brightness(0.32) contrast(1.04);
        transform: scale(1.05);
      }

      .page-video-overlay {
        background:
          linear-gradient(to bottom, rgba(1,1,2,0.22), rgba(1,1,2,0.58)),
          linear-gradient(to right, rgba(255,255,255,0.035), rgba(0,0,0,0.2));
      }

      .page-video-fade {
        background: radial-gradient(circle at center, rgba(255,255,255,0.08), rgba(0,0,0,0.22));
      }

      .dashboard-shell {
        position: relative;
        z-index: 1;
        min-height: 100vh;
        padding: 110px 28px 42px;
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

      .dashboard-stat-grid {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: 16px;
        margin-top: 26px;
      }

      .dashboard-stat {
        padding: 18px 20px;
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 22px;
        background: rgba(255, 255, 255, 0.03);
      }

      .dashboard-stat span {
        display: block;
        color: var(--text-sub);
        font-size: 12px;
        letter-spacing: 0.1em;
        text-transform: uppercase;
      }

      .dashboard-stat strong {
        display: block;
        margin-top: 10px;
        color: var(--text-title);
        font-size: clamp(26px, 4vw, 40px);
        letter-spacing: -0.04em;
      }

      .dashboard-stat p {
        margin-top: 10px;
        color: var(--text-sub);
        line-height: 1.7;
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

      .dashboard-form {
        display: flex;
        flex-direction: column;
        gap: 16px;
      }

      .dashboard-field {
        display: flex;
        flex-direction: column;
        gap: 8px;
      }

      .dashboard-field span {
        color: var(--text-sub);
        font-size: 14px;
      }

      .dashboard-input {
        width: 100%;
        min-height: 48px;
        padding: 0 14px;
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 16px;
        background: rgba(255, 255, 255, 0.04);
        color: var(--text-title);
      }

      select.dashboard-input {
        appearance: none;
        -webkit-appearance: none;
        color-scheme: dark;
        -webkit-tap-highlight-color: transparent;
        padding-right: 44px;
        background-color: rgba(8, 10, 12, 0.92);
        background-image:
          linear-gradient(45deg, transparent 50%, rgba(255, 255, 255, 0.82) 50%),
          linear-gradient(135deg, rgba(255, 255, 255, 0.82) 50%, transparent 50%);
        background-position:
          calc(100% - 18px) calc(50% - 3px),
          calc(100% - 12px) calc(50% - 3px);
        background-size: 6px 6px, 6px 6px;
        background-repeat: no-repeat;
      }

      select.dashboard-input:hover,
      select.dashboard-input:focus,
      select.dashboard-input:active,
      select.dashboard-input:focus-visible {
        background-color: rgba(8, 10, 12, 0.92);
        color: var(--text-title);
        outline: none;
        box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.16);
      }

      select.dashboard-input option {
        background: #0c1014;
        color: #f5f7fa;
      }

      .dashboard-input::placeholder {
        color: var(--text-dim);
      }

      .dashboard-check {
        display: flex;
        align-items: center;
        gap: 10px;
        color: var(--text-sub);
      }

      .dashboard-check input {
        width: 16px;
        height: 16px;
      }

      .dashboard-actions {
        display: flex;
        flex-wrap: wrap;
        gap: 12px;
        margin-top: 20px;
      }

      .dashboard-feed,
      .dashboard-activity {
        display: grid;
        gap: 12px;
      }

      .dashboard-feed-item,
      .dashboard-activity-item {
        padding: 14px 16px;
        border-radius: 16px;
        border: 1px solid rgba(255, 255, 255, 0.08);
        background: rgba(255, 255, 255, 0.026);
      }

      .dashboard-feed-item strong,
      .dashboard-activity-item strong {
        display: block;
        color: var(--text-title);
        font-size: 15px;
      }

      .dashboard-feed-item p,
      .dashboard-activity-item span,
      .dashboard-activity-item em {
        display: block;
        margin-top: 6px;
        color: var(--text-sub);
        line-height: 1.65;
        font-style: normal;
      }

      .dashboard-feed-item.success {
        border-color: rgba(52, 211, 153, 0.24);
        background: rgba(6, 95, 70, 0.18);
      }

      .dashboard-feed-item.danger {
        border-color: rgba(248, 113, 113, 0.24);
        background: rgba(127, 29, 29, 0.18);
      }

      .dashboard-activity-item {
        text-decoration: none;
      }

      .dashboard-activity-item:hover {
        transform: translateY(-1px);
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

      .dashboard-button.disconnect {
        background: rgba(190, 24, 24, 0.92);
        border-color: rgba(248, 113, 113, 0.42);
        color: #ffffff;
        box-shadow: 0 12px 28px rgba(127, 29, 29, 0.34);
      }

      .dashboard-button.disconnect:hover:not(:disabled) {
        background: rgba(220, 38, 38, 0.96);
        border-color: rgba(252, 165, 165, 0.56);
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
        top: 88px;
        right: 24px;
        z-index: 1400;
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
          padding: 92px 18px 18px;
        }

        .dashboard-stat-grid,
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
