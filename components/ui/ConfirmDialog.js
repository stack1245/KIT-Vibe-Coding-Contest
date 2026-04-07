'use client';

export default function ConfirmDialog({
  open,
  eyebrow = '확인 필요',
  title,
  message,
  cancelLabel = '취소',
  confirmLabel = '확인',
  confirmVariant = 'danger',
  onCancel,
  onConfirm,
}) {
  if (!open) {
    return null;
  }

  return (
    <div className="ui-confirm">
      <div className="ui-confirm-backdrop" onClick={onCancel} />
      <div className="ui-confirm-card" role="dialog" aria-modal="true">
        <p className="ui-confirm-eyebrow">{eyebrow}</p>
        <h2 className="ui-confirm-title">{title}</h2>
        <p className="ui-confirm-message">{message}</p>
        <div className="ui-confirm-actions">
          <button type="button" className="dashboard-button secondary" onClick={onCancel}>{cancelLabel}</button>
          <button type="button" className={`dashboard-button ${confirmVariant}`} onClick={onConfirm}>{confirmLabel}</button>
        </div>
      </div>
    </div>
  );
}