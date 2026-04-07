'use client';

export default function Toast({ message, type = 'success' }) {
  return <div className={`ui-toast${message ? ` is-visible ${type}` : ''}`}>{message}</div>;
}