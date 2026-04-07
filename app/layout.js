import './globals.css';

export const metadata = {
  title: 'Phase Vuln Coach',
  description: 'Phase Vuln Coach Next.js application',
};

export default function RootLayout({ children }) {
  return (
    <html lang="ko">
      <body>{children}</body>
    </html>
  );
}