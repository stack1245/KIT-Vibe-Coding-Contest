const securityHeaders = [
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'X-Frame-Options', value: 'SAMEORIGIN' },
];

const allowedDevOrigins = [
  'localhost',
  '127.0.0.1',
  '144.91.91.44',
  ...String(process.env.NEXT_ALLOWED_DEV_ORIGINS || '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean),
];

const isDevelopment = process.env.NODE_ENV === 'development';
const outputFileTracingExcludes = {
  '/analysis': ['next.config.mjs'],
  '/api/analysis/upload': ['next.config.mjs'],
};

/** @type {import('next').NextConfig} */
const nextConfig = {
  distDir: isDevelopment ? '.next-webpack-dev' : '.next',
  allowedDevOrigins,
  deploymentId: process.env.DEPLOYMENT_VERSION || undefined,
  outputFileTracingExcludes,
  async headers() {
    return [
      {
        source: '/:path*',
        headers: securityHeaders,
      },
    ];
  },
};

export default nextConfig;
