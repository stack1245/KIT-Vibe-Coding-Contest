import path from 'node:path';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: {
      'server-only': path.resolve(process.cwd(), 'tests/mocks/server-only.js'),
    },
  },
  test: {
    environment: 'node',
  },
});