import 'server-only';
import path from 'node:path';

export const PROJECT_ROOT_DIR = /* turbopackIgnore: true */ process.cwd();
export const DATA_ROOT_DIR = path.join(/* turbopackIgnore: true */ process.cwd(), 'data');
export const DB_SCHEMA_FILE_PATH = path.join(/* turbopackIgnore: true */ process.cwd(), 'db', 'schema.sql');
export const DB_MIGRATIONS_DIR_PATH = path.join(/* turbopackIgnore: true */ process.cwd(), 'db', 'migrations');
export const UPLOAD_ROOT_DIR = path.join(/* turbopackIgnore: true */ process.cwd(), 'upload');

export function normalizeStoredUploadRelativePath(value = '') {
  return String(value || '')
    .trim()
    .replace(/^upload[\\/]/, '')
    .replace(/\\/g, '/');
}
