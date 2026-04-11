import 'server-only';
import crypto from 'node:crypto';

const ENCRYPTED_VALUE_PREFIX = 'enc:';

function getEncryptionSecret() {
  return String(
    process.env.GITHUB_TOKEN_ENCRYPTION_KEY
    || process.env.SECRET_STORAGE_KEY
    || process.env.SESSION_SECRET
    || '',
  ).trim();
}

function deriveEncryptionKey(secret) {
  return crypto.createHash('sha256').update(secret).digest();
}

export function encryptSecretValue(value) {
  const rawValue = String(value || '').trim();
  if (!rawValue) {
    return '';
  }

  const secret = getEncryptionSecret();
  if (!secret) {
    return rawValue;
  }

  const key = deriveEncryptionKey(secret);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(rawValue, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  return `${ENCRYPTED_VALUE_PREFIX}${iv.toString('base64url')}.${tag.toString('base64url')}.${encrypted.toString('base64url')}`;
}

export function decryptSecretValue(value) {
  const rawValue = String(value || '').trim();
  if (!rawValue) {
    return '';
  }

  if (!rawValue.startsWith(ENCRYPTED_VALUE_PREFIX)) {
    return rawValue;
  }

  const secret = getEncryptionSecret();
  if (!secret) {
    throw new Error('missing-secret-storage-key');
  }

  const serialized = rawValue.slice(ENCRYPTED_VALUE_PREFIX.length);
  const [ivText, tagText, encryptedText] = serialized.split('.');
  if (!ivText || !tagText || !encryptedText) {
    throw new Error('invalid-secret-storage-value');
  }

  const key = deriveEncryptionKey(secret);
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(ivText, 'base64url'),
  );
  decipher.setAuthTag(Buffer.from(tagText, 'base64url'));

  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(encryptedText, 'base64url')),
    decipher.final(),
  ]);

  return decrypted.toString('utf8');
}
