import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';

function encryptionKey() {
  const value = process.env.WEBFLOW_ENCRYPTION_KEY?.trim();
  if (!value || !/^[a-f0-9]{64}$/i.test(value)) {
    throw new Error('WEBFLOW_ENCRYPTION_KEY must be a 32-byte hexadecimal key');
  }
  return Buffer.from(value, 'hex');
}

/** Encrypt a credential for server-side storage using AES-256-GCM. */
export function encryptSecret(value) {
  const iv = randomBytes(12);
  const cipher = createCipheriv(ALGORITHM, encryptionKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [iv, tag, ciphertext].map((part) => part.toString('base64url')).join('.');
}

/** Decrypt a credential previously returned by {@link encryptSecret}. */
export function decryptSecret(value) {
  const [ivEncoded, tagEncoded, ciphertextEncoded] = value.split('.');
  if (!ivEncoded || !tagEncoded || !ciphertextEncoded) throw new Error('Invalid encrypted secret');
  const decipher = createDecipheriv(
    ALGORITHM,
    encryptionKey(),
    Buffer.from(ivEncoded, 'base64url'),
  );
  decipher.setAuthTag(Buffer.from(tagEncoded, 'base64url'));
  return Buffer.concat([
    decipher.update(Buffer.from(ciphertextEncoded, 'base64url')),
    decipher.final(),
  ]).toString('utf8');
}
