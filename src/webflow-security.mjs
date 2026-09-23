import { createHmac, timingSafeEqual } from 'node:crypto';

/** Maximum age accepted for a Webflow webhook request. */
export const WEBHOOK_MAX_AGE_MS = 5 * 60 * 1000;

/**
 * Verify a Webflow webhook signature and reject stale requests.
 *
 * Webflow signs `${timestamp}:${body}` with SHA-256. OAuth-created webhooks
 * use the OAuth client secret; site-token webhooks use their webhook secret.
 *
 * @param {string} body Raw request body, before JSON parsing.
 * @param {string|undefined} timestamp Webflow's millisecond timestamp header.
 * @param {string|undefined} signature Webflow's hexadecimal HMAC header.
 * @param {string|undefined} secret Signing secret.
 * @param {number} [now=Date.now()] Clock value, injectable for tests.
 * @returns {boolean} Whether the signature is valid and recent.
 */
export function verifyWebflowSignature(body, timestamp, signature, secret, now = Date.now()) {
  const numericTimestamp = Number(timestamp);
  if (!secret || !signature || !Number.isFinite(numericTimestamp)) return false;
  if (Math.abs(now - numericTimestamp) > WEBHOOK_MAX_AGE_MS) return false;

  try {
    const expected = createHmac('sha256', secret)
      .update(`${numericTimestamp}:${body}`)
      .digest('hex');
    const actual = Buffer.from(signature, 'hex');
    const wanted = Buffer.from(expected, 'hex');
    return actual.length === wanted.length && timingSafeEqual(actual, wanted);
  } catch {
    // Invalid hex or malformed input must fail closed.
    return false;
  }
}
