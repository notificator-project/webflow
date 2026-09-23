import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import test from 'node:test';
import { verifyWebflowSignature, WEBHOOK_MAX_AGE_MS } from '../src/webflow-security.mjs';

const body = JSON.stringify({ triggerType: 'form_submission' });
const secret = 'test-webflow-secret';
const timestamp = 1_700_000_000_000;
const signature = createHmac('sha256', secret).update(`${timestamp}:${body}`).digest('hex');

test('accepts a valid recent Webflow signature', () => {
  assert.equal(verifyWebflowSignature(body, String(timestamp), signature, secret, timestamp), true);
});

test('rejects a modified body', () => {
  assert.equal(
    verifyWebflowSignature(`${body}.`, String(timestamp), signature, secret, timestamp),
    false,
  );
});

test('rejects stale requests', () => {
  assert.equal(
    verifyWebflowSignature(
      body,
      String(timestamp),
      signature,
      secret,
      timestamp + WEBHOOK_MAX_AGE_MS + 1,
    ),
    false,
  );
});

test('rejects malformed signatures', () => {
  assert.equal(
    verifyWebflowSignature(body, String(timestamp), 'not-hex', secret, timestamp),
    false,
  );
});
