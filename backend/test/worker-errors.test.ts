import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import { SafeFetchError } from '../src/core/safe-fetch.js';
import { describeScanFailure } from '../src/worker/errors.js';

test('target connection timeouts become an immediate actionable website error', () => {
  const failure = describeScanFailure(new SafeFetchError(new Error('Target connection timed out.'), {}));
  assert.equal(failure.code, 'TARGET_UNREACHABLE');
  assert.equal(failure.stage, 'Website could not be reached');
  assert.match(failure.message, /try a different website/i);
});

test('common network connection failures are classified as unreachable targets', () => {
  const cause = Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' });
  const failure = describeScanFailure(new SafeFetchError(cause, {}));
  assert.equal(failure.code, 'TARGET_UNREACHABLE');
});

test('unexpected worker failures get a clear non-technical retry instruction', () => {
  const failure = describeScanFailure(new Error('DynamoDB request failed'));
  assert.equal(failure.code, 'SCAN_FAILED');
  assert.match(failure.message, /enter a different website/i);
});
