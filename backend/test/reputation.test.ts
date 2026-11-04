import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encodeVirusTotalUrlId } from '../src/core/reputation.js';

test('VirusTotal URL identifiers are URL-safe base64 without padding', () => {
  const url = 'https://example.com/login?next=%2Faccount';
  const id = encodeVirusTotalUrlId(url);
  assert.equal(Buffer.from(id, 'base64url').toString('utf8'), url);
  assert.equal(id.includes('='), false);
  assert.match(id, /^[A-Za-z0-9_-]+$/);
});
