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


import { matchOpenPhishIndicators } from '../src/core/reputation.js';

test('OpenPhish checks exact URL before hostname fallback', () => {
  const exact = new Set(['https://phish.example/login']);
  const hosts = new Set(['phish.example']);
  assert.equal(matchOpenPhishIndicators(exact, hosts, new URL('https://phish.example/login')), 'exact_url');
  assert.equal(matchOpenPhishIndicators(exact, hosts, new URL('https://phish.example/other')), 'hostname');
  assert.equal(matchOpenPhishIndicators(exact, hosts, new URL('https://clean.example/')), null);
});
