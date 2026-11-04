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

import { reputationConsensus } from '../src/core/reputation.js';
import { makeFinding } from '../src/core/scoring.js';

test('one clean feed is not enough to mark reputation clean', () => {
  const result = reputationConsensus([
    { name: 'Google Safe Browsing', available: true },
    { name: 'VirusTotal', available: false },
  ], []);
  assert.equal(result.available, false);
  assert.equal(result.activePrimarySources, 1);
});

test('an unanalysed VirusTotal URL is not counted as a clean source', () => {
  const result = reputationConsensus([
    { name: 'Google Safe Browsing', available: true },
    { name: 'VirusTotal', available: true, countsForConsensus: false },
  ], []);
  assert.equal(result.available, false);
  assert.equal(result.activePrimarySources, 1);
});

test('two independent clean providers provide reputation coverage', () => {
  const result = reputationConsensus([
    { name: 'Google Safe Browsing', available: true },
    { name: 'VirusTotal', available: true },
  ], []);
  assert.equal(result.available, true);
  assert.equal(result.activePrimarySources, 2);
});

test('one high-confidence known-bad match is actionable immediately', () => {
  const finding = makeFinding(
    'reputation', 'critical', 'Known phishing URL', 'Threat feed match.',
    ['fixture match'], 'Avoid the URL.', 0.97, 'threat',
  );
  const result = reputationConsensus([
    { name: 'Google Safe Browsing', available: true },
    { name: 'VirusTotal', available: false },
  ], [finding]);
  assert.equal(result.available, true);
});


import { googleSafeBrowsingThreatTypes, parseGoogleCacheDuration } from '../src/core/reputation.js';

test('Google Safe Browsing v5 keeps only requested phishing and malware threat types', () => {
  const types = googleSafeBrowsingThreatTypes({
    threats: [
      { threatTypes: ['SOCIAL_ENGINEERING'] },
      { threatTypes: ['MALWARE', 'UNWANTED_SOFTWARE'] },
    ],
  });
  assert.deepEqual(types.sort(), ['MALWARE', 'SOCIAL_ENGINEERING']);
});

test('Google Safe Browsing v5 parses server cache duration', () => {
  assert.equal(parseGoogleCacheDuration('3.5s'), 3);
  assert.equal(parseGoogleCacheDuration('bad-value', 300), 300);
});
