import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeBrandLookalikes } from '../src/core/lookalikes.js';

test('official Indian bank domains are not flagged as lookalikes', () => {
  const result = analyzeBrandLookalikes(new URL('https://www.sbi.co.in/'));
  assert.equal(result.findings.some(item => item.title.includes('lookalike') || item.title.includes('impersonation')), false);
});

test('brand lookalike domain plus credential context is a high-confidence threat', () => {
  const result = analyzeBrandLookalikes(
    new URL('https://paypa1-login.example.com/signin'),
    { title: 'PayPal secure login', credentialForms: 1 },
  );
  assert.equal(result.findings.some(item => item.signalType === 'threat' && item.severity === 'high'), true);
});

test('brand word only in the path is not enough to call a page phishing', () => {
  const result = analyzeBrandLookalikes(new URL('https://ordinary-example.com/paypal'));
  assert.equal(result.findings.some(item => item.signalType === 'threat'), false);
});

test('punycode hostnames create a caution signal rather than a malicious verdict', () => {
  const result = analyzeBrandLookalikes(new URL('https://xn--pple-43d.com/'));
  assert.equal(result.findings.some(item => item.title === 'Internationalized punycode hostname detected'), true);
  assert.equal(result.findings.some(item => item.signalType === 'threat'), false);
});
