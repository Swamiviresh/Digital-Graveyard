import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import {
  calculateFactorStrength,
  calculateSecurityScore,
  FACTOR_WEIGHTS,
  makeFinding,
} from '../src/core/scoring.js';
import type { Finding, ScanFactors, Severity, SignalType } from '../src/core/types.js';

const completeCleanFactors: ScanFactors = {
  ssl: 100,
  domain: 100,
  httpSecurity: 100,
  content: 100,
  reputation: 100,
};

function finding(
  category: string,
  severity: Severity,
  signalType: SignalType,
  confidence = 0.8,
  title = `${signalType}-${severity}`,
): Finding {
  return makeFinding(category, severity, title, 'Test evidence.', [], 'Review this evidence.', confidence, signalType);
}

test('domain identity and suspicious behaviour dominate routine presentation hardening', () => {
  assert.equal(FACTOR_WEIGHTS.domain, 0.35);
  assert.equal(FACTOR_WEIGHTS.content, 0.35);
  assert.equal(FACTOR_WEIGHTS.reputation, 0.20);
  assert.equal(FACTOR_WEIGHTS.ssl, 0.07);
  assert.equal(FACTOR_WEIGHTS.httpSecurity, 0.03);
  assert.equal(Object.values(FACTOR_WEIGHTS).reduce((sum, weight) => sum + weight, 0), 1);
});

test('routine header findings barely move a fully covered clean score', () => {
  const headers = [
    finding('http', 'medium', 'posture', 0.8, 'HSTS header is missing'),
    finding('http', 'low', 'posture', 0.8, 'Content Security Policy is missing'),
    finding('http', 'low', 'posture', 0.8, 'Content type protection is missing'),
  ];
  const result = calculateSecurityScore(headers, {
    ...completeCleanFactors,
    httpSecurity: calculateFactorStrength(headers),
  });
  assert.ok((result.securityScore ?? 0) >= 99);
  assert.equal(result.evidenceCoverage, 100);
});

test('corroborated phishing behaviour sharply lowers an otherwise clean score', () => {
  const phishing = finding('content', 'high', 'threat', 0.88, 'Multiple phishing-like signals detected');
  const factors = { ...completeCleanFactors, content: calculateFactorStrength([phishing]) };
  const result = calculateSecurityScore([phishing], factors);
  assert.ok((result.securityScore ?? 100) <= 30);
  assert.equal(result.securityLevel, 'high-risk');
});

test('higher scores represent stronger security when all checks are clean', () => {
  const result = calculateSecurityScore([], completeCleanFactors);
  assert.deepEqual(result, { securityScore: 100, securityLevel: 'strong', evidenceCoverage: 100 });
});

test('routine hardening-header omissions have low weight and missing reputation limits score confidence', () => {
  const headerFindings = [
    finding('http', 'medium', 'posture', 0.8, 'HSTS header is missing'),
    finding('http', 'low', 'posture', 0.8, 'Content Security Policy is missing'),
    finding('http', 'low', 'posture', 0.8, 'Content type protection is missing'),
  ];
  const httpStrength = calculateFactorStrength(headerFindings);
  assert.ok(httpStrength >= 90, `Expected HTTP strength >= 90, got ${httpStrength}`);
  const result = calculateSecurityScore(headerFindings, {
    ssl: 100,
    domain: 100,
    httpSecurity: httpStrength,
    content: 100,
    reputation: null,
  });
  assert.equal(result.securityScore, 79);
  assert.equal(result.securityLevel, 'good');
  assert.equal(result.evidenceCoverage, 80);
});

test('a high-confidence critical malicious finding caps the security score', () => {
  const result = calculateSecurityScore(
    [finding('reputation', 'critical', 'threat', 0.97, 'Multiple feeds report confirmed malicious activity')],
    completeCleanFactors,
  );
  assert.ok((result.securityScore ?? 100) <= 8);
  assert.equal(result.securityLevel, 'critical-risk');
});

test('a high-confidence high malicious finding cannot be diluted by unrelated clean checks', () => {
  const result = calculateSecurityScore(
    [finding('reputation', 'high', 'threat', 0.9, 'Threat feed reports malicious detections')],
    completeCleanFactors,
  );
  assert.ok((result.securityScore ?? 100) <= 30);
  assert.equal(result.securityLevel, 'high-risk');
});

test('a high-severity TLS posture failure lowers security but is not called malicious proof', () => {
  const result = calculateSecurityScore(
    [finding('ssl', 'high', 'posture', 0.85, 'TLS certificate is not valid')],
    completeCleanFactors,
  );
  assert.ok((result.securityScore ?? 100) <= 55);
  assert.equal(result.securityLevel, 'moderate');
});

test('low-confidence heuristic findings do not trigger malicious-threat score ceilings', () => {
  const weakSignal = finding('content', 'medium', 'threat', 0.3, 'Uncorroborated possible impersonation');
  const factors = { ...completeCleanFactors, content: calculateFactorStrength([weakSignal]) };
  const result = calculateSecurityScore([weakSignal], factors);
  assert.ok((result.securityScore ?? 0) >= 80);
  assert.equal(result.securityLevel, 'strong');
});

test('unavailable evidence limits score confidence without being treated as malicious', () => {
  const result = calculateSecurityScore([], {
    ssl: 100,
    domain: 100,
    httpSecurity: 100,
    content: 100,
    reputation: null,
  });
  assert.equal(result.securityScore, 79);
  assert.equal(result.securityLevel, 'good');
  assert.equal(result.evidenceCoverage, 80);
});

test('no usable evidence returns unknown rather than falsely labelling the site unsafe', () => {
  const result = calculateSecurityScore([], {
    ssl: null,
    domain: null,
    httpSecurity: null,
    content: null,
    reputation: null,
  });
  assert.deepEqual(result, { securityScore: null, securityLevel: 'unknown', evidenceCoverage: 0 });
});
