import test from 'node:test';
import assert from 'node:assert/strict';
import { parseBedrockResult } from '../src/core/bedrock.js';

const validResult = {
  sitePurpose: 'The page appears to provide a public web search service.',
  safetyAssessment: 'Observed checks show a valid certificate and no listed malicious findings. Some checks were unavailable, so this is not a guarantee of safety.',
  verdict: 'The available evidence indicates a strong observed security posture.',
  positives: ['TLS present'],
  concerns: [],
  recommendations: ['Review unavailable reputation checks'],
  limitations: ['This is a passive scan of bounded page evidence.'],
};

test('validates Bedrock structured website-purpose and safety output', () => {
  const value = parseBedrockResult(JSON.stringify(validResult));
  assert.equal(value.verdict, validResult.verdict);
  assert.match(value.sitePurpose, /web search/);
  assert.match(value.safetyAssessment, /not a guarantee/);
});

test('rejects malformed or incomplete Bedrock output', () => {
  assert.throws(() => parseBedrockResult('not json'));
  const { safetyAssessment: _missingSafetyAssessment, ...missingSafety } = validResult;
  assert.throws(() => parseBedrockResult(JSON.stringify(missingSafety)));
  assert.throws(() => parseBedrockResult(JSON.stringify({ ...validResult, sitePurpose: '' })));
});
