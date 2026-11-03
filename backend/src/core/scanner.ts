import { normalizeUrl, ScanInputError } from './url-safety.js';
import { safeFetch, SafeFetchError } from './safe-fetch.js';
import type { SafeResponse, TlsEvidence } from './safe-fetch.js';
import { analyzeContent, analyzeDomain, analyzeHttp, analyzeTls } from './analyzers.js';
import { checkReputation } from './reputation.js';
import { calculateFactorStrength, calculateSecurityScore, securityLevelLabel } from './scoring.js';
import { explainEvidence } from './bedrock.js';
import type { EvidenceBundle, Finding, ScanReport } from './types.js';

export async function runScan(
  scanId: string,
  targetUrl: string,
  progress: (stage: string, value: number) => Promise<void>,
): Promise<ScanReport> {
  const target = normalizeUrl(targetUrl);
  const limitations: string[] = [];

  await progress('Resolving public target', 8);
  let response: Awaited<ReturnType<typeof safeFetch>>;
  try {
    response = await safeFetch(target);
  } catch (error) {
    if (error instanceof ScanInputError || target.protocol !== 'https:') throw error;
    const fallback = new URL(target.href);
    fallback.protocol = 'http:';
    fallback.port = '';
    try {
      response = await safeFetch(fallback);
    } catch {
      throw error;
    }
  }

  await progress('Inspecting TLS and HTTP security', 25);
  let tlsResponse: SafeResponse | null = response;
  let tlsEvidence: TlsEvidence | undefined;
  let tlsConnectionError: string | undefined;
  const submittedHost = target.hostname.replace(/^\[|\]$/g, '');
  const finalHost = new URL(response.url).hostname.replace(/^\[|\]$/g, '');

  // A redirect can move the content request to another host. Probe the original
  // submitted hostname directly (without following redirects) so its certificate
  // is never confused with the certificate of a redirect destination.
  if (target.protocol === 'http:' || !response.url.startsWith('https:') || finalHost !== submittedHost) {
    const probe = new URL(target.href);
    probe.protocol = 'https:';
    probe.port = '';
    tlsResponse = null;
    try {
      tlsResponse = await safeFetch(probe, 0, [], {}, false);
    } catch (error) {
      if (error instanceof ScanInputError) throw error;
      const message = error instanceof Error ? error.message : String(error);
      tlsConnectionError = error instanceof SafeFetchError && error.code
        ? `${error.code}: ${message}`
        : message;
      if (error instanceof SafeFetchError) tlsEvidence = error.tlsEvidence;
    }
  }

  const tls = await analyzeTls(tlsResponse, submittedHost, tlsConnectionError, tlsEvidence);
  const hostname = target.hostname.replace(/^\[|\]$/g, '');
  const domain = await analyzeDomain(hostname, Boolean(tls.valid && tls.hostnameMatches));
  const http = analyzeHttp(response, target);

  await progress('Parsing bounded page content', 47);
  const contentType = String(response.headers['content-type'] || '');
  const content = contentType.includes('text/html')
    ? analyzeContent(response.body, response.url)
    : { available: false, reason: 'Target response was not HTML.', findings: [] as Finding[] };

  await progress('Checking reputation providers', 62);
  const reputation = await checkReputation(target.hostname);
  const findings: Finding[] = [
    ...(tls.findings || []),
    ...(domain.findings || []),
    ...(http.findings || []),
    ...(content.findings || []),
    ...reputation.findings,
  ];

  if (!domain.identityAvailable) {
    limitations.push('RDAP registration identity evidence was unavailable; the registrant or business identity could not be assessed.');
  }
  if (!domain.available) limitations.push('Domain DNS and registration evidence were unavailable.');
  if (!reputation.result.available) {
    const providers = Array.isArray(reputation.result.providers)
      ? reputation.result.providers as Array<{ reason?: string }>
      : [];
    limitations.push(`Reputation check unavailable: ${providers.map(provider => provider.reason).filter(Boolean).join('; ') || 'provider did not return evidence'}`);
  }
  if (!tls.available) {
    const tlsReason = 'error' in tls && typeof tls.error === 'string' ? tls.error : 'no peer certificate was captured';
    limitations.push(`TLS certificate details were unavailable: ${tlsReason}`);
  }
  if (!content.available) {
    limitations.push('reason' in content ? String(content.reason) : 'Content analysis was unavailable.');
  }

  // Each factor is a strength score: 0 is weakest, 100 is strongest.
  const factors = {
    ssl: tls.available ? calculateFactorStrength(findings.filter(finding => finding.category === 'ssl')) : null,
    domain: domain.identityAvailable && typeof domain.identityStrength === 'number' ? domain.identityStrength : null,
    httpSecurity: http.available ? calculateFactorStrength(findings.filter(finding => finding.category === 'http')) : null,
    content: content.available ? calculateFactorStrength(findings.filter(finding => finding.category === 'content')) : null,
    reputation: reputation.result.available ? calculateFactorStrength(findings.filter(finding => finding.category === 'reputation')) : null,
  };

  const score = calculateSecurityScore(findings, factors);
  const evidence: EvidenceBundle = {
    targetUrl: target.href,
    ssl: tls,
    domain,
    http,
    content,
    reputation: reputation.result,
    findings,
    factors,
    ...score,
    limitations,
  };

  await progress('Generating evidence-based report', 78);
  let ai: ScanReport['ai'];
  try {
    ai = await explainEvidence(evidence);
  } catch {
    ai = {
      available: false,
      sitePurpose: 'title' in content && typeof content.title === 'string' && content.title.trim()
        ? `The page title is \"${String(content.title).slice(0, 160)}\", but an AI-generated description is unavailable.`
        : 'The purpose of this website could not be determined from the collected page content.',
      safetyAssessment: score.securityScore === null
        ? 'An AI safety assessment is unavailable, and the scan did not collect enough weighted evidence to calculate a security score.'
        : `AI assessment is unavailable. The deterministic security score is ${score.securityScore}/100 (${securityLevelLabel(score.securityLevel)}); review the findings and ${score.evidenceCoverage}% evidence coverage before relying on this result.`,
      verdict: 'Rule-based evidence summary only. Gemini did not return an AI explanation; the deterministic security score and collected evidence are shown separately.',
      positives: [],
      concerns: findings.slice(0, 5).map(finding => finding.title),
      recommendations: findings.map(finding => finding.recommendation).slice(0, 8),
      limitations: ['Gemini explanation unavailable or not configured.'],
    };
    limitations.push('Gemini explanation was unavailable; no AI-generated claims are included.');
  }

  const positives = Object.entries(factors)
    .filter(([, value]) => value !== null && value >= 85)
    .map(([key]) => `${key} checks showed strong security signals.`);
  const levelLabel = securityLevelLabel(score.securityLevel);
  const summary = score.securityScore === null
    ? `A security score could not be calculated because no weighted evidence checks returned usable data. Evidence coverage: ${score.evidenceCoverage}%.`
    : `Security score ${score.securityScore}/100 — ${levelLabel}. Evidence coverage: ${score.evidenceCoverage}%. ${findings.length} observations were recorded; unavailable checks are listed separately.`;

  return {
    scanId,
    targetUrl: target.href,
    scannedAt: new Date().toISOString(),
    status: 'COMPLETED',
    ...score,
    factors,
    summary,
    ssl: tls,
    domain,
    http,
    content,
    reputation: reputation.result,
    ai: {
      ...ai,
      positives: ai.positives.length ? ai.positives : positives,
      limitations: [...ai.limitations, ...limitations],
    },
    findings,
    limitations,
  };
}
