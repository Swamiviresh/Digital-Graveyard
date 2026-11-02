import type { Finding, ScanFactors, SecurityLevel, Severity, SignalType } from './types.js';

/**
 * Domain identity, suspicious content/behaviour, and provider reputation
 * account for 90% of the score. Visual polish is not measured. TLS identity is
 * important but comparatively light; routine response-header hardening has
 * deliberately low weight. Missing evidence is disclosed and limits confidence.
 */
export const FACTOR_WEIGHTS = {
  // Domain registration/identity and suspicious page behaviour dominate.
  domain: 0.35,
  content: 0.35,
  reputation: 0.20,
  ssl: 0.07,
  httpSecurity: 0.03,
} as const;

const CATEGORY_BY_FACTOR: Record<keyof ScanFactors, string> = {
  ssl: 'ssl',
  domain: 'domain',
  httpSecurity: 'http',
  content: 'content',
  reputation: 'reputation',
};

/**
 * Deductions from a factor's 100-point security-strength baseline.
 * A threat indicator has substantially more impact than a hardening advisory.
 * Context and availability observations are deliberately conservative.
 */
const SECURITY_DEDUCTIONS: Record<SignalType, Record<Severity, number>> = {
  threat:       { critical: 96, high: 76, medium: 44, low: 18, info: 0 },
  posture:      { critical: 72, high: 42, medium: 10, low: 3, info: 0 },
  context:      { critical: 55, high: 32, medium: 13, low: 4, info: 0 },
  availability: { critical: 16, high: 8, medium: 3, low: 1, info: 0 },
};

const clamp = (value: number, min = 0, max = 100): number =>
  Math.max(min, Math.min(max, Number.isFinite(value) ? value : min));

const severityPoints: Record<Severity, number> = {
  critical: 96,
  high: 76,
  medium: 44,
  low: 18,
  info: 0,
};

export function makeFinding(
  category: string,
  severity: Severity,
  title: string,
  description: string,
  evidence: string[],
  recommendation: string,
  confidence = 0.8,
  signalType: SignalType = 'threat',
): Finding {
  return {
    id: `${category}-${title}`.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''),
    category,
    severity,
    title,
    description,
    evidence: evidence.slice(0, 8),
    confidence: clamp(confidence, 0, 1),
    signalType,
    recommendation,
  };
}

function deductionForFinding(finding: Finding): number {
  const signalType = finding.signalType || 'threat';
  const severity = finding.severity;
  const confidence = clamp(finding.confidence ?? 0.65, 0, 1);
  return SECURITY_DEDUCTIONS[signalType][severity] * confidence;
}

/**
 * Combine findings in the same family with diminishing returns. This prevents
 * several correlated missing-header advisories from being counted as though
 * each were independent proof of malicious behaviour.
 */
function combineDeductions(values: number[]): number {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => b - a);
  const strongest = sorted[0] || 0;
  const supporting = sorted.slice(1).reduce((sum, value) => sum + value, 0);
  return clamp(strongest + supporting * 0.2);
}

/** Returns a 0-100 factor strength; higher always means stronger security. */
export function calculateFactorStrength(findings: Finding[]): number {
  const deductions = findings.map(deductionForFinding).filter(value => value > 0);
  return Math.round(clamp(100 - combineDeductions(deductions)));
}

export function classifySecurityLevel(score: number | null): SecurityLevel {
  if (score === null || !Number.isFinite(score)) return 'unknown';
  if (score < 20) return 'critical-risk';
  if (score < 40) return 'high-risk';
  if (score < 60) return 'moderate';
  if (score < 80) return 'good';
  return 'strong';
}

export function securityLevelLabel(level: SecurityLevel): string {
  const labels: Record<SecurityLevel, string> = {
    'critical-risk': 'CRITICAL RISK',
    'high-risk': 'HIGH RISK',
    moderate: 'MODERATE SECURITY',
    good: 'GOOD SECURITY',
    strong: 'STRONG SECURITY',
    unknown: 'INSUFFICIENT DATA',
  };
  return labels[level];
}

function threatScoreCeiling(finding: Finding): number | null {
  const signalType = finding.signalType || 'threat';
  const confidence = clamp(finding.confidence ?? 0.65, 0, 1);

  // High-confidence direct threat evidence must not be diluted by unrelated
  // clean categories. These are ceilings on the security score, not risk floors.
  if (signalType === 'threat') {
    if (finding.severity === 'critical' && confidence >= 0.8) return 8;
    if (finding.severity === 'high' && confidence >= 0.85) return 30;
    if (finding.severity === 'medium' && confidence >= 0.85) return 55;
    if (finding.severity === 'low' && confidence >= 0.95) return 72;
  }

  // Severe configuration failures are security concerns, but are not called
  // proof of phishing or malware in the absence of malicious-behaviour evidence.
  if (signalType === 'posture') {
    if (finding.severity === 'critical' && confidence >= 0.8) return 28;
    if (finding.severity === 'high' && confidence >= 0.8) return 55;
  }

  return null;
}

export function calculateSecurityScore(
  findings: Finding[],
  factors: ScanFactors,
): { securityScore: number | null; securityLevel: SecurityLevel; evidenceCoverage: number } {
  let weightedStrength = 0;
  let availableWeight = 0;
  let totalWeight = 0;

  for (const [key, weight] of Object.entries(FACTOR_WEIGHTS) as [keyof typeof FACTOR_WEIGHTS, number][]) {
    const factorValue = factors[key];
    totalWeight += weight;
    if (typeof factorValue !== 'number' || !Number.isFinite(factorValue)) continue;
    const bounded = clamp(factorValue);
    weightedStrength += bounded * weight;
    availableWeight += weight;
  }

  const evidenceCoverage = Math.round((availableWeight / totalWeight) * 100);
  if (availableWeight === 0) {
    return { securityScore: null, securityLevel: 'unknown', evidenceCoverage: 0 };
  }

  // Missing checks are not treated as malicious or as clean. Score the evidence
  // that exists, but cap the maximum score according to its coverage so an
  // 80%-covered scan cannot be presented as fully verified or strongly secure.
  let securityScore = Math.round(clamp(weightedStrength / availableWeight));
  const coverageCeiling = evidenceCoverage < 40 ? 39
    : evidenceCoverage < 60 ? 59
      : evidenceCoverage < 80 ? 69
        : evidenceCoverage < 90 ? 79
          : evidenceCoverage < 95 ? 89
            : evidenceCoverage < 100 ? 94
              : 100;
  securityScore = Math.min(securityScore, coverageCeiling);

  const applicableCeilings = findings
    .map(threatScoreCeiling)
    .filter((value): value is number => value !== null);

  if (applicableCeilings.length) {
    securityScore = Math.min(securityScore, ...applicableCeilings);
  }

  securityScore = Math.round(clamp(securityScore));
  return {
    securityScore,
    securityLevel: classifySecurityLevel(securityScore),
    evidenceCoverage,
  };
}

// Kept exported for tests and for callers that need the severity baseline.
export const BASE_SEVERITY_POINTS = severityPoints;
