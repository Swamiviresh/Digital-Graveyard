export type ScanStatus = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type SignalType = 'threat' | 'posture' | 'context' | 'availability';
export type SecurityLevel = 'critical-risk' | 'high-risk' | 'moderate' | 'good' | 'strong' | 'unknown';

export interface Finding {
  id: string;
  category: string;
  severity: Severity;
  title: string;
  description: string;
  evidence: string[];
  confidence: number;
  recommendation: string;
  /** Malicious evidence, security posture, context, or service availability. */
  signalType?: SignalType;
}

export interface ScanFactors {
  ssl: number | null;
  domain: number | null;
  httpSecurity: number | null;
  content: number | null;
  reputation: number | null;
}

export interface ScanReport {
  scanId: string;
  targetUrl: string;
  scannedAt: string;
  status: 'COMPLETED';
  /** 0 = critical risk; 100 = strongest observed security. */
  securityScore: number | null;
  securityLevel: SecurityLevel;
  /** Percentage of weighted evidence families that returned usable data. */
  evidenceCoverage: number;
  factors: ScanFactors;
  summary: string;
  ssl: Record<string, unknown>;
  domain: Record<string, unknown>;
  http: Record<string, unknown>;
  content: Record<string, unknown>;
  reputation: Record<string, unknown>;
  ai: {
    available: boolean;
    sitePurpose: string;
    safetyAssessment: string;
    verdict: string;
    positives: string[];
    concerns: string[];
    recommendations: string[];
    limitations: string[];
  };
  findings: Finding[];
  limitations: string[];
}

export interface ScanRecord {
  scanId: string;
  targetUrl: string;
  hostname: string;
  status: ScanStatus;
  progress: number;
  stage: string;
  createdAt: string;
  updatedAt: string;
  ttl: number;
  report?: ScanReport;
  error?: { code: string; message: string };
}

export interface EvidenceBundle {
  targetUrl: string;
  ssl: Record<string, unknown>;
  domain: Record<string, unknown>;
  http: Record<string, unknown>;
  content: Record<string, unknown>;
  reputation: Record<string, unknown>;
  findings: Finding[];
  factors: ScanFactors;
  securityScore: number | null;
  securityLevel: SecurityLevel;
  evidenceCoverage: number;
  limitations: string[];
}
