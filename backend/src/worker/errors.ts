import { SafeFetchError } from '../core/safe-fetch.js';

export interface ScanFailure {
  code: 'TARGET_UNREACHABLE' | 'SCAN_FAILED';
  stage: string;
  message: string;
}

/**
 * Convert internal worker errors into safe, actionable messages for the scanner UI.
 * Target connectivity failures are not retried through the long SQS visibility window:
 * the user can correct the URL or choose another website immediately.
 */
export function describeScanFailure(error: unknown): ScanFailure {
  const message = error instanceof Error ? error.message : String(error);
  const code = error instanceof SafeFetchError ? error.code || '' : '';
  const targetUnavailable =
    error instanceof SafeFetchError &&
    (
      /target (?:connection|request) timed out/i.test(message) ||
      ['ECONNREFUSED', 'ECONNRESET', 'EHOSTUNREACH', 'ENETUNREACH', 'ETIMEDOUT', 'EAI_AGAIN'].includes(code)
    );

  if (targetUnavailable) {
    return {
      code: 'TARGET_UNREACHABLE',
      stage: 'Website could not be reached',
      message: 'We could not connect to this website from our scanner. It may be offline, too slow to respond, or blocking automated requests. Check the URL or try a different website.',
    };
  }

  return {
    code: 'SCAN_FAILED',
    stage: 'Scan could not be completed',
    message: 'We could not complete this scan because an analysis step failed. Please try again, or enter a different website if the problem continues.',
  };
}
