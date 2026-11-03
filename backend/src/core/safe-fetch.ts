import * as http from 'node:http';
import * as https from 'node:https';
import { config } from './config.js';
import { normalizeUrl, resolvePublic, validateRedirectTarget } from './url-safety.js';

export interface TlsEvidence {
  certificate?: Record<string, unknown>;
  tlsAuthorized?: boolean;
  tlsError?: string;
}

export interface SafeResponse extends TlsEvidence {
  url: string;
  status: number;
  headers: http.IncomingHttpHeaders;
  body: string;
  redirects: string[];
}

/** Preserve TLS details even if the HTTP request fails after the handshake. */
export class SafeFetchError extends Error {
  readonly code?: string;
  constructor(cause: unknown, readonly tlsEvidence: TlsEvidence) {
    super(cause instanceof Error ? cause.message : String(cause));
    this.name = 'SafeFetchError';
    const code = cause && typeof cause === 'object' && 'code' in cause
      ? (cause as { code?: unknown }).code
      : undefined;
    if (typeof code === 'string') this.code = code;
  }
}
export async function safeFetch(input: URL, redirectCount = 0, redirectTrail: string[] = [], extraHeaders: Record<string,string> = {}, followRedirects = true): Promise<SafeResponse> {
  const url = await validateRedirectTarget(input);
  const addresses = await resolvePublic(url.hostname.replace(/^\[|\]$/g,''));
  const pinned = addresses[0]!;
  const transport = url.protocol === 'https:' ? https : http;
  const result = await new Promise<SafeResponse>((resolve, reject) => {
    let connectTimer: NodeJS.Timeout | undefined;
    const tlsEvidence: TlsEvidence = {};
    const captureTlsEvidence = (socket: tlsSocket) => {
      const peer = socket.getPeerCertificate();
      const hasPeerCertificate = Boolean(
        peer && Object.keys(peer).length > 0 &&
        (peer.subject || peer.valid_to || peer.fingerprint256),
      );
      tlsEvidence.certificate = hasPeerCertificate ? {
        subject: peer.subject,
        issuer: peer.issuer,
        validFrom: peer.valid_from,
        validTo: peer.valid_to,
        fingerprint256: peer.fingerprint256,
        subjectAltName: peer.subjectaltname,
        serialNumber: peer.serialNumber,
      } : undefined;
      tlsEvidence.tlsAuthorized = socket.authorized;
      tlsEvidence.tlsError = socket.authorizationError
        ? String(socket.authorizationError)
        : undefined;
    };
    const request = transport.request(url, {
      method: 'GET', headers: { 'user-agent': 'DigitalGraveyardSecurityScanner/1.0 (+evidence-only)', accept: 'text/html,application/json;q=0.8,*/*;q=0.2', 'accept-encoding': 'identity', ...extraHeaders },
      timeout: config.requestTimeoutMs, ...(url.protocol === 'https:' ? { rejectUnauthorized: false } : {}),
      lookup: (_hostname, options, callback) => {
        if (options.all) {
          callback(null, [{ address: pinned.address, family: pinned.family }]);
        } else {
          callback(null, pinned.address, pinned.family);
        }
      },
      family: pinned.family,
    }, response => {
      const chunks: Buffer[] = []; let bytes = 0;
      response.on('data', (chunk: Buffer) => {
        bytes += chunk.length;
        if (bytes > config.maxResponseBytes) { request.destroy(new Error('Response exceeded the configured size limit.')); return; }
        chunks.push(chunk);
      });
      response.on('error', error => reject(new SafeFetchError(error, tlsEvidence)));
      response.on('end', async () => {
        const status = response.statusCode || 0;
        const location = response.headers.location;
        if (followRedirects && [301,302,303,307,308].includes(status) && location) {
          if (redirectCount >= config.maxRedirects) { reject(new SafeFetchError(new Error('Redirect limit exceeded.'), tlsEvidence)); return; }
          try {
            const next = await validateRedirectTarget(new URL(location, url));
            resolve(await safeFetch(next, redirectCount + 1, [...redirectTrail, url.href], next.origin===url.origin?extraHeaders:{}));
          } catch (error) { reject(error); }
          return;
        }
        resolve({
          url: url.href,
          status,
          headers: response.headers,
          body: Buffer.concat(chunks).toString('utf8'),
          redirects: redirectTrail,
          ...tlsEvidence,
        });
      });
    });
    connectTimer=setTimeout(()=>request.destroy(new Error('Target connection timed out.')),config.connectTimeoutMs);
    request.on('socket', socket => {
      const ready = () => { if (connectTimer) clearTimeout(connectTimer); };
      if (url.protocol === 'https:') {
        const secureSocket = socket as tlsSocket;
        const onSecureConnect = () => {
          captureTlsEvidence(secureSocket);
          ready();
        };
        secureSocket.once('secureConnect', onSecureConnect);
        // Reused, already-connected TLS sockets may have completed the handshake
        // before the request's socket listener is attached.
        if (!secureSocket.secureConnecting && !secureSocket.connecting) {
          captureTlsEvidence(secureSocket);
          ready();
        }
      } else {
        socket.once('connect', ready);
      }
    });
    request.on('timeout', () => request.destroy(new Error('Target request timed out.')));
    request.on('error', error => {
      if (connectTimer) clearTimeout(connectTimer);
      reject(new SafeFetchError(error, tlsEvidence));
    });
    request.end();
  });
  return result;
}
type tlsSocket = import('node:tls').TLSSocket;
