import * as http from 'node:http';
import * as https from 'node:https';
import { config } from './config.js';
import { normalizeUrl, resolvePublic, validateRedirectTarget } from './url-safety.js';

export interface SafeResponse { url: string; status: number; headers: http.IncomingHttpHeaders; body: string; redirects: string[]; certificate?: Record<string, unknown>; tlsAuthorized?: boolean; tlsError?: string; }
export async function safeFetch(input: URL, redirectCount = 0, redirectTrail: string[] = [], extraHeaders: Record<string,string> = {}, followRedirects = true): Promise<SafeResponse> {
  const url = await validateRedirectTarget(input);
  const addresses = await resolvePublic(url.hostname.replace(/^\[|\]$/g,''));
  const pinned = addresses[0]!;
  const transport = url.protocol === 'https:' ? https : http;
  const result = await new Promise<SafeResponse>((resolve, reject) => {
    let connectTimer: NodeJS.Timeout | undefined;
    let connectedSocket: tlsSocket | undefined;
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
      const responseSocket = response.socket as tlsSocket | null;
      const chunks: Buffer[] = []; let bytes = 0;
      response.on('data', (chunk: Buffer) => {
        bytes += chunk.length;
        if (bytes > config.maxResponseBytes) { request.destroy(new Error('Response exceeded the configured size limit.')); return; }
        chunks.push(chunk);
      });
      response.on('error', reject);
      response.on('end', async () => {
        const status = response.statusCode || 0;
        const location = response.headers.location;
        if (followRedirects && [301,302,303,307,308].includes(status) && location) {
          if (redirectCount >= config.maxRedirects) { reject(new Error('Redirect limit exceeded.')); return; }
          try {
            const next = await validateRedirectTarget(new URL(location, url));
            resolve(await safeFetch(next, redirectCount + 1, [...redirectTrail, url.href], next.origin===url.origin?extraHeaders:{}));
          } catch (error) { reject(error); }
          return;
        }
        const socket = responseSocket ?? connectedSocket;
        const tls = url.protocol === 'https:' && socket ? socket : undefined;
        const cert = tls?.getPeerCertificate?.();
        resolve({ url: url.href, status, headers: response.headers, body: Buffer.concat(chunks).toString('utf8'), redirects: redirectTrail, certificate: cert && cert.subject ? { subject: cert.subject, issuer: cert.issuer, validFrom: cert.valid_from, validTo: cert.valid_to, fingerprint256: cert.fingerprint256, subjectAltName: cert.subjectaltname } : undefined, tlsAuthorized: tls?.authorized, tlsError: tls ? String(tls.authorizationError || '') || undefined : undefined });
      });
    });
    connectTimer=setTimeout(()=>request.destroy(new Error('Target connection timed out.')),config.connectTimeoutMs);
    request.on('socket',socket=>{connectedSocket = socket as tlsSocket; const ready=()=>{if(connectTimer)clearTimeout(connectTimer);};socket.once(url.protocol==='https:'?'secureConnect':'connect',ready);});
    request.on('timeout', () => request.destroy(new Error('Target request timed out.')));
    request.on('error', error=>{if(connectTimer)clearTimeout(connectTimer);reject(error);});
    request.end();
  });
  return result;
}
type tlsSocket = import('node:tls').TLSSocket;
