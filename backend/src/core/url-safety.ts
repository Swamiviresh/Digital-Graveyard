import { lookup } from 'node:dns/promises';
import ipaddr from 'ipaddr.js';

export class ScanInputError extends Error {
  constructor(message: string, public statusCode = 400, public code = 'INVALID_URL') { super(message); }
}

export function normalizeUrl(input: unknown): URL {
  if (typeof input !== 'string' || input.length > 2048) throw new ScanInputError('Provide a URL under 2048 characters.');
  const raw = input.trim();
  const candidate = /^[a-z][a-z\d+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`;
  let url: URL;
  try { url = new URL(candidate); } catch { throw new ScanInputError('Enter a valid website URL.'); }
  if (!['http:', 'https:'].includes(url.protocol)) throw new ScanInputError('Only HTTP and HTTPS URLs are supported.');
  if (url.username || url.password) throw new ScanInputError('URLs containing credentials are not supported.');
  const host=url.hostname.replace(/^\[|\]$/g,'');
  if (!host || host.endsWith('.localhost') || host === 'localhost') throw new ScanInputError('Local and localhost targets are not allowed.');
  if (url.port && !((url.protocol==='http:'&&url.port==='80')||(url.protocol==='https:'&&url.port==='443'))) throw new ScanInputError('Only standard HTTP and HTTPS ports are allowed.');
  url.hash = '';
  return url;
}

export function isPublicAddress(address: string): boolean {
  try {
    const parsed = ipaddr.process(address);
    return parsed.range() === 'unicast';
  } catch { return false; }
}

export function validateResolvedAddresses(results: Array<{address:string;family:number}>): Array<{address:string;family:number}> {
  if (!results.length || results.some(item => !isPublicAddress(item.address))) throw new ScanInputError('The target resolves to a non-public or reserved address.', 400, 'SSRF_BLOCKED');
  return results;
}
export async function validateRedirectTarget(input: string | URL): Promise<URL> { const url=normalizeUrl(input instanceof URL?input.href:input); validateResolvedAddresses(await resolvePublic(url.hostname.replace(/^\[|\]$/g,''))); return url; }
export async function resolvePublic(hostname: string): Promise<Array<{ address: string; family: number }>> {
  if (ipaddr.isValid(hostname)) {
    const family = ipaddr.parse(hostname).kind() === 'ipv4' ? 4 : 6;
    if (!isPublicAddress(hostname)) throw new ScanInputError('The target resolves to a non-public address.', 400, 'SSRF_BLOCKED');
    return [{ address: hostname, family }];
  }
  let results: Awaited<ReturnType<typeof lookup>>[];
  try { results = await lookup(hostname, { all: true, verbatim: true }); }
  catch { throw new ScanInputError('The website hostname could not be resolved.', 422, 'DNS_LOOKUP_FAILED'); }
  return validateResolvedAddresses(results);
}
