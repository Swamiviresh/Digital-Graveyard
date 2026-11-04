import { createHash } from 'node:crypto';
import { GetSecretValueCommand, SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, PutCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { GetObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { config } from './config.js';
import { makeFinding } from './scoring.js';
import type { Finding } from './types.js';

export interface ProviderResult {
  available: boolean;
  reason?: string;
  data?: Record<string, unknown>;
  findings: Finding[];
}
export interface ReputationProvider {
  readonly name: string;
  readonly timeoutMs: number;
  check(url: URL, preliminaryFindings: Finding[]): Promise<ProviderResult>;
}
interface ProviderKeys {
  virusTotalApiKey?: string;
  googleSafeBrowsingApiKey?: string;
  urlhausAuthKey?: string;
  urlscanApiKey?: string;
}
const secrets = new SecretsManagerClient({ region: config.region, maxAttempts: 2 });
const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region: config.region }));
const s3 = new S3Client({ region: config.region });
let keyCache: { value: ProviderKeys; expiresAt: number } | undefined;
let pendingKeys: Promise<ProviderKeys> | undefined;
let feedCache: { exactUrls: Set<string>; hostnames: Set<string>; loadedAt: number; entryCount: number } | undefined;
let localUrlscanDay = '';
let localUrlscanCount = 0;

const unavailable = (reason: string): ProviderResult => ({ available: false, reason, findings: [] });
const noMatch = (name: string, data: Record<string, unknown> = {}): ProviderResult => ({
  available: true,
  data: { provider: name, matched: false, checkedAt: new Date().toISOString(), ...data },
  findings: [],
});

function knownBadFinding(provider: string, target: string, evidence: string[]): Finding {
  return makeFinding(
    'reputation',
    'critical',
    provider + ' reports this URL as malicious',
    'The submitted URL matched a known-bad entry in ' + provider + '. This is a threat-intelligence match, not a claim that every page on the domain is malicious.',
    evidence,
    'Do not enter credentials, payment details, or download files from this URL. Investigate the provider record and use a trusted route to reach the intended service.',
    0.97,
    'threat',
  );
}

async function getProviderKeys(): Promise<ProviderKeys> {
  if (keyCache && keyCache.expiresAt > Date.now()) return keyCache.value;
  if (pendingKeys) return pendingKeys;
  if (!config.reputationSecretArn) return {};
  pendingKeys = secrets.send(new GetSecretValueCommand({ SecretId: config.reputationSecretArn }))
    .then(result => {
      const raw = result.SecretString?.trim();
      if (!raw) throw new Error('The reputation credentials secret is empty.');
      const parsed = JSON.parse(raw) as ProviderKeys;
      keyCache = { value: parsed, expiresAt: Date.now() + 5 * 60 * 1000 };
      return parsed;
    })
    .finally(() => { pendingKeys = undefined; });
  return pendingKeys;
}

function digest(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

async function readCached(cacheKey: string): Promise<ProviderResult | null> {
  if (!config.reputationCacheTable) return null;
  try {
    const result = await ddb.send(new GetCommand({
      TableName: config.reputationCacheTable,
      Key: { cacheKey },
      ConsistentRead: false,
    }));
    const item = result.Item as { result?: ProviderResult; expiresAt?: number } | undefined;
    if (item?.result && Number(item.expiresAt || 0) > Math.floor(Date.now() / 1000)) {
      return { ...item.result, data: { ...(item.result.data || {}), cacheHit: true } };
    }
  } catch (error) {
    console.warn(JSON.stringify({ level: 'warn', component: 'reputation-cache', message: error instanceof Error ? error.message : 'Cache read failed' }));
  }
  return null;
}

async function writeCached(cacheKey: string, result: ProviderResult, ttlSeconds: number): Promise<void> {
  if (!config.reputationCacheTable || !result.available) return;
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + Math.max(1, Math.min(ttlSeconds, 86400));
  try {
    await ddb.send(new PutCommand({
      TableName: config.reputationCacheTable,
      Item: { cacheKey, result, checkedAt: now, expiresAt, ttl: expiresAt },
    }));
  } catch (error) {
    console.warn(JSON.stringify({ level: 'warn', component: 'reputation-cache', message: error instanceof Error ? error.message : 'Cache write failed' }));
  }
}

async function cached(
  providerKey: string,
  target: string,
  ttlSeconds: number,
  load: () => Promise<ProviderResult>,
): Promise<ProviderResult> {
  const cacheKey = providerKey + '#' + digest(target);
  const previous = await readCached(cacheKey);
  if (previous) return previous;
  const result = await load();
  if (result.available) {
    const responseTtl = typeof result.data?.cacheTtlSeconds === 'number' ? result.data.cacheTtlSeconds : ttlSeconds;
    await writeCached(cacheKey, result, Math.min(ttlSeconds, responseTtl));
  }
  return result;
}

async function fetchJson(url: string, init: RequestInit = {}, timeoutMs = 8000): Promise<{ response: Response; body: Record<string, unknown> }> {
  const response = await fetch(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
  const text = await response.text();
  let body: Record<string, unknown> = {};
  try {
    const parsed = JSON.parse(text) as unknown;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) body = parsed as Record<string, unknown>;
  } catch {
    body = {};
  }
  return { response, body };
}

export function parseGoogleCacheDuration(value: unknown, fallbackSeconds = 300): number {
  const match = typeof value === 'string' ? /^(\d+(?:\.\d+)?)s$/.exec(value.trim()) : null;
  if (!match) return fallbackSeconds;
  const seconds = Number(match[1]);
  return Number.isFinite(seconds) && seconds > 0 ? Math.max(1, Math.floor(seconds)) : fallbackSeconds;
}

export function googleSafeBrowsingThreatTypes(body: Record<string, unknown>): string[] {
  const supported = new Set(['SOCIAL_ENGINEERING', 'MALWARE']);
  const threats = Array.isArray(body.threats) ? body.threats as Array<Record<string, unknown>> : [];
  return [...new Set(threats.flatMap(threat =>
    Array.isArray(threat.threatTypes)
      ? threat.threatTypes.map(String).filter(type => supported.has(type))
      : [],
  ))];
}

export class GoogleSafeBrowsingProvider implements ReputationProvider {
  readonly name = 'Google Safe Browsing';
  readonly timeoutMs = 9000;
  async check(url: URL): Promise<ProviderResult> {
    if (containsSensitiveQuery(url)) return unavailable('Google Safe Browsing lookup was skipped because the URL query may contain a credential or personal identifier.');
    return cached('google-safe-browsing-v5', url.href, 1800, async () => {
      const keys = await getProviderKeys();
      if (!keys.googleSafeBrowsingApiKey) return unavailable('Google Safe Browsing API key is not configured.');
      const endpoint = new URL('https://safebrowsing.googleapis.com/v5/urls:search');
      endpoint.searchParams.set('key', keys.googleSafeBrowsingApiKey);
      endpoint.searchParams.append('urls', url.href);
      const result = await fetchJson(endpoint.toString(), { method: 'GET' });
      if (!result.response.ok) return unavailable('Google Safe Browsing v5 returned HTTP ' + result.response.status + '.');
      const threatTypes = googleSafeBrowsingThreatTypes(result.body);
      const cacheTtlSeconds = parseGoogleCacheDuration(result.body.cacheDuration, 300);
      if (!threatTypes.length) {
        return noMatch(this.name, {
          threatTypesChecked: ['SOCIAL_ENGINEERING', 'MALWARE'],
          checkedUrl: url.href,
          attributionRequired: false,
          cacheTtlSeconds,
          apiVersion: 'v5',
        });
      }
      return {
        available: true,
        data: {
          provider: this.name,
          matched: true,
          threatTypes,
          matchCount: threatTypes.length,
          checkedUrl: url.href,
          attributionRequired: true,
          attributionText: 'Advisory provided by Google',
          advisoryUrl: 'https://developers.google.com/safe-browsing/reference/Appropriate.Usage',
          cacheTtlSeconds,
          apiVersion: 'v5',
        },
        findings: [knownBadFinding(this.name, url.href, [
          'Matched threat types: ' + threatTypes.join(', '),
          'Google Safe Browsing v5 urls.search matched this URL.',
        ])],
      };
    });
  }
}

export function matchOpenPhishIndicators(exactUrls: Set<string>, hostnames: Set<string>, target: URL): 'exact_url' | 'hostname' | null {
  if (exactUrls.has(target.href)) return 'exact_url';
  if (hostnames.has(target.hostname.toLowerCase())) return 'hostname';
  return null;
}

export class OpenPhishProvider implements ReputationProvider {
  readonly name = 'OpenPhish Community Feed';
  readonly timeoutMs = 5000;

  private async getFeed() {
    if (!config.openPhishFeedBucket) throw new Error('OpenPhish feed bucket is not configured.');
    if (feedCache && Date.now() - feedCache.loadedAt < 5 * 60 * 1000) return feedCache;
    const object = await s3.send(new GetObjectCommand({
      Bucket: config.openPhishFeedBucket,
      Key: config.openPhishFeedKey,
    }));
    const text = await object.Body?.transformToString();
    if (!text) throw new Error('The latest OpenPhish feed snapshot is empty.');
    const exactUrls = new Set<string>();
    const hostnames = new Set<string>();
    for (const line of text.split(/\r?\n/)) {
      const value = line.trim();
      if (!value || value.startsWith('#')) continue;
      try {
        const parsed = new URL(value);
        if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
          exactUrls.add(parsed.href);
          hostnames.add(parsed.hostname.toLowerCase());
        }
      } catch {
        // Ignore malformed feed lines; preserve valid indicators.
      }
    }
    if (exactUrls.size === 0) throw new Error('OpenPhish feed contained no valid URLs.');
    feedCache = { exactUrls, hostnames, loadedAt: Date.now(), entryCount: exactUrls.size };
    return feedCache;
  }

  async check(url: URL): Promise<ProviderResult> {
    return cached('openphish', url.href, 6 * 60 * 60, async () => {
      try {
        const feed = await this.getFeed();
        const matchedBy = matchOpenPhishIndicators(feed.exactUrls, feed.hostnames, url);
        const exactMatch = matchedBy === 'exact_url';
        const hostnameMatch = matchedBy === 'hostname';
        if (!matchedBy) {
          return noMatch(this.name, {
            matchedBy: null,
            feedEntryCount: feed.entryCount,
            feedLoadedAt: new Date(feed.loadedAt).toISOString(),
          });
        }
        return {
          available: true,
          data: {
            provider: this.name,
            matched: true,
            matchedBy,
            matchedUrl: exactMatch ? url.href : null,
            matchedHostname: hostnameMatch ? url.hostname : null,
            feedEntryCount: feed.entryCount,
            feedLoadedAt: new Date(feed.loadedAt).toISOString(),
          },
          findings: [knownBadFinding(this.name, url.href, [
            exactMatch ? 'Exact submitted URL appears in the OpenPhish community feed.' : 'The submitted hostname appears in the OpenPhish community feed.',
            'Match method: ' + matchedBy,
          ])],
        };
      } catch (error) {
        return unavailable(error instanceof Error ? error.message : 'OpenPhish feed could not be read.');
      }
    });
  }
}


export function encodeVirusTotalUrlId(url: string): string {
  return Buffer.from(url, 'utf8').toString('base64url').replace(/=+$/, '');
}

export class VirusTotalProvider implements ReputationProvider {
  readonly name = 'VirusTotal';
  readonly timeoutMs = 9000;

  async check(url: URL): Promise<ProviderResult> {
    if (containsSensitiveQuery(url)) return unavailable('VirusTotal lookup was skipped because the URL query may contain a credential or personal identifier.');
    return cached('virustotal-url', url.href, 24 * 60 * 60, async () => {
      const keys = await getProviderKeys();
      if (!keys.virusTotalApiKey) return unavailable('VirusTotal API key is not configured.');
      const urlId = encodeVirusTotalUrlId(url.href);
      const result = await fetchJson('https://www.virustotal.com/api/v3/urls/' + encodeURIComponent(urlId), {
        headers: { 'x-apikey': keys.virusTotalApiKey },
      });
      if (result.response.status === 404) {
        return noMatch(this.name, {
          checkedUrl: url.href,
          noAnalysis: true,
          lookupStatus: 'not_previously_analyzed',
          cacheTtlSeconds: 6 * 60 * 60,
        });
      }
      if (!result.response.ok) return unavailable('VirusTotal returned HTTP ' + result.response.status + '.');
      const data = result.body.data && typeof result.body.data === 'object'
        ? result.body.data as Record<string, unknown>
        : {};
      const attributes = data.attributes && typeof data.attributes === 'object'
        ? data.attributes as Record<string, unknown>
        : {};
      const stats = attributes.last_analysis_stats && typeof attributes.last_analysis_stats === 'object'
        ? attributes.last_analysis_stats as Record<string, unknown>
        : null;
      if (!stats) return unavailable('VirusTotal returned no completed URL analysis statistics.');
      const counts = Object.values(stats).map(value => Number(value)).filter(value => Number.isFinite(value) && value >= 0);
      const total = counts.reduce((sum, value) => sum + value, 0);
      if (total <= 0) return unavailable('VirusTotal returned no completed engine results for this URL.');
      const malicious = Number(stats.malicious || 0);
      const suspicious = Number(stats.suspicious || 0);
      const findings: Finding[] = [];
      if (malicious > 0) {
        const ratio = malicious / total;
        const severity = malicious >= 5 || (total >= 20 && ratio >= 0.15)
          ? 'critical'
          : malicious >= 2 || (total >= 20 && ratio >= 0.05) ? 'high' : 'medium';
        const confidence = severity === 'critical' ? 0.97 : severity === 'high' ? 0.9 : 0.75;
        findings.push(makeFinding(
          'reputation',
          severity,
          'VirusTotal URL analysis reports malicious detections',
          'VirusTotal reports one or more malicious engine classifications for this exact URL. It is supporting reputation evidence; detection counts and engine coverage matter.',
          [malicious + ' malicious of ' + total + ' engines; ' + suspicious + ' suspicious', 'URL ID uses the unpadded base64url URL identifier.'],
          'Review the individual engine results and do not submit sensitive information until the detections are understood.',
          confidence,
          'threat',
        ));
      } else if (suspicious > 0) {
        findings.push(makeFinding(
          'reputation',
          suspicious >= 5 ? 'medium' : 'low',
          'VirusTotal URL analysis reports suspicious detections',
          'VirusTotal reported suspicious classifications for this URL. This is a supporting indicator, not proof that the site is malicious.',
          [suspicious + ' suspicious of ' + total + ' engines'],
          'Review provider results and confirm the domain owner before sensitive actions.',
          0.65,
          'threat',
        ));
      }
      return {
        available: true,
        data: {
          provider: this.name,
          matched: malicious > 0 || suspicious > 0,
          checkedUrl: url.href,
          urlId,
          stats,
          malicious,
          suspicious,
          total,
        },
        findings,
      };
    });
  }
}

export class UrlhausProvider implements ReputationProvider {
  readonly name = 'URLhaus';
  readonly timeoutMs = 9000;
  async check(url: URL): Promise<ProviderResult> {
    if (containsSensitiveQuery(url)) return unavailable('URLhaus lookup was skipped because the URL query may contain a credential or personal identifier.');
    return cached('urlhaus', url.href, 12 * 60 * 60, async () => {
      const keys = await getProviderKeys();
      if (!keys.urlhausAuthKey) return unavailable('URLhaus Auth-Key is not configured.');
      const form = new URLSearchParams({ url: url.href });
      const result = await fetchJson('https://urlhaus-api.abuse.ch/v1/url/', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', 'Auth-Key': keys.urlhausAuthKey },
        body: form.toString(),
      });
      if (!result.response.ok) return unavailable('URLhaus returned HTTP ' + result.response.status + '.');
      const queryStatus = String(result.body.query_status || '');
      if (queryStatus === 'no_results') return noMatch(this.name, { checkedUrl: url.href, queryStatus });
      if (queryStatus !== 'ok') return unavailable('URLhaus response status: ' + (queryStatus || 'unknown') + '.');
      return {
        available: true,
        data: {
          provider: this.name,
          matched: true,
          queryStatus,
          urlStatus: result.body.url_status || null,
          threat: result.body.threat || null,
          dateAdded: result.body.date_added || null,
          tags: Array.isArray(result.body.tags) ? result.body.tags.slice(0, 12) : [],
        },
        findings: [knownBadFinding(this.name, url.href, [
          'URLhaus query status: ' + queryStatus,
          'URL status: ' + String(result.body.url_status || 'not provided'),
          'Threat: ' + String(result.body.threat || 'malware-related URL'),
          'Date added: ' + String(result.body.date_added || 'not provided'),
        ])],
      };
    });
  }
}

function suspiciousPreliminaryEvidence(findings: Finding[]): boolean {
  return findings.some(finding =>
    (finding.signalType === 'threat' && finding.confidence >= 0.65) ||
    (finding.signalType === 'posture' && ['high', 'critical'].includes(finding.severity) && finding.confidence >= 0.8),
  );
}

function containsSensitiveQuery(url: URL): boolean {
  const sensitiveName = /token|auth|session|password|passwd|secret|api[_-]?key|^key$|code|email|phone|mobile|otp|jwt|signature|credential/i;
  if ([...url.searchParams.keys()].some(name => sensitiveName.test(name))) return true;
  return [...url.searchParams.values()].some(value =>
    value.includes('@') || /^[A-Za-z0-9_-]{28,}$/.test(value),
  );
}

function urlscanMalicious(result: Record<string, unknown>): boolean {
  const verdicts = result.verdicts && typeof result.verdicts === 'object' ? result.verdicts as Record<string, unknown> : {};
  const overall = verdicts.overall && typeof verdicts.overall === 'object' ? verdicts.overall as Record<string, unknown> : {};
  if (overall.malicious === true) return true;
  const categories = Array.isArray(overall.categories) ? overall.categories.map(String) : [];
  return categories.some(category => /phish|malware|credential|scam/i.test(category));
}

async function reserveUrlscanDailyBudget(): Promise<boolean> {
  const date = new Date().toISOString().slice(0, 10);
  const key = 'urlscan-submissions#' + date;
  const ttl = Math.floor(Date.now() / 1000) + 2 * 86400;
  if (config.reputationCacheTable) {
    try {
      await ddb.send(new UpdateCommand({
        TableName: config.reputationCacheTable,
        Key: { cacheKey: key },
        UpdateExpression: 'SET #ttl=:ttl ADD submissions :one',
        ConditionExpression: 'attribute_not_exists(submissions) OR submissions < :limit',
        ExpressionAttributeNames: { '#ttl': 'ttl' },
        ExpressionAttributeValues: { ':ttl': ttl, ':one': 1, ':limit': 40 },
      }));
      return true;
    } catch (error) {
      if ((error as { name?: string }).name === 'ConditionalCheckFailedException') return false;
      return false;
    }
  }
  if (localUrlscanDay !== date) {
    localUrlscanDay = date;
    localUrlscanCount = 0;
  }
  if (localUrlscanCount >= 40) return false;
  localUrlscanCount += 1;
  return true;
}

async function getUrlscanResult(uuid: string, apiKey: string): Promise<Record<string, unknown> | null> {
  const endpoint = 'https://urlscan.io/api/v1/result/' + encodeURIComponent(uuid) + '/';
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const result = await fetchJson(endpoint, { headers: { 'API-Key': apiKey } }, 9000);
    if (result.response.status === 200) return result.body;
    if (result.response.status !== 404) {
      if (result.response.status === 410) return null;
      throw new Error('urlscan.io result endpoint returned HTTP ' + result.response.status + '.');
    }
    await new Promise(resolve => setTimeout(resolve, 5000));
  }
  return null;
}

export class UrlscanProvider implements ReputationProvider {
  readonly name = 'urlscan.io';
  readonly timeoutMs = 70000;
  async check(url: URL, preliminaryFindings: Finding[]): Promise<ProviderResult> {
    return cached('urlscan', url.href, 24 * 60 * 60, async () => {
      if (!suspiciousPreliminaryEvidence(preliminaryFindings)) {
        return unavailable('Skipped to conserve the private-scan quota; no preliminary high-confidence suspicious signal was found.');
      }
      const keys = await getProviderKeys();
      if (!keys.urlscanApiKey) return unavailable('urlscan.io API key is not configured.');
      if (containsSensitiveQuery(url)) {
        return unavailable('Private browser analysis was skipped because the URL query contains a field that may carry a credential or personal identifier.');
      }
      const search = new URL('https://urlscan.io/api/v1/search/');
      search.searchParams.set('q', 'domain:' + url.hostname);
      search.searchParams.set('size', '3');
      search.searchParams.set('sort', 'task.time:desc');
      const searchResult = await fetchJson(search.toString(), { headers: { 'API-Key': keys.urlscanApiKey } });
      if (!searchResult.response.ok) return unavailable('urlscan.io search returned HTTP ' + searchResult.response.status + '.');
      const results = Array.isArray(searchResult.body.results)
        ? searchResult.body.results as Array<Record<string, unknown>>
        : [];
      const cutoff = Date.now() - 7 * 86400000;
      const recent = results.find(item => {
        const task = item.task && typeof item.task === 'object' ? item.task as Record<string, unknown> : {};
        const time = Date.parse(String(task.time || ''));
        return Number.isFinite(time) && time >= cutoff;
      });
      let result: Record<string, unknown> | null = null;
      let source: 'existing_scan' | 'new_private_scan' = 'existing_scan';
      let uuid = '';
      if (recent) {
        uuid = String(recent._id || '');
        if (!uuid) return unavailable('A recent urlscan.io record was found, but it did not include a result identifier.');
        const details = await fetchJson('https://urlscan.io/api/v1/result/' + encodeURIComponent(uuid) + '/', {
          headers: { 'API-Key': keys.urlscanApiKey },
        }, 9000);
        if (details.response.status !== 200) {
          return unavailable('A recent urlscan.io record exists, but its result could not be retrieved. Skipping a duplicate browser scan.');
        }
        result = details.body;
      }
      if (!recent) {
        if (!await reserveUrlscanDailyBudget()) return unavailable('The daily private urlscan.io submission safety limit has been reached.');
        source = 'new_private_scan';
        const submitted = await fetchJson('https://urlscan.io/api/v1/scan/', {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'API-Key': keys.urlscanApiKey },
          body: JSON.stringify({ url: url.href, visibility: 'private' }),
        }, 12000);
        if (!submitted.response.ok) return unavailable('urlscan.io submission returned HTTP ' + submitted.response.status + '.');
        uuid = String(submitted.body.uuid || '');
        if (!uuid) return unavailable('urlscan.io accepted the request without returning a scan ID.');
        await new Promise(resolve => setTimeout(resolve, 30000));
        result = await getUrlscanResult(uuid, keys.urlscanApiKey);
      }
      if (!result) return unavailable('urlscan.io accepted the scan, but its browser-rendered result was not ready before the worker timeout.');
      const task = result.task && typeof result.task === 'object' ? result.task as Record<string, unknown> : {};
      const page = result.page && typeof result.page === 'object' ? result.page as Record<string, unknown> : {};
      const malicious = urlscanMalicious(result);
      return {
        available: true,
        data: {
          provider: this.name,
          matched: malicious,
          source,
          uuid,
          resultUrl: 'https://urlscan.io/result/' + encodeURIComponent(uuid) + '/',
          visibility: source === 'new_private_scan' ? 'private' : 'existing result',
          pageTitle: typeof page.title === 'string' ? page.title.slice(0, 200) : null,
          pageDomain: page.domain || null,
          taskTime: task.time || null,
          malicious,
        },
        findings: malicious ? [knownBadFinding(this.name, url.href, [
          'urlscan.io browser analysis marked the result as malicious.',
          'Scan source: ' + source,
          'Result: https://urlscan.io/result/' + uuid + '/',
        ])] : [],
      };
    });
  }
}

export class CertificateTransparencyProvider implements ReputationProvider {
  readonly name = 'Certificate Transparency (crt.sh)';
  readonly timeoutMs = 6000;
  async check(url: URL): Promise<ProviderResult> {
    if (!config.enableCertificateTransparency) return unavailable('Optional Certificate Transparency lookup is disabled.');
    return cached('certificate-transparency', url.hostname, 24 * 60 * 60, async () => {
      const endpoint = new URL('https://crt.sh/');
      endpoint.searchParams.set('q', '%.' + url.hostname);
      endpoint.searchParams.set('output', 'json');
      const response = await fetch(endpoint.toString(), {
        headers: { 'user-agent': 'DigitalGraveyardSecurityScanner/1.0 (passive CT lookup)' },
        signal: AbortSignal.timeout(5500),
      });
      if (!response.ok) return unavailable('crt.sh returned HTTP ' + response.status + '.');
      let entries: Array<Record<string, unknown>>;
      try {
        entries = JSON.parse(await response.text()) as Array<Record<string, unknown>>;
      } catch {
        return unavailable('crt.sh returned an unreadable response.');
      }
      if (!Array.isArray(entries)) return unavailable('crt.sh returned an unexpected response.');
      const dates = entries.map(entry => Date.parse(String(entry.not_before || ''))).filter(value => Number.isFinite(value));
      if (!dates.length) return noMatch(this.name, { certificateEntries: entries.length, latestObservedIssuance: null });
      const latest = Math.max(...dates);
      const days = Math.floor((Date.now() - latest) / 86400000);
      const findings = days >= 0 && days <= 7 ? [makeFinding(
        'domain', 'low', 'Certificate Transparency shows a recently issued certificate',
        'crt.sh recorded a certificate for this hostname within the last seven days. Recent certificate issuance can occur during ordinary renewals and is not evidence of malicious activity by itself.',
        ['Latest observed not_before date: ' + new Date(latest).toISOString(), 'Days since issuance: ' + days],
        'Review recent DNS and certificate changes if this domain is unexpected.',
        0.6,
        'context',
      )] : [];
      return {
        available: true,
        data: {
          provider: this.name,
          matched: false,
          certificateEntries: entries.length,
          latestObservedIssuance: new Date(latest).toISOString(),
          daysSinceLatestIssuance: days,
        },
        findings,
      };
    });
  }
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, providerName: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => reject(new Error(providerName + ' timed out after ' + timeoutMs + 'ms.')), timeoutMs);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export function reputationConsensus(
  providers: Array<{ name: string; available: boolean; countsForConsensus?: boolean }>,
  findings: Finding[],
): { available: boolean; activePrimarySources: number; reason?: string } {
  const primary = new Set(['Google Safe Browsing', 'OpenPhish Community Feed', 'URLhaus', 'VirusTotal']);
  const activePrimarySources = providers.filter(provider => primary.has(provider.name) && provider.available && provider.countsForConsensus !== false).length;
  const providerReportedThreat = findings.some(finding =>
    finding.category === 'reputation' && finding.signalType === 'threat',
  );
  const available = providerReportedThreat || activePrimarySources >= 2;
  return {
    available,
    activePrimarySources,
    ...(!available ? {
      reason: activePrimarySources === 1
        ? 'Only one independent threat-intelligence source returned data; a single no-match is insufficient to call reputation clean.'
        : 'Fewer than two independent primary threat-intelligence sources returned usable evidence.',
    } : {}),
  };
}

export async function checkReputation(
  target: URL,
  preliminaryFindings: Finding[] = [],
): Promise<{ result: Record<string, unknown>; findings: Finding[] }> {
  const providers: ReputationProvider[] = [
    new GoogleSafeBrowsingProvider(),
    new OpenPhishProvider(),
    new UrlhausProvider(),
    new VirusTotalProvider(),
    new UrlscanProvider(),
    new CertificateTransparencyProvider(),
  ];
  const settled = await Promise.allSettled(providers.map(provider =>
    withTimeout(provider.check(target, preliminaryFindings), provider.timeoutMs, provider.name),
  ));
  const results = settled.map((item, index): ProviderResult => {
    if (item.status === 'fulfilled') return item.value;
    return unavailable(item.reason instanceof Error ? item.reason.message : providers[index]!.name + ' failed.');
  });
  const findings = results.flatMap(result => result.findings);
  const consensus = reputationConsensus(
    providers.map((provider, index) => ({
      name: provider.name,
      available: results[index]!.available,
      countsForConsensus: results[index]!.data?.noAnalysis !== true,
    })),
    findings,
  );
  const activePrimarySources = consensus.activePrimarySources;
  const reputationAvailable = consensus.available;
  const reason = consensus.reason;
  return {
    result: {
      available: reputationAvailable,
      ...(reason ? { reason } : {}),
      activePrimarySources,
      requiredPrimarySourcesForCleanResult: 2,
      checkedUrl: target.href,
      checkedAt: new Date().toISOString(),
      providers: results.map((result, index) => ({
        name: providers[index]!.name,
        available: result.available,
        ...(result.reason ? { reason: result.reason } : {}),
        ...(result.data || {}),
      })),
    },
    findings,
  };
}
