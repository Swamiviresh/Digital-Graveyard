import { domainToUnicode } from 'node:url';
import { distance } from 'fastest-levenshtein';
import { parse } from 'tldts';
import { makeFinding } from './scoring.js';
import type { Finding } from './types.js';
import { BRAND_DOMAINS } from './brand-domains.js';

export interface BrandIdentityAssessment {
  flagged: boolean;
  brand: string | null;
  displayName: string | null;
  matchTypes: string[];
  confidence: number;
  hostname: string;
  registrableDomain: string | null;
  unicodeHostname: string;
  findings: Finding[];
}

const normalizeLabel = (value: string): string => value.toLowerCase().replace(/[^a-z0-9]/g, '');

function isOfficialHost(hostname: string, domains: string[]): boolean {
  return domains.some(domain => hostname === domain || hostname.endsWith('.' + domain));
}

export function analyzeBrandLookalikes(
  url: URL,
  page: { title?: string; visibleTextExcerpt?: string; credentialForms?: number; externalCredentialForms?: number } = {},
): BrandIdentityAssessment {
  const hostname = url.hostname.toLowerCase().replace(/\.$/, '');
  const parsed = parse(hostname);
  const registrableDomain = parsed.domain || null;
  const rootLabel = normalizeLabel(parsed.domainWithoutSuffix || '');
  const subdomains = (parsed.subdomain || '').split('.').filter(Boolean);
  const path = decodeURIComponent(url.pathname).toLowerCase();
  const title = (page.title || '').toLowerCase();
  const visible = (page.visibleTextExcerpt || '').toLowerCase();
  const hasCredentials = Number(page.credentialForms || 0) > 0;
  const unicodeHostname = domainToUnicode(hostname);
  const punycode = hostname.split('.').some(label => label.startsWith('xn--'));
  const matchTypes: string[] = [];
  let matchedBrand: typeof BRAND_DOMAINS[number] | undefined;
  let bestDistance = Number.POSITIVE_INFINITY;
  let exactSubdomain = false;
  let pathMention = false;
  let titleMention = false;

  for (const brand of BRAND_DOMAINS) {
    if (isOfficialHost(hostname, brand.domains)) continue;
    const officialLabels = brand.domains
      .map(domain => normalizeLabel(parse(domain).domainWithoutSuffix || ''));
    const brandDistance = Math.min(...officialLabels.map(label => distance(rootLabel, label)));
    const threshold = rootLabel.length >= 8 ? 2 : 1;
    const closeDomain = rootLabel.length >= 4 && brandDistance > 0 && brandDistance <= threshold;
    const subdomainMention = subdomains.some(label => {
      const token = normalizeLabel(label);
      return token === brand.brand || (brand.brand.length >= 5 && token.includes(brand.brand));
    });
    const localPathMention = new RegExp('(?:^|[^a-z0-9])' + brand.brand + '(?:[^a-z0-9]|$)', 'i').test(path);
    const localTitleMention = title.includes(brand.brand) || visible.includes(brand.brand);
    if (closeDomain || subdomainMention || localPathMention || localTitleMention) {
      const rank = closeDomain ? brandDistance : subdomainMention ? 0 : localPathMention ? 3 : 4;
      if (!matchedBrand || rank < bestDistance) {
        matchedBrand = brand;
        bestDistance = rank;
        exactSubdomain = subdomainMention;
        pathMention = localPathMention;
        titleMention = localTitleMention;
      }
    }
  }

  const domainLookalike = Boolean(matchedBrand && bestDistance > 0 && bestDistance <= 2);
  const brandInSubdomain = Boolean(matchedBrand && exactSubdomain);
  const brandInPath = Boolean(matchedBrand && pathMention);
  const brandInPage = Boolean(matchedBrand && titleMention);
  let confidence = 0;
  if (matchedBrand && (domainLookalike || brandInSubdomain)) {
    confidence = domainLookalike && (hasCredentials || brandInPage) ? 0.93 : 0.82;
    matchTypes.push(domainLookalike ? 'registrable-domain edit distance ' + bestDistance : 'brand token in a non-official subdomain');
    if (brandInPage) matchTypes.push('brand name in page title or visible text');
    if (hasCredentials) matchTypes.push('password form present');
  } else if (matchedBrand && brandInPath && (hasCredentials || brandInPage)) {
    confidence = 0.72;
    matchTypes.push('brand name in URL path');
    if (hasCredentials) matchTypes.push('password form present');
    if (brandInPage) matchTypes.push('brand name in page title or visible text');
  } else {
    matchedBrand = undefined;
  }

  const findings: Finding[] = [];
  if (matchedBrand && confidence >= 0.8) {
    const corroborated = hasCredentials || brandInPage;
    findings.push(makeFinding(
      'content',
      corroborated ? 'high' : 'medium',
      corroborated ? 'Possible brand impersonation with credential context' : 'Possible brand lookalike hostname',
      'The hostname or URL path resembles a known brand but is not one of the maintained official domains. This is a heuristic signal and requires review; it is not proof of phishing.',
      ['Brand: ' + matchedBrand.displayName, 'Hostname: ' + hostname, ...matchTypes, 'Official domains checked: ' + matchedBrand.domains.join(', ')],
      'Verify the exact registrable domain against the brand’s official website before entering credentials or payment information.',
      confidence,
      corroborated ? 'threat' : 'context',
    ));
  }
  if (punycode) {
    findings.push(makeFinding(
      'content', 'low', 'Internationalized punycode hostname detected',
      'The hostname contains an IDN punycode label. Internationalized domains can be legitimate, but lookalike characters can be used in impersonation attempts.',
      ['ASCII hostname: ' + hostname, 'Unicode form: ' + unicodeHostname],
      'Check the displayed Unicode hostname carefully and compare its registrable domain with the official brand domain.',
      0.65,
      'context',
    ));
    matchTypes.push('punycode/IDN label');
  }
  return {
    flagged: Boolean(matchedBrand || punycode),
    brand: matchedBrand?.brand || null,
    displayName: matchedBrand?.displayName || null,
    matchTypes,
    confidence,
    hostname,
    registrableDomain,
    unicodeHostname,
    findings,
  };
}
