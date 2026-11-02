import { parse } from 'parse5';
import { resolve4, resolve6, resolveMx, resolveNs } from 'node:dns/promises';
import { safeFetch } from './safe-fetch.js';
import { makeFinding } from './scoring.js';
import { config } from './config.js';
import type { Finding } from './types.js';

const attempt = async <T>(fn: () => Promise<T>): Promise<T | null> => { try { return await fn(); } catch { return null; } };
export async function analyzeTls(response: Awaited<ReturnType<typeof safeFetch>>, hostname: string, connectionError?:string) {
  if (!response.url.startsWith('https:')) return { available: true, httpsAvailable: false, valid: false, certificate: null, error: connectionError||'HTTPS was unavailable during the certificate probe.', findings:[makeFinding('ssl','medium','HTTPS is unavailable','The target did not complete an HTTPS connection.',[connectionError||'HTTPS probe did not receive a TLS response.'],'Enable HTTPS with a valid certificate.',0.8,'posture')] };
  const cert = response.certificate;
  const expiry = cert?.validTo ? Date.parse(String(cert.validTo)) : NaN;
  const valid = Boolean(response.tlsAuthorized) && Number.isFinite(expiry) && expiry > Date.now();
  const names=String(cert?.subjectAltName||'').split(',').map(v=>v.trim().replace(/^DNS:/i,'').toLowerCase());
  const host=hostname.toLowerCase();
  const sanMatch=names.some(name=>name===host||(name.startsWith('*.')&&host.endsWith(name.slice(1))&&host.split('.').length===name.split('.').length));
  const cn=String((cert?.subject as Record<string,string>|undefined)?.CN||'').toLowerCase();
  const hostMatches=Boolean(cert&&(sanMatch||(!names.length&&cn===host)));
  const findings: Finding[] = [];
  if (!valid) findings.push(makeFinding('ssl', 'high', 'TLS certificate is not valid', 'The HTTPS certificate could not be validated as trusted and current.', [String(cert?.validTo || response.tlsAuthorized === false ? 'Certificate validation failed.' : 'Certificate details unavailable.')], 'Renew or correctly configure the certificate.',0.8,'posture'));
  if (cert && !hostMatches) findings.push(makeFinding('ssl', 'high', 'Certificate hostname mismatch', 'The certificate identity does not match the scanned hostname.', [hostname, String(cert.subjectAltName || '')], 'Issue a certificate for the scanned hostname.',0.8,'posture'));
  if (Number.isFinite(expiry) && expiry - Date.now() < 14 * 86400000 && expiry > Date.now()) findings.push(makeFinding('ssl', 'medium', 'Certificate expires soon', 'The certificate expires within 14 days.', [String(cert?.validTo)], 'Renew the certificate before it expires.',0.8,'posture'));
  return { available: Boolean(cert), httpsAvailable: true, valid, hostnameMatches: hostMatches, certificate: cert || null, connectionError:response.tlsError||null, daysUntilExpiry: Number.isFinite(expiry) ? Math.floor((expiry-Date.now())/86400000) : null, findings };
}

export function summarizeRdap(rdap:Record<string,unknown>|null, now=Date.now()) {
  const events=Array.isArray(rdap?.events)?rdap.events as Array<Record<string,string>>:[];
  const registeredAt=events.find(e=>/registration|creation/i.test(e.eventAction||''))?.eventDate||null;
  const expiresAt=events.find(e=>/expiration/i.test(e.eventAction||''))?.eventDate||null;
  const registrar=(rdap?.entities as Array<Record<string,unknown>>|undefined)?.find(e=>(e.roles as string[]|undefined)?.includes('registrar'));
  const vcard=registrar?.vcardArray as unknown[]|undefined;
  const name=Array.isArray(vcard?.[1])?(vcard![1] as unknown[]).find(item=>Array.isArray(item)&&(item as unknown[])[0]==='fn') as unknown[]|undefined:undefined;
  const age=registeredAt?Math.max(0,(now-Date.parse(registeredAt))/(365.25*86400000)):null;
  return{registeredAt,expiresAt,registrar:name?.[3]?String(name[3]).slice(0,160):null,domainAgeYears:age===null?null:Math.round(age*10)/10};
}

export interface DomainIdentityEvidence {
  rdapAvailable: boolean;
  registeredAt: string | null;
  expiresAt: string | null;
  registrar: string | null;
  nameserverCount: number;
  dnssecEnabled: boolean;
  statuses: string[];
  certificateMatches: boolean;
}

/**
 * Estimates strength of domain-identity signals, not the legal identity of the
 * registrant. RDAP, DNS and a matching TLS certificate provide corroborating
 * technical signals; none independently proves that a business is legitimate.
 */
export function assessDomainIdentity(evidence: DomainIdentityEvidence, now=Date.now()): number | null {
  if (!evidence.rdapAvailable) return null;

  let score = 35;
  const registrationTime = evidence.registeredAt ? Date.parse(evidence.registeredAt) : NaN;
  const expiryTime = evidence.expiresAt ? Date.parse(evidence.expiresAt) : NaN;
  const ageYears = Number.isFinite(registrationTime)
    ? Math.max(0, (now - registrationTime) / (365.25 * 86400000))
    : null;
  const normalizedStatuses = evidence.statuses.map(status => status.toLowerCase().replace(/[\s_-]/g, ''));
  const hasHoldStatus = normalizedStatuses.some(status =>
    ['clienthold', 'serverhold', 'redemptionperiod', 'pendingdelete', 'inactive'].includes(status),
  );
  const hasActiveStatus = normalizedStatuses.some(status => status === 'active' || status === 'ok');

  if (Number.isFinite(registrationTime)) score += 10;
  if (evidence.registrar) score += 10;
  if (evidence.nameserverCount > 0) score += 10;
  if (hasActiveStatus) score += 5;
  if (evidence.dnssecEnabled) score += 5;
  if (evidence.certificateMatches) score += 15;

  if (ageYears !== null) {
    if (ageYears >= 5) score += 10;
    else if (ageYears >= 2) score += 5;
    else if (ageYears < 90 / 365.25) score -= 20;
    else if (ageYears < 1) score -= 10;
  }

  if (hasHoldStatus) score -= 35;
  if (Number.isFinite(expiryTime)) {
    if (expiryTime < now) score -= 25;
    else if (expiryTime - now < 30 * 86400000) score -= 5;
  }

  return Math.max(0, Math.min(100, Math.round(score)));
}

export async function analyzeDomain(hostname: string, certificateMatches = false) {
  const [a, aaaa, ns, mx, rdap] = await Promise.all([
    attempt(() => resolve4(hostname)), attempt(() => resolve6(hostname)), attempt(() => resolveNs(hostname)), attempt(() => resolveMx(hostname)),
    safeFetch(new URL(`https://rdap.org/domain/${encodeURIComponent(hostname)}`)).then(r => { try { return JSON.parse(r.body) as Record<string, unknown>; } catch { return null; } }).catch(() => null),
  ]);
  const rdapSummary=summarizeRdap(rdap);
  const nameservers=ns||[];
  const secureDNS = rdap?.secureDNS && typeof rdap.secureDNS === 'object'
    ? rdap.secureDNS as Record<string, unknown>
    : null;
  const statuses=Array.isArray(rdap?.status)?rdap.status.map(String):[];
  const dnssecEnabled=secureDNS?.delegationSigned===true;
  const identityEvidence:DomainIdentityEvidence={
    rdapAvailable:Boolean(rdap),
    registeredAt:rdapSummary.registeredAt,
    expiresAt:rdapSummary.expiresAt,
    registrar:rdapSummary.registrar,
    nameserverCount:nameservers.length,
    dnssecEnabled,
    statuses,
    certificateMatches,
  };
  const identityStrength=assessDomainIdentity(identityEvidence);
  const findings:Finding[]=[];
  if(identityEvidence.rdapAvailable && rdapSummary.domainAgeYears!==null && rdapSummary.domainAgeYears<90/365.25){
    findings.push(makeFinding('domain','medium','Very recently registered domain','RDAP registration data indicates that this domain was created within the last 90 days. Newness is a caution signal, not proof of maliciousness.',[String(rdapSummary.registeredAt)],'Independently verify the operator before entering credentials or making payments.',0.75,'context'));
  } else if(identityEvidence.rdapAvailable && rdapSummary.domainAgeYears!==null && rdapSummary.domainAgeYears<1){
    findings.push(makeFinding('domain','low','Recently registered domain','RDAP registration data indicates that this domain is less than one year old.',[String(rdapSummary.registeredAt)],'Use additional care with account and payment actions until the operator is established.',0.65,'context'));
  }
  const normalizedStatuses=statuses.map(status=>status.toLowerCase().replace(/[\s_-]/g,''));
  if(normalizedStatuses.some(status=>['clienthold','serverhold','redemptionperiod','pendingdelete','inactive'].includes(status))){
    findings.push(makeFinding('domain','high','Domain registration status needs review','RDAP reports a hold, redemption, pending-delete or inactive status for this domain.',statuses,'Verify the domain registration status with the registrar before trusting the site.',0.9,'posture'));
  }
  const expiryTime=rdapSummary.expiresAt?Date.parse(rdapSummary.expiresAt):NaN;
  if(Number.isFinite(expiryTime)&&expiryTime<Date.now()){
    findings.push(makeFinding('domain','high','Domain registration appears expired','The RDAP expiration date is in the past. Registration status and current control should be independently checked.',[String(rdapSummary.expiresAt)],'Verify current registration and ownership status with the registrar.',0.85,'posture'));
  }
  const identityAssessment=!identityEvidence.rdapAvailable
    ? 'RDAP registration records were unavailable; domain identity could not be assessed.'
    : normalizedStatuses.some(status=>['clienthold','serverhold','redemptionperiod','pendingdelete','inactive'].includes(status))
      ? 'RDAP reports a registration status that needs review.'
      : rdapSummary.domainAgeYears!==null&&rdapSummary.domainAgeYears<90/365.25
        ? 'The domain is newly registered. Treat this as a caution signal, not proof of maliciousness.'
        : certificateMatches
          ? 'RDAP registration data and a hostname-matching TLS certificate were observed. The registrant or business identity is not independently verified.'
          : 'RDAP registration data was found. A matching TLS domain-control signal was not confirmed, and the registrant or business identity is not independently verified.';
  return {
    available:Boolean(a||aaaa||ns||rdap),
    identityAvailable:Boolean(rdap),
    identityStrength,
    identityAssessment,
    identitySignals:{
      rdapRecord:Boolean(rdap),
      registrationDate:Boolean(rdapSummary.registeredAt),
      registrar:Boolean(rdapSummary.registrar),
      nameservers:nameservers.length,
      dnssecEnabled,
      certificateMatches,
      statuses,
    },
    ...rdapSummary,
    ipv4:a||[],
    ipv6:aaaa||[],
    nameservers,
    mailExchangers:mx||[],
    dnssec:secureDNS,
    rdapAvailable:Boolean(rdap),
    findings,
  };
}
export function analyzeHttp(response: Awaited<ReturnType<typeof safeFetch>>, initialUrl: URL) {
  const h = response.headers;
  const headers = { hsts: h['strict-transport-security'] || null, contentSecurityPolicy: h['content-security-policy'] || null, xFrameOptions: h['x-frame-options'] || null, xContentTypeOptions: h['x-content-type-options'] || null, referrerPolicy: h['referrer-policy'] || null, permissionsPolicy: h['permissions-policy'] || null };
  const findings: Finding[] = [];
  if(response.status>=500)findings.push(makeFinding('http','high','Server returned an error response','The target returned a server-side error status.',[`HTTP ${response.status}`],'Review server availability and response behavior.',0.8,'availability'));
  if(response.status>=400&&response.status<500)findings.push(makeFinding('http','info','Target returned a client error response','The target returned a 4xx status during inspection.',[`HTTP ${response.status}`],'Confirm the page is publicly accessible for a complete assessment.',0.8,'availability'));
  if (!headers.hsts && response.url.startsWith('https:')) findings.push(makeFinding('http','medium','HSTS header is missing','The response does not include Strict-Transport-Security.',[], 'Add an appropriate HSTS policy.',0.8,'posture'));
  if (!headers.contentSecurityPolicy) findings.push(makeFinding('http','low','Content Security Policy is missing','No Content-Security-Policy response header was observed.',[], 'Define a restrictive Content-Security-Policy.',0.8,'posture'));
  if (!headers.xContentTypeOptions) findings.push(makeFinding('http','low','Content type protection is missing','X-Content-Type-Options was not observed.',[], 'Set X-Content-Type-Options: nosniff.',0.8,'posture'));
  const redirectChain = [...response.redirects, response.url];
  const downgrade = redirectChain.some((u,i) => i > 0 && u.startsWith('http:') && redirectChain[i-1]?.startsWith('https:'));
  if (downgrade) findings.push(makeFinding('http','high','HTTPS redirect downgrade','The redirect chain returned to plaintext HTTP.',redirectChain,'Remove redirects that downgrade to HTTP.',0.8,'posture'));
  return { available:true, status:response.status, finalUrl:response.url, redirects:response.redirects, redirectCount:response.redirects.length, httpsRedirected:initialUrl.protocol==='http:' && response.url.startsWith('https:'), headers, findings };
}
interface Attr { name: string; value: string; }
interface HtmlNode { nodeName?: string; tagName?: string; value?: string; attrs?: Attr[]; childNodes?: HtmlNode[]; }
export function analyzeContent(html: string, baseUrl: string) {
  const doc = parse(html.slice(0, config.maxHtmlChars)) as unknown as HtmlNode;
  const forms: Array<{action:string; inputs:string[]; passwordFields:number}> = [];
  const scripts: string[] = [], inlineScripts: string[] = [], externalResources: string[] = [], links: Array<{text:string;href:string}> = [], downloads:string[]=[];
  const texts: string[] = [];
  const visibleTexts: string[] = [];
  const headings: string[] = [];
  let metaDescription = '';
  const nodeText = (node: HtmlNode): string => (node.value || '') + (node.childNodes || []).map(nodeText).join(' ');
  const walk = (node: HtmlNode, hiddenText = false) => {
    const tag = node.tagName?.toLowerCase(); const attrs = Object.fromEntries((node.attrs || []).map(a=>[a.name.toLowerCase(),a.value]));
    const skipVisibleText = hiddenText || ['script','style','noscript','svg','template'].includes(tag || '');
    if (node.value) { texts.push(node.value); if (!skipVisibleText) visibleTexts.push(node.value); }
    if (/^h[1-3]$/.test(tag || '')) { const heading = nodeText(node).replace(/\s+/g, ' ').trim(); if (heading) headings.push(heading.slice(0, 180)); }
    if (tag === 'meta') {
      const key = String(attrs.name || attrs.property || '').toLowerCase();
      if (!metaDescription && ['description','og:description','twitter:description'].includes(key) && attrs.content) metaDescription = String(attrs.content).replace(/\s+/g, ' ').slice(0, 500);
    }
    if (tag === 'form') {
      const inputs: string[]=[]; let passwords=0;
      const collect = (n:HtmlNode) => { if (n.tagName === 'input') { const t=(n.attrs||[]).find(a=>a.name==='type')?.value || 'text'; inputs.push(t); if(t.toLowerCase()==='password') passwords++; } for(const c of n.childNodes||[]) collect(c); };
      collect(node); forms.push({action:attrs.action||'',inputs,passwordFields:passwords});
    }
    if (tag === 'script' && attrs.src) scripts.push(attrs.src);
    if (tag === 'script' && !attrs.src) inlineScripts.push((node.childNodes||[]).map(c=>c.value||'').join(''));
    const linkText=(n:HtmlNode):string=>(n.value||'')+' '+(n.childNodes||[]).map(linkText).join(' ');
    if (['script','img','iframe','link','source'].includes(tag||'')) { const src=attrs.src||attrs.href; if(src) { try { const u=new URL(src,baseUrl); if(u.origin!==new URL(baseUrl).origin) externalResources.push(u.origin); } catch {} } }
    if (tag === 'a' && attrs.href) { links.push({text:linkText(node).trim().slice(0,120),href:attrs.href}); if(/\.(exe|msi|apk|dmg|zip|iso)(?:$|\?)/i.test(attrs.href)) downloads.push(attrs.href.slice(0,240)); }
    for(const c of node.childNodes||[]) walk(c, skipVisibleText);
  };
  walk(doc);
  const text = texts.join(' ').replace(/\s+/g,' ').slice(0, config.maxHtmlChars).toLowerCase();
  const findings: Finding[]=[];
  const credentialForms=forms.filter(f=>f.passwordFields>0);
  const pageTitle=(html.match(/<title[^>]*>([^<]*)/i)?.[1]||'').slice(0,200);
  const targetHost=new URL(baseUrl).hostname.toLowerCase();
  const trustedBrandDomains:Record<string,string[]> = {
    paypal:['paypal.com','paypal.in','paypal.co.uk'],
    google:['google.com','google.co.in','google.co.uk'],
    microsoft:['microsoft.com','live.com','office.com','outlook.com'],
    apple:['apple.com','icloud.com'],
    amazon:['amazon.com','amazon.in','amazon.co.uk','amazon.de'],
    coinbase:['coinbase.com'],
    binance:['binance.com'],
    metamask:['metamask.io'],
    facebook:['facebook.com'],
    instagram:['instagram.com'],
    netflix:['netflix.com'],
    steam:['steampowered.com','steamcommunity.com'],
    chase:['chase.com'],
    wise:['wise.com'],
  };
  const isBrandDomain=(hostname:string,brand:string)=>(
    trustedBrandDomains[brand]||[]
  ).some(domain=>hostname===domain||hostname.endsWith(`.${domain}`));
  const brands=Object.keys(trustedBrandDomains);
  const brandSignals=credentialForms.length
    ? brands.filter(brand=>pageTitle.toLowerCase().includes(brand)&&!isBrandDomain(targetHost,brand))
    : [];
  const externalCredentialForms=credentialForms.filter(form=>{try{return new URL(form.action,baseUrl).origin!==new URL(baseUrl).origin;}catch{return false;}});
  const suspiciousCredentialDestinations=externalCredentialForms.filter(form=>{
    try{
      const destination=new URL(form.action,baseUrl).hostname.toLowerCase();
      return !brandSignals.some(brand=>isBrandDomain(destination,brand));
    }catch{return true;}
  });
  if(credentialForms.length) findings.push(makeFinding('content','medium','Credential collection form detected','Password fields were found in the page markup; this is common on legitimate login pages and is not treated as proof of phishing.',credentialForms.map(f=>`Password inputs: ${f.passwordFields}; form action: ${f.action||'(same page)'}`),'Verify the operator and ensure credential submissions use an authorized endpoint.',0.5,'context'));
  if(externalCredentialForms.length)findings.push(makeFinding('content','medium','Credential form submits to another origin','A password form action resolves to a different origin than the scanned page. This can be legitimate SSO, but the destination should be verified.',externalCredentialForms.map(f=>f.action),'Confirm the destination is an authorized identity provider.',0.55,'context'));
  if(brandSignals.length)findings.push(makeFinding('content',suspiciousCredentialDestinations.length?'high':'medium','Possible brand impersonation signal','The page title names a known brand not present in the scanned hostname while also containing a credential form.',brandSignals.map(brand=>`Title references ${brand}; host is ${targetHost}`),'Verify that the domain is an official brand property before entering credentials.',suspiciousCredentialDestinations.length?0.88:0.68,'threat'));
  const suspiciousTerms=['verify your account','urgent action required','wallet seed phrase','your account will be suspended','confirm your password'];
  const matched=suspiciousTerms.filter(term=>text.includes(term));
  const obfuscated=inlineScripts.some(script=>{const lower=script.toLowerCase();return lower.includes('eval(')||lower.includes('atob(')||lower.includes('document.write');});
  const misleading=links.filter(link=>link.text.startsWith('http://')||link.text.startsWith('https://')).filter(link=>{try{return new URL(link.text).hostname!==new URL(link.href,baseUrl).hostname;}catch{return false;}});
  if(matched.length) findings.push(makeFinding('content','medium','Potentially deceptive language detected','The page contains language sometimes used in credential-harvesting lures. Context matters; a phrase by itself is not proof of maliciousness.',matched,'Review the context and avoid coercive or misleading account prompts.',0.45,'context'));
  if(obfuscated)findings.push(makeFinding('content','medium','Obfuscation-like script pattern detected','An inline script uses a dynamic evaluation or decoding pattern; this is an indicator for review, not proof of maliciousness.',['Inline script contains eval, atob, or document.write.'],'Review the script source and remove unnecessary obfuscation.',0.4,'context'));
  if(misleading.length)findings.push(makeFinding('content','medium','Visible URL differs from link destination','One or more links display a URL that differs from its destination host.',misleading.slice(0,5).map(l=>`${l.text} -> ${l.href}`),'Verify displayed link text and destination match.',0.55,'context'));
  const corroboratedPhishingSignals=
    (brandSignals.length>0 && suspiciousCredentialDestinations.length>0) ||
    (credentialForms.length>0 && matched.length>=2) ||
    (credentialForms.length>0 && misleading.length>0);
  if(corroboratedPhishingSignals){
    const evidence=[
      ...(brandSignals.length?[`Brand mismatch: ${brandSignals.join(', ')}`]:[]),
      ...(suspiciousCredentialDestinations.length?[`${suspiciousCredentialDestinations.length} credential form(s) submit to an unrelated external host`]:[]),
      ...(matched.length?[`Suspicious language: ${matched.join(', ')}`]:[]),
      ...(misleading.length?[`${misleading.length} visible URL(s) differ from their destination`]:[]),
    ];
    findings.push(makeFinding('content','high','Multiple phishing-like signals detected','Several independent indicators occur together: credential collection plus brand mismatch, multiple account-lure phrases, or deceptive link destinations. This combination warrants investigation but is not a malware verdict.',evidence,'Do not submit credentials or payment details until the site operator and destination domains are independently verified.',0.88,'threat'));
  }
  if(downloads.length)findings.push(makeFinding('content','low','Executable or archive download links found','The page links to file types that can carry executable or archived content. No files were downloaded.',downloads.slice(0,5),'Verify download links are expected and clearly identified.',0.35,'context'));
  const visibleTextExcerpt = visibleTexts.join(' ').replace(/\s+/g, ' ').trim().slice(0, 1600);
  return { available:true, title:pageTitle, metaDescription, headings:[...new Set(headings)].slice(0, 12), visibleTextExcerpt, brandSignals, externalCredentialForms:externalCredentialForms.length, forms:forms.length, credentialForms:credentialForms.length, scriptCount:scripts.length+inlineScripts.length, inlineScriptCount:inlineScripts.length, externalScriptCount:scripts.length, obfuscationPattern:obfuscated, suspiciousDownloads:downloads.slice(0,10), misleadingLinks:misleading.slice(0,10), scripts:scripts.slice(0,30), externalResourceOrigins:[...new Set(externalResources)].slice(0,40), linkCount:links.length, suspiciousTerms:matched, truncated:html.length>config.maxHtmlChars, findings };
}
