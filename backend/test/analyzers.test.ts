import test from 'node:test'; import assert from 'node:assert/strict';
import { analyzeContent,analyzeHttp,analyzeTls,assessDomainIdentity } from '../src/core/analyzers.js';
test('TLS analysis catches invalid and hostname-mismatched certs',async()=>{const base={url:'https://example.com',status:200,headers:{},body:'',redirects:[],certificate:{subject:{CN:'other.test'},issuer:{CN:'CA'},validTo:new Date(Date.now()+86400000).toISOString(),subjectAltName:'DNS:other.test'},tlsAuthorized:false};const result=await analyzeTls(base,'example.com');assert.equal(result.valid,false);assert.equal(result.hostnameMatches,false);assert.ok(result.findings.length>=1);});
test('TLS analysis reports when HTTPS is unavailable',async()=>{const result=await analyzeTls({url:'http://example.com/',status:200,headers:{},body:'',redirects:[]},'example.com','connection refused');assert.equal(result.httpsAvailable,false);assert.equal(result.available,true);assert.equal(result.findings[0]?.title,'HTTPS is unavailable');});
test('HTTP analysis reports missing security headers and redirect downgrade',()=>{const r=analyzeHttp({url:'http://example.com',status:200,headers:{},body:'',redirects:['https://example.com']},new URL('http://example.com'));assert.equal(r.redirectCount,1);assert.ok(r.findings.some(f=>f.title.includes('downgrade')));});
test('HTTP analysis recognizes configured headers',()=>{const r=analyzeHttp({url:'https://example.com',status:200,headers:{'strict-transport-security':'max-age=31536000','content-security-policy':'default-src self','x-content-type-options':'nosniff'},body:'',redirects:[]},new URL('https://example.com'));assert.equal(r.findings.length,0);});
test('content parser finds password forms and lure language without executing scripts',()=>{const r=analyzeContent('<title>Example</title><form><input type="password"></form><p>Verify your account now</p><script>window.x=1</script>','https://example.com');assert.equal(r.credentialForms,1);assert.ok(r.findings.length);assert.equal(r.scriptCount,1);assert.equal(r.inlineScriptCount,1);assert.equal(r.externalScriptCount,0);});
test('content analyzer flags an explicit intentionally vulnerable scanner-test application',()=>{
  const html = '<title>Gin & Juice Shop</title><main><p>This is a deliberately vulnerable web application designed for testing web vulnerability scanners. Put your scanner to the test!</p></main>';
  const r = analyzeContent(html, 'https://example.com/');
  assert.equal(r.intentionalVulnerabilityDisclosure, true);
  const finding = r.findings.find(item => item.title === 'Site declares itself an intentionally vulnerable test application');
  assert.ok(finding);
  assert.equal(finding?.severity, 'high');
  assert.equal(finding?.signalType, 'posture');
  assert.ok((finding?.confidence || 0) >= 0.95);
});
test('ordinary security-training mentions do not trigger intentional-vulnerability classification',()=>{
  const r = analyzeContent('<title>Security Training</title><p>We provide security training and vulnerability scanner evaluation services.</p>', 'https://example.com/');
  assert.equal(r.intentionalVulnerabilityDisclosure, false);
});
test('domain analysis extracts registration age, expiry, and registrar from RDAP fixtures',async()=>{const {summarizeRdap}=await import('../src/core/analyzers.js');const base=Date.parse('2025-01-01T00:00:00Z');const v=summarizeRdap({events:[{eventAction:'registration',eventDate:'2020-01-01T00:00:00Z'},{eventAction:'expiration',eventDate:'2026-01-01T00:00:00Z'}],entities:[{roles:['registrar'],vcardArray:['vcard',[['fn',{},'text','Sample Registrar']]]}]},base);assert.equal(v.registeredAt,'2020-01-01T00:00:00Z');assert.equal(v.expiresAt,'2026-01-01T00:00:00Z');assert.equal(v.registrar,'Sample Registrar');assert.equal(v.domainAgeYears,5);});
test('content analyzer flags supported brand and off-origin credential evidence conservatively',()=>{const r=analyzeContent('<title>PayPal secure login</title><form action="https://collector.example/login"><input type="password"></form>','https://example.com');assert.ok(r.brandSignals.includes('paypal'));assert.equal(r.externalCredentialForms,1);assert.ok(r.findings.some(f=>f.title==='Possible brand impersonation signal'));assert.ok(r.findings.some(f=>f.title==='Credential form submits to another origin'));
assert.ok(r.findings.some(f=>f.title==='Multiple phishing-like signals detected'&&f.signalType==='threat'&&f.confidence>=0.85));});
test('domain identity rewards corroborated registration signals without claiming registrant verification',()=>{
  const mature=assessDomainIdentity({
    rdapAvailable:true,
    registeredAt:'2015-01-01T00:00:00Z',
    expiresAt:'2027-01-01T00:00:00Z',
    registrar:'Example Registrar',
    nameserverCount:2,
    dnssecEnabled:true,
    statuses:['active'],
    certificateMatches:true,
  },Date.parse('2026-11-02T00:00:00Z'));
  const newDomain=assessDomainIdentity({
    rdapAvailable:true,
    registeredAt:'2026-10-20T00:00:00Z',
    expiresAt:'2027-10-20T00:00:00Z',
    registrar:'Example Registrar',
    nameserverCount:2,
    dnssecEnabled:false,
    statuses:['active'],
    certificateMatches:true,
  },Date.parse('2026-11-02T00:00:00Z'));
  const held=assessDomainIdentity({
    rdapAvailable:true,
    registeredAt:'2015-01-01T00:00:00Z',
    expiresAt:'2027-01-01T00:00:00Z',
    registrar:'Example Registrar',
    nameserverCount:2,
    dnssecEnabled:true,
    statuses:['clientHold'],
    certificateMatches:true,
  },Date.parse('2026-11-02T00:00:00Z'));
  assert.equal(mature,100);
  assert.ok(newDomain!==null && newDomain<80);
  assert.ok(held!==null && held<mature);
  assert.equal(assessDomainIdentity({
    rdapAvailable:false,registeredAt:null,expiresAt:null,registrar:null,
    nameserverCount:2,dnssecEnabled:false,statuses:[],certificateMatches:false,
  }),null);
});
test('brand-name lookalike hostnames are not trusted merely because they contain the brand word',()=>{
  const r=analyzeContent('<title>PayPal secure login</title><form action="https://collector.example/login"><input type="password"></form>','https://paypal-login.example/');
  assert.ok(r.brandSignals.includes('paypal'));
  assert.ok(r.findings.some(f=>f.title==='Multiple phishing-like signals detected'));
});
test('official brand subdomains are not flagged as lookalikes by the hostname check',()=>{
  const r=analyzeContent('<title>Google account login</title><form action="/signin"><input type="password"></form>','https://accounts.google.com/');
  assert.equal(r.brandSignals.includes('google'),false);
});

test('TLS analysis can validate a captured certificate when the HTTP request fails after handshake', async () => {
  const certificate = {
    subject: { CN: 'www.google.com' },
    issuer: { CN: 'Example Trust Root' },
    validFrom: new Date(Date.now() - 86400000).toISOString(),
    validTo: new Date(Date.now() + 86400000).toISOString(),
    fingerprint256: 'AA:BB:CC',
    subjectAltName: 'DNS:google.com, DNS:www.google.com',
  };
  const result = await analyzeTls(
    null,
    'google.com',
    'ECONNRESET: peer closed after TLS handshake',
    { certificate, tlsAuthorized: true },
  );
  assert.equal(result.available, true);
  assert.equal(result.httpsAvailable, true);
  assert.equal(result.valid, true);
  assert.equal(result.hostnameMatches, true);
  assert.equal(result.connectionError, null);
  assert.equal('requestError' in result ? result.requestError : undefined, 'ECONNRESET: peer closed after TLS handshake');
});

test('TLS analysis keeps a failed handshake unavailable and preserves its diagnostic', async () => {
  const result = await analyzeTls(null, 'google.com', 'ETIMEDOUT: TLS probe timed out');
  assert.equal(result.available, false);
  assert.equal(result.valid, false);
  assert.ok('error' in result);
  assert.match(String('error' in result ? result.error : ''), /ETIMEDOUT/);
  assert.deepEqual(result.findings, []);
});
