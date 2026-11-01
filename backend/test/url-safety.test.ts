import test from 'node:test'; import assert from 'node:assert/strict';
import { normalizeUrl,isPublicAddress,validateResolvedAddresses,ScanInputError } from '../src/core/url-safety.js';
test('normalizes hostname and accepts HTTP(S)',()=>{assert.equal(normalizeUrl('example.com').href,'https://example.com/');assert.equal(normalizeUrl('http://example.com').protocol,'http:');});
test('rejects non-HTTP, embedded credentials, local host and unusual ports',()=>{for(const value of ['file:///etc/passwd','http://user:pass@example.com','http://localhost','http://example.com:8080'])assert.throws(()=>normalizeUrl(value));});
test('rejects private, loopback, link-local, multicast and reserved targets',()=>{for(const address of ['127.0.0.1','10.0.0.1','172.16.0.1','192.168.1.1','169.254.169.254','224.0.0.1','::1','fc00::1','fe80::1'])assert.equal(isPublicAddress(address),false,address);});
test('rejects mixed public/private DNS answers to prevent rebinding',()=>{assert.throws(()=>validateResolvedAddresses([{address:'8.8.8.8',family:4},{address:'127.0.0.1',family:4}]),(e)=>e instanceof ScanInputError&&e.code==='SSRF_BLOCKED');});
test('accepts only all-public resolved addresses',()=>{assert.equal(validateResolvedAddresses([{address:'8.8.8.8',family:4}]).length,1);});
test('redirect target validation rejects a private destination before connecting',async()=>{const {validateRedirectTarget}=await import('../src/core/url-safety.js');await assert.rejects(()=>validateRedirectTarget('http://169.254.169.254/latest/meta-data/'));});
