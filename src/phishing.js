import { API_BASE_URL } from './config.js';

const $ = (id) => document.getElementById(id);
const sleep = (ms) => new Promise((resolve) => window.setTimeout(resolve, ms));

function normalizeTarget(raw) {
  const value = String(raw || '').trim();
  if (!value || value.length > 2048) throw new Error('Enter a website URL under 2048 characters.');
  const candidate = /^[a-z][a-z\d+.-]*:\/\//i.test(value) ? value : `https://${value}`;
  let url;
  try { url = new URL(candidate); } catch { throw new Error('Enter a valid website address, such as https://example.com.'); }
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Only HTTP and HTTPS websites are supported.');
  if (url.username || url.password) throw new Error('URLs containing embedded credentials are not supported.');
  if (!url.hostname.includes('.') || url.hostname === 'localhost' || url.hostname.endsWith('.localhost')) throw new Error('Enter a public domain name.');
  if (url.port && !((url.protocol === 'http:' && url.port === '80') || (url.protocol === 'https:' && url.port === '443'))) throw new Error('Only standard HTTP and HTTPS ports are supported.');
  url.hash = '';
  return url;
}

function setError(message) {
  const box = $('phishing-error');
  box.textContent = message;
  box.classList.remove('hidden');
}

function setProgress(status) {
  const progress = Math.max(0, Math.min(100, Number(status.progress) || 0));
  $('phishing-stage').textContent = status.stage || 'Collecting website evidence…';
  $('phishing-percent').textContent = `${progress}%`;
  $('phishing-progress-bar').style.width = `${progress}%`;
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, { ...options, cache: 'no-store', signal: AbortSignal.timeout(20000) });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data?.error?.message || data?.message || `Request failed (${response.status}).`);
  return data;
}

async function runScan(target) {
  if (!API_BASE_URL) throw new Error('The live analysis API is not configured for this deployment.');
  const created = await requestJson(`${API_BASE_URL}/api/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: target.href }),
  });
  if (!created.scanId) throw new Error('The scan service did not return a scan ID.');

  for (let attempt = 0; attempt < 180; attempt += 1) {
    const status = await requestJson(`${API_BASE_URL}/api/scans/${encodeURIComponent(created.scanId)}`);
    setProgress(status);
    if (status.status === 'COMPLETED') {
      return requestJson(`${API_BASE_URL}/api/scans/${encodeURIComponent(created.scanId)}/report`);
    }
    if (status.status === 'FAILED') throw new Error(status.error?.message || 'The website scan failed.');
    await sleep(1500);
  }
  throw new Error(`The scan is still processing. Reopen the full scanner and check scan ID: ${created.scanId}`);
}

function phishingSignals(report) {
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const content = report.content && typeof report.content === 'object' ? report.content : {};
  const relevant = findings.filter((finding) => {
    const title = String(finding.title || '').toLowerCase();
    const category = String(finding.category || '').toLowerCase();
    return category === 'reputation'
      || /credential|brand impersonation|deceptive language|misleading link|recently registered domain|phishing|lookalike/i.test(title);
  });
  const signals = relevant.map((finding) => {
    const title = String(finding.title || 'Security indicator');
    const description = String(finding.description || 'A signal was observed during the website scan.');
    const evidence = Array.isArray(finding.evidence) ? finding.evidence : [];
    const severity = String(finding.severity || 'info').toLowerCase();
    let points = severity === 'critical' ? 34 : severity === 'high' ? 25 : severity === 'medium' ? 13 : severity === 'low' ? 6 : 0;
    if (/credential collection form/i.test(title)) points = Math.min(points, 8);
    if (/recently registered domain/i.test(title)) points = Math.min(points, 7);
    if (/possible brand impersonation/i.test(title)) points = Math.max(points, 22);
    return { title, description, evidence, severity, points };
  });
  if (Array.isArray(content.brandSignals) && content.brandSignals.length && !signals.some((s) => /brand impersonation/i.test(s.title))) {
    signals.push({ title: 'Possible brand impersonation', description: 'The page title references a known brand that is not present in the scanned hostname while a credential form is present.', evidence: content.brandSignals.map((brand) => `Brand reference: ${brand}`), severity: 'medium', points: 22 });
  }
  const unique = [...new Map(signals.map((signal) => [signal.title, signal])).values()];
  const score = Math.min(100, unique.reduce((total, signal) => total + signal.points, 0));
  return { signals: unique, score };
}

function appendTextList(container, values) {
  container.replaceChildren();
  (Array.isArray(values) ? values : []).slice(0, 6).forEach((value) => {
    const li = document.createElement('li');
    li.className = 'flex gap-2 leading-relaxed';
    const dot = document.createElement('span');
    dot.className = 'text-purple-300';
    dot.textContent = '›';
    const text = document.createElement('span');
    text.textContent = String(value);
    li.append(dot, text);
    container.append(li);
  });
}

function renderReport(report) {
  const { signals, score } = phishingSignals(report);
  const ai = report.ai && typeof report.ai === 'object' ? report.ai : {};
  const target = new URL(report.targetUrl);
  const level = score >= 60 ? 'High phishing signals' : score >= 30 ? 'Suspicious signals found' : score > 0 ? 'Some indicators need review' : 'No phishing indicators detected';
  $('phishing-score').textContent = String(score);
  $('phishing-score-bar').style.width = `${score}%`;
  $('phishing-score-bar').className = `phish-bar h-full rounded-full ${score >= 60 ? 'bg-red-400' : score >= 30 ? 'bg-orange-300' : 'bg-purple-300'}`;
  $('phishing-verdict').textContent = level;
  $('phishing-target').href = target.href;
  $('phishing-target').textContent = target.href;
  $('phishing-meta').textContent = `Scanned ${new Date(report.scannedAt).toLocaleString()} · ${target.hostname}`;
  $('phishing-indicator-count').textContent = `${signals.length} indicator${signals.length === 1 ? '' : 's'}`;
  $('phishing-ai-status').textContent = ai.available ? 'AI explanation available' : 'Rule-based summary';
  $('phishing-ai-summary').textContent = ai.available
    ? (ai.safetyAssessment || ai.verdict || 'The AI service did not return a summary.')
    : (ai.verdict || ai.safetyAssessment || 'AI explanation was unavailable. The findings below are based on deterministic checks.');
  appendTextList($('phishing-recommendations'), ai.recommendations);
  $('phishing-indicators').replaceChildren();
  signals.forEach((signal) => {
    const card = document.createElement('article');
    card.className = 'rounded-xl border border-white/10 bg-black/20 p-4';
    const header = document.createElement('div');
    header.className = 'flex items-start justify-between gap-3';
    const title = document.createElement('h3');
    title.className = 'text-sm font-semibold text-white';
    title.textContent = signal.title;
    const severity = document.createElement('span');
    severity.className = 'shrink-0 text-[9px] uppercase tracking-widest font-mono rounded-full px-2 py-1 border border-white/10 text-white/50';
    severity.textContent = signal.severity;
    header.append(title, severity);
    const description = document.createElement('p');
    description.className = 'text-xs leading-relaxed text-white/50 mt-3';
    description.textContent = signal.description;
    card.append(header, description);
    if (signal.evidence.length) {
      const evidence = document.createElement('p');
      evidence.className = 'text-[11px] leading-relaxed text-purple-200/60 font-mono mt-3 break-words';
      evidence.textContent = signal.evidence.slice(0, 3).join(' · ');
      card.append(evidence);
    }
    $('phishing-indicators').append(card);
  });
  $('phishing-no-indicators').classList.toggle('hidden', signals.length > 0);
  $('phishing-coverage').textContent = `Website scan evidence coverage: ${Number(report.evidenceCoverage) || 0}% · ${(report.limitations || []).length} scan limitation(s)`;
  $('phishing-results').classList.remove('hidden');
}

function initPhishingDetector() {
  const form = $('phishing-form');
  if (!form) return;
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    $('phishing-error').classList.add('hidden');
    $('phishing-results').classList.add('hidden');
    let target;
    try { target = normalizeTarget($('phishing-url').value); }
    catch (error) { setError(error instanceof Error ? error.message : 'Enter a valid website URL.'); return; }

    const button = $('phishing-submit');
    button.disabled = true;
    button.textContent = 'ANALYSING…';
    $('phishing-progress').classList.remove('hidden');
    $('phishing-progress-bar').style.width = '0%';
    try {
      const report = await runScan(target);
      renderReport(report);
      $('phishing-stage').textContent = 'Analysis complete';
      $('phishing-percent').textContent = '100%';
      $('phishing-progress-bar').style.width = '100%';
      $('phishing-results').scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Unable to complete the phishing assessment.');
    } finally {
      button.disabled = false;
      button.innerHTML = '<span class="inline-flex items-center gap-2"><span class="material-symbols-outlined text-base">shield_search</span> Analyse URL</span>';
    }
  });
}

initPhishingDetector();
