// popup.js - PhishGuard v2
 
function getColorForVerdict(verdict) {
  return { SAFE: '#22c55e', SUSPICIOUS: '#f59e0b', PHISHING: '#ef4444' }[verdict] || '#64748b';
}
 
function isInternalURL(url) {
  return (
    url.startsWith('chrome://') ||
    url.startsWith('chrome-extension://') ||
    url.startsWith('edge://') ||
    url.startsWith('about:') ||
    url.startsWith('file://') ||
    url === ''
  );
}
 
function buildSignals(data) {
  const signals = [];
  const f = data.features_summary || {};
 
  // CTI signals (highest priority)
  if (data.urlhaus_flagged)
    signals.push({ text: `URLhaus: ${data.urlhaus_threat || 'Blacklisted'}`, type: 'bad' });
 
  if (data.virustotal_detections > 0)
    signals.push({ text: `VirusTotal: ${data.virustotal_detections} detections`, type: 'bad' });
 
  if (data.typosquatting_target)
    signals.push({ text: `Typosquatting: looks like ${data.typosquatting_target}`, type: 'bad' });
 
  if (!data.dns_resolved)
    signals.push({ text: 'Domain does not resolve - possibly fake', type: 'bad' });
 
  if (data.whois_domain_age && data.whois_domain_age.includes('NEW'))
    signals.push({ text: `Newly registered: ${data.whois_domain_age}`, type: 'bad' });
 
  // ML-based signals from features
  if (f.has_ip)
    signals.push({ text: 'IP address used instead of domain name', type: 'bad' });
 
  if (f.suspicious_tld)
    signals.push({ text: 'Suspicious TLD (.xyz .tk .ml etc)', type: 'bad' });
 
  if (f.brand_in_subdomain)
    signals.push({ text: 'Brand name hidden in subdomain', type: 'bad' });
 
  if (f.random_domain)
    signals.push({ text: 'Randomly generated domain name', type: 'bad' });
 
  if (f.shortening_service)
    signals.push({ text: 'URL shortener used to hide destination', type: 'bad' });
 
  if (f.phish_hints > 0)
    signals.push({ text: `${f.phish_hints} phishing keyword(s) in URL`, type: 'bad' });
 
  if (f.nb_hyphens > 2)
    signals.push({ text: `Excessive hyphens in domain (${f.nb_hyphens})`, type: 'bad' });
 
  if (f.length_url > 100)
    signals.push({ text: `Unusually long URL (${f.length_url} chars)`, type: 'bad' });
 
  if (f.nb_subdomains > 2)
    signals.push({ text: `Too many subdomains (${f.nb_subdomains})`, type: 'bad' });
 
  // If ML says phishing but no specific signals found — explain why
  if (signals.length === 0 && data.verdict === 'PHISHING') {
    signals.push({ text: `ML model flagged URL pattern (${Math.round(data.ml_confidence * 100)}% confidence)`, type: 'bad' });
    signals.push({ text: 'URL structure matches known phishing patterns', type: 'bad' });
  }
 
  if (signals.length === 0 && data.verdict === 'SUSPICIOUS') {
    signals.push({ text: 'URL pattern partially matches suspicious signatures', type: 'warn' });
  }
 
  return signals;
}
 
function renderResult(data, url) {
  const color   = getColorForVerdict(data.verdict);
  const riskPct = Math.round(data.risk_score * 100);
  const mlPct   = Math.round(data.ml_confidence * 100);
  const f       = data.features_summary || {};
  const signals = buildSignals(data);
 
  const signalsHTML = signals.length > 0
    ? signals.map(s => `<span class="tag tag-${s.type === 'warn' ? 'warn' : 'bad'}">${s.text}</span>`).join('')
    : `<span class="tag tag-ok">No threats detected</span>`;
 
  document.getElementById('content').innerHTML = `
    <div class="verdict-block">
      <div class="verdict-label verdict-${data.verdict}">${data.verdict}</div>
      <div class="risk-bar-wrap">
        <div class="risk-bar" style="width:${riskPct}%;background:${color}"></div>
      </div>
      <div class="score-text">
        Risk Score: ${riskPct}% &nbsp;|&nbsp; ML Confidence: ${mlPct}%
      </div>
    </div>
 
    <div class="section">
      <h3>Threat Signals</h3>
      <div>${signalsHTML}</div>
    </div>
 
    <div class="section">
      <h3>CTI Intelligence</h3>
      <div class="feature-row">
        <span>URLhaus</span>
        <span class="val ${data.urlhaus_flagged ? 'val-bad' : 'val-ok'}">
          ${data.urlhaus_flagged ? 'BLACKLISTED' : 'Clean'}
        </span>
      </div>
      <div class="feature-row">
        <span>DNS</span>
        <span class="val ${data.dns_resolved ? 'val-ok' : 'val-bad'}">
          ${data.dns_resolved ? (data.dns_ip || 'Resolved') : 'Not resolved'}
        </span>
      </div>
      <div class="feature-row">
        <span>Domain Age</span>
        <span class="val ${data.whois_domain_age && data.whois_domain_age.includes('NEW') ? 'val-bad' : 'val-ok'}">
          ${data.whois_domain_age || 'Unknown'}
        </span>
      </div>
      <div class="feature-row">
        <span>Typosquatting</span>
        <span class="val ${data.typosquatting_target ? 'val-bad' : 'val-ok'}">
          ${data.typosquatting_target ? `Mimics ${data.typosquatting_target}` : 'None'}
        </span>
      </div>
      ${data.virustotal_detections !== null && data.virustotal_detections !== undefined ? `
      <div class="feature-row">
        <span>VirusTotal</span>
        <span class="val ${data.virustotal_detections > 0 ? 'val-bad' : 'val-ok'}">
          ${data.virustotal_detections} detections
        </span>
      </div>` : ''}
    </div>
 
    <div class="section">
      <h3>URL Features</h3>
      <div class="feature-row">
        <span>URL Length</span>
        <span class="val ${f.length_url > 75 ? 'val-bad' : 'val-ok'}">${f.length_url ?? 'N/A'}</span>
      </div>
      <div class="feature-row">
        <span>Dots in URL</span>
        <span class="val ${f.nb_dots > 4 ? 'val-bad' : 'val-ok'}">${f.nb_dots ?? 'N/A'}</span>
      </div>
      <div class="feature-row">
        <span>Hyphens</span>
        <span class="val ${f.nb_hyphens > 2 ? 'val-bad' : 'val-ok'}">${f.nb_hyphens ?? 'N/A'}</span>
      </div>
      <div class="feature-row">
        <span>Subdomains</span>
        <span class="val ${f.nb_subdomains > 2 ? 'val-bad' : 'val-ok'}">${f.nb_subdomains ?? 'N/A'}</span>
      </div>
      <div class="feature-row">
        <span>Phish Hints</span>
        <span class="val ${f.phish_hints > 0 ? 'val-bad' : 'val-ok'}">${f.phish_hints ?? 'N/A'}</span>
      </div>
    </div>
 
    <div class="url-text">${url}</div>
 
    <div class="footer">
      <span class="scan-time">Scanned in ${data.scan_time_ms}ms</span>
      <button class="rescan-btn" id="rescan-btn">Rescan</button>
    </div>
  `;
 
  document.getElementById('rescan-btn').addEventListener('click', () => {
    document.getElementById('content').innerHTML = `
      <div class="loading"><div class="spinner"></div>Rescanning...</div>`;
    fetch('http://localhost:8000/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    })
      .then(r => r.json())
      .then(d => renderResult(d, url))
      .catch(() => showError('Rescan failed.'));
  });
}
 
function showError(msg) {
  document.getElementById('content').innerHTML =
    `<div class="error">${msg}<br><small>Is the PhishGuard server running on port 8000?</small></div>`;
}
 
function showInternal() {
  document.getElementById('content').innerHTML = `
    <div style="text-align:center;padding:40px 20px;color:#64748b">
      <div style="font-size:32px;margin-bottom:12px">🛡️</div>
      <div style="font-size:14px;color:#94a3b8">PhishGuard does not scan<br>internal browser pages.</div>
      <div style="font-size:12px;margin-top:8px;color:#475569">Navigate to a website to scan it.</div>
    </div>
  `;
}
 
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const tab = tabs[0];
  if (!tab || !tab.url) { showError('No active tab found.'); return; }
  const url = tab.url;
  if (isInternalURL(url)) { showInternal(); return; }
 
  fetch('http://localhost:8000/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  })
    .then(r => r.json())
    .then(d => renderResult(d, url))
    .catch(() => showError('Cannot reach PhishGuard API.'));
});
