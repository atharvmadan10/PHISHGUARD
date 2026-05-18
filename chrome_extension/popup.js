/// popup.js
 
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
 
function renderResult(data, url) {
  const color = getColorForVerdict(data.verdict);
  const riskPct = Math.round(data.risk_score * 100);
  const f = data.features_summary || {};
 
  const flags = [];
  if (f.has_ip)             flags.push(['IP in URL', 'bad']);
  if (f.suspicious_tld)     flags.push(['Suspicious TLD', 'bad']);
  if (f.brand_in_subdomain) flags.push(['Brand in subdomain', 'bad']);
  if (f.random_domain)      flags.push(['Random domain', 'bad']);
  if (f.shortening_service) flags.push(['URL Shortener', 'bad']);
  if (f.phish_hints > 0)    flags.push([`Phish hints: ${f.phish_hints}`, 'bad']);
  if (flags.length === 0)   flags.push(['No major threats', 'ok']);
 
  document.getElementById('content').innerHTML = `
    <div class="verdict-block">
      <div class="verdict-label verdict-${data.verdict}">${data.verdict}</div>
      <div class="risk-bar-wrap">
        <div class="risk-bar" style="width:${riskPct}%;background:${color}"></div>
      </div>
      <div class="score-text">Risk Score: ${riskPct}% &nbsp;|&nbsp; ML Confidence: ${riskPct}%</div>
    </div>
 
    <div class="section">
      <h3>Threat Signals</h3>
      <div>
        ${flags.map(([label, type]) =>
          `<span class="tag tag-${type}">${label}</span>`
        ).join('')}
      </div>
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
 
// Main
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const tab = tabs[0];
  if (!tab || !tab.url) { showError('No active tab found.'); return; }
 
  const url = tab.url;
 
  // Skip internal pages
  if (isInternalURL(url)) {
    showInternal();
    return;
  }
 
  fetch('http://localhost:8000/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  })
    .then(r => r.json())
    .then(d => renderResult(d, url))
    .catch(() => showError('Cannot reach PhishGuard API.'));
});