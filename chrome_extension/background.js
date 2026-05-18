// background.js - PhishGuard Service Worker
const API_BASE = 'http://localhost:8000';
const cache = {};

async function scanURL(url) {
  if (!url) return null;
  if (url.startsWith('chrome://')) return null;
  if (url.startsWith('chrome-extension://')) return null;
  if (url.startsWith('about:')) return null;
  if (url.startsWith('edge://')) return null;

  if (cache[url]) return cache[url];

  try {
    const resp = await fetch(`${API_BASE}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    if (!resp.ok) return null;
    const data = await resp.json();
    cache[url] = data;
    return data;
  } catch(e) {
    console.error('PhishGuard API error:', e);
    return null;
  }
}

function setIcon(tabId, verdict) {
  const colors = {
    SAFE:       '#22c55e',
    SUSPICIOUS: '#f59e0b',
    PHISHING:   '#ef4444',
  };
  const color = colors[verdict] || '#64748b';

  chrome.action.setBadgeText({
    tabId,
    text: verdict === 'PHISHING' ? '!' : verdict === 'SUSPICIOUS' ? '?' : '',
  });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

function showWarningBanner(tabId, riskScore, verdict) {
  if (verdict !== 'PHISHING' && verdict !== 'SUSPICIOUS') return;

  const bgColor  = verdict === 'PHISHING' ? '#7f1d1d' : '#78350f';
  const emoji    = verdict === 'PHISHING' ? '🚨' : '⚠️';
  const message  = verdict === 'PHISHING'
    ? `This site has a ${Math.round(riskScore * 100)}% phishing risk score. Your data may be at risk!`
    : `This site looks suspicious with a ${Math.round(riskScore * 100)}% risk score. Proceed with caution.`;

  chrome.scripting.executeScript({
    target: { tabId },
    func: (bgColor, emoji, message, verdict) => {
      if (document.getElementById('phishguard-banner')) return;

      const banner = document.createElement('div');
      banner.id = 'phishguard-banner';
      banner.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        z-index: 2147483647;
        background: ${bgColor};
        color: #fff;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        padding: 12px 20px;
        font-size: 14px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        box-shadow: 0 2px 12px rgba(0,0,0,0.5);
        gap: 12px;
      `;

      banner.innerHTML = `
        <div style="display:flex;align-items:center;gap:10px">
          <span style="font-size:20px">${emoji}</span>
          <div>
            <strong>PhishGuard ${verdict} Warning</strong><br>
            <span style="font-size:13px;opacity:0.9">${message}</span>
          </div>
        </div>
        <button id="phishguard-dismiss" style="
          background: rgba(255,255,255,0.2);
          border: 1px solid rgba(255,255,255,0.4);
          color: #fff;
          padding: 6px 14px;
          cursor: pointer;
          border-radius: 6px;
          font-size: 13px;
          white-space: nowrap;
        ">Dismiss</button>
      `;

      document.body.insertBefore(banner, document.body.firstChild);
      document.body.style.marginTop = (banner.offsetHeight + 4) + 'px';

      document.getElementById('phishguard-dismiss').onclick = () => {
        banner.remove();
        document.body.style.marginTop = '';
      };
    },
    args: [bgColor, emoji, message, verdict],
  }).catch(err => console.warn('PhishGuard banner injection failed:', err));
}

// Watch every tab update
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete') return;
  if (!tab.url) return;

  const result = await scanURL(tab.url);
  if (!result) return;

  setIcon(tabId, result.verdict);

  // Store for popup
  chrome.storage.local.set({ [`scan_${tabId}`]: result });

  // Show banner for phishing or suspicious
  if (result.verdict === 'PHISHING' || result.verdict === 'SUSPICIOUS') {
    showWarningBanner(tabId, result.risk_score, result.verdict);
  }
});

// Handle messages from popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'GET_SCAN') {
    chrome.storage.local.get([`scan_${message.tabId}`], (data) => {
      sendResponse(data[`scan_${message.tabId}`] || null);
    });
    return true;
  }

  if (message.type === 'RESCAN') {
    delete cache[message.url];
    scanURL(message.url).then(sendResponse);
    return true;
  }
});
