import os
import re
import time
import math
import hashlib
import asyncio
import logging
from datetime import datetime
from urllib.parse import urlparse
 
import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
 
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phishguard")
 
MODEL_PATH    = "phishguard_model.pkl"
FEATURES_PATH = "feature_names (1).pkl"
 
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Model not found: {MODEL_PATH}")
if not os.path.exists(FEATURES_PATH):
    raise FileNotFoundError(f"Feature names not found: {FEATURES_PATH}")
 
model         = joblib.load(MODEL_PATH)
feature_names = joblib.load(FEATURES_PATH)
logger.info(f"Model loaded - expects {len(feature_names)} features")
 
_cache: dict = {}
_scan_history: list = []
 
app = FastAPI(title="PhishGuard API", version="1.0.0")
 
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
 
class ScanRequest(BaseModel):
    url: str
 
class ScanResponse(BaseModel):
    url: str
    verdict: str
    risk_score: float
    ml_confidence: float
    features_summary: dict
    scan_time_ms: float
    timestamp: str
 
SUSPICIOUS_TLDS = {'.xyz','.tk','.ml','.ga','.cf','.gq','.pw','.top','.click','.club','.work'}
BRAND_KEYWORDS  = ['paypal','google','amazon','apple','microsoft','netflix','facebook',
                   'instagram','bank','secure','chase','wellsfargo','ebay','dropbox']
URL_SHORTENERS  = ['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly']
PHISH_HINTS     = ['secure','account','update','login','signin','verify','banking',
                   'confirm','password','credit','wallet','alert','suspend']
 
def _entropy(s):
    if not s: return 0
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    return -sum((f/len(s)) * math.log2(f/len(s)) for f in freq.values())
 
def _safe_port(parsed):
    try:
        return 1 if parsed.port and parsed.port not in (80, 443) else 0
    except:
        return 0
 
def extract_features(url: str) -> dict:
    try:
        if not isinstance(url, str): url = ''
        url = url.strip()
        if not url.startswith('http'): url = 'http://' + url
        parsed   = urlparse(url)
        domain   = parsed.netloc.lower().replace('www.', '')
        path     = parsed.path
        query    = parsed.query
        hostname = parsed.netloc.lower()
    except:
        return {f: 0 for f in feature_names}
 
    parts      = domain.split('.')
    subdomains = parts[:-2] if len(parts) > 2 else []
    tld        = parts[-1] if parts else ''
 
    words_raw  = [w for w in re.split(r'[\W_]+', url)      if w]
    words_host = [w for w in re.split(r'[\W_]+', hostname) if w]
    words_path = [w for w in re.split(r'[\W_]+', path)     if w]
 
    char_repeat = max(
        (len(m.group(0)) for m in re.finditer(r'(.)\1+', url)), default=0
    )
 
    features = {
        'length_url':                 len(url),
        'length_hostname':            len(hostname),
        'ip':                         1 if re.match(r'\d+\.\d+\.\d+\.\d+', hostname) else 0,
        'nb_dots':                    url.count('.'),
        'nb_hyphens':                 url.count('-'),
        'nb_at':                      url.count('@'),
        'nb_qm':                      url.count('?'),
        'nb_and':                     url.count('&'),
        'nb_or':                      url.count('|'),
        'nb_eq':                      url.count('='),
        'nb_underscore':              url.count('_'),
        'nb_tilde':                   url.count('~'),
        'nb_percent':                 url.count('%'),
        'nb_slash':                   url.count('/'),
        'nb_star':                    url.count('*'),
        'nb_colon':                   url.count(':'),
        'nb_comma':                   url.count(','),
        'nb_semicolumn':              url.count(';'),
        'nb_dollar':                  url.count('$'),
        'nb_space':                   url.count(' ') + url.count('%20'),
        'nb_www':                     url.lower().count('www'),
        'nb_com':                     url.lower().count('.com'),
        'nb_dslash':                  url.count('//'),
        'http_in_path':               1 if 'http' in path.lower() else 0,
        'https_token':                1 if 'https' in domain else 0,
        'ratio_digits_url':           sum(c.isdigit() for c in url) / max(len(url), 1),
        'ratio_digits_host':          sum(c.isdigit() for c in hostname) / max(len(hostname), 1),
        'punycode':                   1 if 'xn--' in url.lower() else 0,
        'port':                       _safe_port(parsed),
        'tld_in_path':                1 if tld in path.lower() else 0,
        'tld_in_subdomain':           1 if tld in '.'.join(subdomains) else 0,
        'abnormal_subdomain':         1 if len(subdomains) > 2 else 0,
        'nb_subdomains':              len(subdomains),
        'prefix_suffix':              1 if '-' in domain else 0,
        'random_domain':              1 if _entropy(parts[0]) > 3.5 else 0,
        'shortening_service':         1 if any(s in domain for s in URL_SHORTENERS) else 0,
        'path_extension':             1 if re.search(r'\.(exe|zip|rar|js|php|bat|cmd)($|\?)', url.lower()) else 0,
        'nb_redirection':             max(url.count('//') - 1, 0),
        'nb_external_redirection':    0,
        'length_words_raw':           len(words_raw),
        'char_repeat':                char_repeat,
        'shortest_words_raw':         min((len(w) for w in words_raw),  default=0),
        'shortest_word_host':         min((len(w) for w in words_host), default=0),
        'shortest_word_path':         min((len(w) for w in words_path), default=0),
        'longest_words_raw':          max((len(w) for w in words_raw),  default=0),
        'longest_word_host':          max((len(w) for w in words_host), default=0),
        'longest_word_path':          max((len(w) for w in words_path), default=0),
        'avg_words_raw':              sum(len(w) for w in words_raw)  / max(len(words_raw),  1),
        'avg_word_host':              sum(len(w) for w in words_host) / max(len(words_host), 1),
        'avg_word_path':              sum(len(w) for w in words_path) / max(len(words_path), 1),
        'phish_hints':                sum(1 for h in PHISH_HINTS if h in url.lower()),
        'domain_in_brand':            1 if any(b.split('.')[0] in domain for b in ['google.com','amazon.com','paypal.com','apple.com','microsoft.com']) else 0,
        'brand_in_subdomain':         1 if any(b in '.'.join(subdomains) for b in BRAND_KEYWORDS) else 0,
        'brand_in_path':              1 if any(b in path.lower() for b in BRAND_KEYWORDS) else 0,
        'suspecious_tld':             1 if any(domain.endswith(t) for t in SUSPICIOUS_TLDS) else 0,
        'statistical_report':         0,
        'nb_hyperlinks':              0,
        'ratio_intHyperlinks':        0,
        'ratio_extHyperlinks':        0,
        'ratio_nullHyperlinks':       0,
        'nb_extCSS':                  0,
        'ratio_intRedirection':       0,
        'ratio_extRedirection':       0,
        'ratio_intErrors':            0,
        'ratio_extErrors':            0,
        'login_form':                 1 if any(x in url.lower() for x in ['login','signin','sign-in']) else 0,
        'external_favicon':           0,
        'links_in_tags':              0,
        'submit_email':               1 if 'mailto:' in url.lower() else 0,
        'ratio_intMedia':             0,
        'ratio_extMedia':             0,
        'sfh':                        0,
        'iframe':                     0,
        'popup_window':               0,
        'safe_anchor':                0,
        'onmouseover':                0,
        'right_clic':                 0,
        'empty_title':                0,
        'domain_in_title':            0,
        'domain_with_copyright':      0,
        'whois_registered_domain':    0,
        'domain_registration_length': 0,
        'domain_age':                 0,
        'web_traffic':                0,
        'dns_record':                 0,
        'google_index':               0,
        'page_rank':                  0,
    }
 
    return {f: features.get(f, 0) for f in feature_names}
 
 
def run_ml(url: str):
    feats = extract_features(url)
    row   = pd.DataFrame([feats])[feature_names].fillna(0)
    prob  = float(model.predict_proba(row)[0][1])
    return prob, feats
 
 
@app.get("/")
def root():
    return {"service": "PhishGuard", "status": "online", "version": "1.0.0"}
 
 
@app.get("/health")
def health():
    return {"status": "healthy", "model_features": len(feature_names), "cached": len(_cache)}
 
 
@app.post("/scan", response_model=ScanResponse)
async def scan_url(req: ScanRequest):
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
 
    cache_key = hashlib.md5(url.encode()).hexdigest()
    if cache_key in _cache:
        return _cache[cache_key]
 
    t0 = time.time()
    loop = asyncio.get_event_loop()
    ml_prob, feats = await loop.run_in_executor(None, run_ml, url)
 
    if ml_prob >= 0.7:
        verdict = "PHISHING"
    elif ml_prob >= 0.4:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"
 
    elapsed_ms = round((time.time() - t0) * 1000, 1)
 
    features_summary = {
        "length_url":         feats.get("length_url"),
        "nb_dots":            feats.get("nb_dots"),
        "nb_hyphens":         feats.get("nb_hyphens"),
        "has_ip":             bool(feats.get("ip")),
        "suspicious_tld":     bool(feats.get("suspecious_tld")),
        "brand_in_subdomain": bool(feats.get("brand_in_subdomain")),
        "phish_hints":        feats.get("phish_hints"),
        "random_domain":      bool(feats.get("random_domain")),
        "nb_subdomains":      feats.get("nb_subdomains"),
        "shortening_service": bool(feats.get("shortening_service")),
    }
 
    result = ScanResponse(
        url=url,
        verdict=verdict,
        risk_score=round(ml_prob, 4),
        ml_confidence=round(ml_prob, 4),
        features_summary=features_summary,
        scan_time_ms=elapsed_ms,
        timestamp=datetime.utcnow().isoformat() + "Z"
    )
 
    _cache[cache_key] = result
    _scan_history.append(result.dict())
    if len(_scan_history) > 1000:
        _scan_history.pop(0)
 
    logger.info(f"{verdict} ({ml_prob:.2f}) - {url} [{elapsed_ms}ms]")
    return result
 
 
@app.get("/history")
def get_history(limit: int = 50):
    return {"scans": _scan_history[-limit:], "total": len(_scan_history)}
 
 
@app.get("/stats")
def get_stats():
    if not _scan_history:
        return {"total": 0, "phishing": 0, "suspicious": 0, "safe": 0}
    verdicts = [s["verdict"] for s in _scan_history]
    return {
        "total":      len(verdicts),
        "phishing":   verdicts.count("PHISHING"),
        "suspicious": verdicts.count("SUSPICIOUS"),
        "safe":       verdicts.count("SAFE"),
    }