import os
import re
import time
import math
import json
import hashlib
import asyncio
import logging
import socket
import urllib.parse
from datetime import datetime
from urllib.parse import urlparse, unquote
from typing import Optional
 
import joblib
import pandas as pd
import requests as req
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
 
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phishguard")
 
# -- Load model --
MODEL_PATH    = "phishguard_model.pkl"
FEATURES_PATH = "feature_names (1).pkl"
 
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Model not found: {MODEL_PATH}")
if not os.path.exists(FEATURES_PATH):
    raise FileNotFoundError(f"Feature names not found: {FEATURES_PATH}")
 
model         = joblib.load(MODEL_PATH)
feature_names = joblib.load(FEATURES_PATH)
logger.info(f"Model loaded - expects {len(feature_names)} features")
 
# -- Config --
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
URLHAUS_API        = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_HOST_API   = "https://urlhaus-api.abuse.ch/v1/host/"
 
# -- Cache --
_cache: dict        = {}
_scan_history: list = []
 
# -- App --
app = FastAPI(title="PhishGuard API", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
 
# -- Schemas --
class ScanRequest(BaseModel):
    url: str
    check_virustotal: bool = False
 
class ScanResponse(BaseModel):
    url: str
    decoded_url: Optional[str]
    obfuscation_techniques: list
    verdict: str
    risk_score: float
    ml_confidence: float
    urlhaus_flagged: bool
    urlhaus_threat: Optional[str]
    virustotal_detections: Optional[int]
    dns_resolved: bool
    dns_ip: Optional[str]
    whois_domain_age: Optional[str]
    whois_registrar: Optional[str]
    typosquatting_target: Optional[str]
    typosquatting_distance: Optional[int]
    features_summary: dict
    threat_signals: list
    scan_time_ms: float
    timestamp: str
 
# -- Constants --
SUSPICIOUS_TLDS = {'.xyz','.tk','.ml','.ga','.cf','.gq','.pw','.top','.click','.club','.work'}
BRAND_KEYWORDS  = ['paypal','google','amazon','apple','microsoft','netflix','facebook',
                   'instagram','bank','secure','chase','wellsfargo','ebay','dropbox']
URL_SHORTENERS  = ['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly']
PHISH_HINTS     = ['secure','account','update','login','signin','verify','banking',
                   'confirm','password','credit','wallet','alert','suspend']
LEGIT_BRANDS    = {
    'paypal':    'paypal.com',
    'google':    'google.com',
    'amazon':    'amazon.com',
    'apple':     'apple.com',
    'microsoft': 'microsoft.com',
    'netflix':   'netflix.com',
    'facebook':  'facebook.com',
    'instagram': 'instagram.com',
    'ebay':      'ebay.com',
    'dropbox':   'dropbox.com',
}
 
# -- Helpers --
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
 
def levenshtein(s1, s2):
    if len(s1) < len(s2): return levenshtein(s2, s1)
    if len(s2) == 0: return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j+1]+1, curr[j]+1, prev[j]+(c1!=c2)))
        prev = curr
    return prev[-1]
 
 
# ─────────────────────────────────────────────
#  URL OBFUSCATION DECODER  (NEW)
# ─────────────────────────────────────────────
 
def decode_obfuscation(url: str) -> tuple[str, list]:
    """
    Detect and decode common URL obfuscation techniques.
    Returns (decoded_url, list_of_techniques_found).
    """
    techniques = []
    decoded = url
 
    # 1. Percent-encoding (e.g. %68%74%74%70 = http)
    try:
        once = unquote(decoded)
        if once != decoded:
            techniques.append("Percent-encoded characters")
            decoded = once
        # Double encoding
        twice = unquote(once)
        if twice != once:
            techniques.append("Double percent-encoding")
            decoded = twice
    except Exception:
        pass
 
    # 2. Unicode / punycode domain (xn--)
    if 'xn--' in decoded.lower():
        techniques.append("Punycode / IDN homograph")
 
    # 3. Hexadecimal IP address (e.g. http://0x7f000001/)
    hex_ip = re.search(r'https?://0x([0-9a-fA-F]{8})', decoded)
    if hex_ip:
        techniques.append("Hex-encoded IP address")
        val = int(hex_ip.group(1), 16)
        ip = '.'.join(str((val >> (8 * i)) & 0xFF) for i in reversed(range(4)))
        decoded = decoded.replace(hex_ip.group(0), f"http://{ip}")
 
    # 4. Octal IP address (e.g. http://0177.0.0.1/)
    octal_ip = re.search(r'https?://(0\d+\.0\d*\.0\d*\.0\d+)', decoded)
    if octal_ip:
        techniques.append("Octal-encoded IP address")
        try:
            parts = [int(p, 8) for p in octal_ip.group(1).split('.')]
            decoded = decoded.replace(octal_ip.group(1), '.'.join(map(str, parts)))
        except Exception:
            pass
 
    # 5. Decimal IP address (e.g. http://2130706433/ = 127.0.0.1)
    dec_ip = re.search(r'https?://(\d{8,10})/', decoded)
    if dec_ip:
        techniques.append("Decimal-encoded IP address")
        try:
            val = int(dec_ip.group(1))
            ip = '.'.join(str((val >> (8 * i)) & 0xFF) for i in reversed(range(4)))
            decoded = decoded.replace(dec_ip.group(1), ip)
        except Exception:
            pass
 
    # 6. @ symbol trick (everything before @ is fake user info)
    if '@' in decoded:
        techniques.append("@ symbol credential trick")
 
    # 7. Multiple slashes / redirects embedded in URL
    if decoded.count('//') > 1:
        techniques.append("Embedded redirect (multiple //)")
 
    # 8. Shortened URL
    shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
                  'rb.gy', 'is.gd', 'buff.ly', 'short.link']
    if any(s in decoded.lower() for s in shorteners):
        techniques.append("URL shortener service")
 
    # 9. Data URI obfuscation
    if decoded.lower().startswith('data:'):
        techniques.append("Data URI scheme")
 
    # 10. Tab / newline injection
    if '\t' in decoded or '\n' in decoded or '\r' in decoded:
        techniques.append("Whitespace injection (tab/newline)")
        decoded = decoded.replace('\t', '').replace('\n', '').replace('\r', '')
 
    return decoded, techniques
 
 
# -- Feature extraction --
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
 
 
# -- CTI Integrations --
 
def check_urlhaus(url: str) -> tuple:
    try:
        resp = req.post(URLHAUS_API, data={"url": url}, timeout=5)
        data = resp.json()
        if data.get("query_status") == "is_listed":
            threat = data.get("threat", "malware")
            return True, threat
        return False, None
    except Exception as e:
        logger.warning(f"URLhaus check failed: {e}")
        return False, None
 
 
def check_urlhaus_host(domain: str) -> tuple:
    try:
        resp = req.post(URLHAUS_HOST_API, data={"host": domain}, timeout=5)
        data = resp.json()
        if data.get("query_status") == "is_listed":
            urls_online = data.get("urls_online", 0)
            return True, f"{urls_online} malicious URLs on this host"
        return False, None
    except Exception as e:
        logger.warning(f"URLhaus host check failed: {e}")
        return False, None
 
 
def check_virustotal(url: str) -> Optional[int]:
    if not VIRUSTOTAL_API_KEY:
        return None
    try:
        import base64
        url_id  = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        resp    = req.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=6
        )
        if resp.status_code == 200:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            return stats.get("malicious", 0) + stats.get("suspicious", 0)
        elif resp.status_code == 404:
            req.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=5
            )
            return 0
    except Exception as e:
        logger.warning(f"VirusTotal check failed: {e}")
    return None
 
 
def check_dns(domain: str) -> tuple:
    try:
        ip = socket.gethostbyname(domain)
        return True, ip
    except Exception:
        return False, None
 
 
def check_whois(domain: str) -> tuple:
    try:
        import whois
        w = whois.whois(domain)
        registrar = w.registrar if hasattr(w, 'registrar') else None
 
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            age_days = (datetime.now() - creation).days
            if age_days < 30:
                age_str = f"{age_days} days (NEW - suspicious)"
            elif age_days < 365:
                age_str = f"{age_days} days"
            else:
                age_str = f"{age_days // 365} years"
            return age_str, registrar
        return None, registrar
    except Exception as e:
        logger.warning(f"WHOIS check failed: {e}")
        return None, None
 
 
def check_typosquatting(domain: str) -> tuple:
    try:
        base = domain.split('.')[0]
        min_dist  = 999
        min_brand = None
        for brand, legit_domain in LEGIT_BRANDS.items():
            legit_base = legit_domain.split('.')[0]
            if base == legit_base:
                return None, None
            dist = levenshtein(base, legit_base)
            if dist < min_dist:
                min_dist  = dist
                min_brand = legit_domain
        if min_dist <= 3:
            return min_brand, min_dist
        return None, None
    except Exception:
        return None, None
 
 
def compute_final_verdict(ml_prob, urlhaus, vt_detections):
    score = ml_prob
    if urlhaus:
        score = min(1.0, score + 0.3)
    if vt_detections:
        if vt_detections >= 5:
            score = min(1.0, score + 0.25)
        elif vt_detections >= 2:
            score = min(1.0, score + 0.1)
 
    if score >= 0.7:
        verdict = "PHISHING"
    elif score >= 0.4:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"
 
    return verdict, round(score, 4)
 
 
# -- Routes --
 
@app.get("/")
def root():
    return {"service": "PhishGuard", "status": "online", "version": "2.0.0"}
 
 
@app.get("/health")
def health():
    return {
        "status":           "healthy",
        "model_features":   len(feature_names),
        "cached_scans":     len(_cache),
        "virustotal":       "enabled" if VIRUSTOTAL_API_KEY else "disabled - set VIRUSTOTAL_API_KEY env var",
        "urlhaus":          "enabled",
        "whois":            "enabled",
        "dns":              "enabled",
        "obfuscation_decoder": "enabled",
    }
 
 
@app.post("/scan", response_model=ScanResponse)
async def scan_url(req_body: ScanRequest):
    url = req_body.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
 
    # Obfuscation decoding FIRST
    decoded_url, obfuscation_techniques = decode_obfuscation(url)
    # Run ML on the decoded URL for better accuracy
    scan_url_effective = decoded_url if decoded_url != url else url
 
    # Cache check
    cache_key = hashlib.md5(url.encode()).hexdigest()
    if cache_key in _cache:
        logger.info(f"Cache hit: {url}")
        return _cache[cache_key]
 
    t0 = time.time()
 
    # Parse domain
    try:
        parsed = urlparse(scan_url_effective)
        domain = parsed.netloc.lower().replace('www.', '')
    except:
        domain = ''
 
    # Run all checks concurrently
    loop = asyncio.get_running_loop()
 
    ml_task        = loop.run_in_executor(None, run_ml, scan_url_effective)
    urlhaus_task   = loop.run_in_executor(None, check_urlhaus, url)
    urlhaus_h_task = loop.run_in_executor(None, check_urlhaus_host, domain)
    dns_task       = loop.run_in_executor(None, check_dns, domain)
    whois_task     = loop.run_in_executor(None, check_whois, domain)
    typo_task      = loop.run_in_executor(None, check_typosquatting, domain)
 
    vt_detections = None
    if req_body.check_virustotal and VIRUSTOTAL_API_KEY:
        vt_task = loop.run_in_executor(None, check_virustotal, url)
        vt_detections = await vt_task
 
    ml_prob, feats          = await ml_task
    urlhaus_flagged, threat = await urlhaus_task
    urlhaus_h, urlhaus_hmsg = await urlhaus_h_task
    dns_resolved, dns_ip    = await dns_task
    whois_age, whois_reg    = await whois_task
    typo_target, typo_dist  = await typo_task
 
    if urlhaus_h and not urlhaus_flagged:
        urlhaus_flagged = True
        threat = urlhaus_hmsg
 
    verdict, risk_score = compute_final_verdict(ml_prob, urlhaus_flagged, vt_detections)
 
    # Boost score if obfuscation detected
    if obfuscation_techniques and verdict == "SAFE":
        risk_score = min(1.0, risk_score + 0.15 * len(obfuscation_techniques))
        if risk_score >= 0.4:
            verdict = "SUSPICIOUS"
 
    elapsed_ms = round((time.time() - t0) * 1000, 1)
 
    threat_signals = []
    if obfuscation_techniques:
        threat_signals.append(f"Obfuscation detected: {', '.join(obfuscation_techniques)}")
    if urlhaus_flagged:
        threat_signals.append(f"URLhaus blacklisted: {threat}")
    if vt_detections:
        threat_signals.append(f"VirusTotal: {vt_detections} detections")
    if feats.get('suspecious_tld'):
        threat_signals.append("Suspicious TLD")
    if feats.get('ip'):
        threat_signals.append("IP address used instead of domain")
    if feats.get('random_domain'):
        threat_signals.append("Randomly generated domain")
    if feats.get('brand_in_subdomain'):
        threat_signals.append("Brand name in subdomain")
    if feats.get('phish_hints', 0) > 0:
        threat_signals.append(f"Phish keywords detected: {int(feats.get('phish_hints'))}")
    if typo_target:
        threat_signals.append(f"Typosquatting: looks like {typo_target} (distance={typo_dist})")
    if not dns_resolved:
        threat_signals.append("Domain does not resolve - possibly fake")
    if whois_age and 'NEW' in str(whois_age):
        threat_signals.append(f"Newly registered domain: {whois_age}")
 
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
        decoded_url=decoded_url if decoded_url != url else None,
        obfuscation_techniques=obfuscation_techniques,
        verdict=verdict,
        risk_score=risk_score,
        ml_confidence=round(ml_prob, 4),
        urlhaus_flagged=urlhaus_flagged,
        urlhaus_threat=threat,
        virustotal_detections=vt_detections,
        dns_resolved=dns_resolved,
        dns_ip=dns_ip,
        whois_domain_age=whois_age,
        whois_registrar=whois_reg,
        typosquatting_target=typo_target,
        typosquatting_distance=typo_dist if typo_target else None,
        features_summary=features_summary,
        threat_signals=threat_signals,
        scan_time_ms=elapsed_ms,
        timestamp=datetime.utcnow().isoformat() + "Z"
    )
 
    _cache[cache_key] = result
    _scan_history.append(result.dict())
    if len(_scan_history) > 1000:
        _scan_history.pop(0)
 
    logger.info(f"{verdict} ({risk_score}) - {url} [{elapsed_ms}ms]")
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
 
 
@app.get("/export/ioc")
def export_ioc(format: str = "json", verdict: str = "ALL"):
    """
    Export Indicators of Compromise (IoC) report.
    - format: 'json' or 'csv'
    - verdict: 'ALL', 'PHISHING', 'SUSPICIOUS'
    """
    scans = _scan_history
    if verdict != "ALL":
        scans = [s for s in scans if s["verdict"] == verdict.upper()]
 
    ioc_records = []
    for s in scans:
        ioc_records.append({
            "ioc_type":              "url",
            "indicator":             s["url"],
            "decoded_url":           s.get("decoded_url") or s["url"],
            "verdict":               s["verdict"],
            "risk_score":            s["risk_score"],
            "ml_confidence":         s["ml_confidence"],
            "urlhaus_flagged":       s["urlhaus_flagged"],
            "urlhaus_threat":        s.get("urlhaus_threat") or "",
            "virustotal_detections": s.get("virustotal_detections") or 0,
            "dns_ip":                s.get("dns_ip") or "",
            "whois_domain_age":      s.get("whois_domain_age") or "",
            "whois_registrar":       s.get("whois_registrar") or "",
            "typosquatting_target":  s.get("typosquatting_target") or "",
            "obfuscation_techniques": "; ".join(s.get("obfuscation_techniques") or []),
            "threat_signals":        "; ".join(s.get("threat_signals") or []),
            "timestamp":             s["timestamp"],
        })
 
    if format.lower() == "csv":
        if not ioc_records:
            return Response(content="No data", media_type="text/csv")
        headers_csv = list(ioc_records[0].keys())
        lines = [",".join(headers_csv)]
        for row in ioc_records:
            lines.append(",".join(f'"{str(row[h]).replace(chr(34), chr(39))}"' for h in headers_csv))
        csv_content = "\n".join(lines)
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=phishguard_ioc_report.csv"}
        )
 
    # JSON export
    report = {
        "report_type":    "PhishGuard IoC Export",
        "generated_at":   datetime.utcnow().isoformat() + "Z",
        "total_iocs":     len(ioc_records),
        "filter_verdict": verdict,
        "indicators":     ioc_records,
    }
    return JSONResponse(
        content=report,
        headers={"Content-Disposition": "attachment; filename=phishguard_ioc_report.json"}
    )
