# PhishGuard - Real-Time Phishing URL Detection System

![Python](https://img.shields.io/badge/Python-3.12-blue)
![XGBoost](https://img.shields.io/badge/XGBoost-2.0-orange)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104-green)
![Accuracy](https://img.shields.io/badge/Accuracy-92.5%25-brightgreen)
![ROC--AUC](https://img.shields.io/badge/ROC--AUC-0.97-brightgreen)

An ML-Powered Phishing URL Detection System with Cyber Threat Intelligence Integration. PhishGuard addresses the vulnerability of phishing attacks bypassing traditional static blacklists by combining statistical Machine Learning classification with active Cyber Threat Intelligence. Designed to mirror real-world Security Operations Center (SOC) workflows, the system operates as a real-time Chrome browser extension.

---

## Team Members

| Name | Roll Number |
|------|------------|
| Atharv Madan | 240103024 |
| Arya Kshirsagar | 240103023 |
| Arnav De | 240103022 |

---

## Project Overview

PhishGuard analyzes visited URLs on the fly by:
- Decoding obfuscation patterns
- Querying live threat feeds (URLhaus API, VirusTotal API)
- Performing passive DNS and WHOIS forensics
- Analyzing typosquatting attempts
- Running ML-based URL feature classification

Results are synthesized into structured IoC (Indicator of Compromise) threat reports accessible via an analyst dashboard.

---

## Features

- **92.5% Accuracy** with 0.97 ROC-AUC on 11,430 labeled URLs
- **87 engineered features** extracted from URL structure
- **Sub-500ms scanning** — real-time threat detection
- **Chrome Extension** showing live SAFE / SUSPICIOUS / PHISHING verdict
- **URLhaus API** integration for live blacklist checking
- **VirusTotal API** integration for multi-engine threat scanning
- **DNS resolution** forensics
- **WHOIS lookup** for domain age and registrar info
- **Typosquatting detection** using Levenshtein distance
- **Automatic warning banner** injected on phishing pages
- **Analytics Dashboard** with scan history and verdict distribution chart
- **Exportable IoC Reports** in structured JSON format
- **REST API** with FastAPI and Swagger docs at `/docs`

---

## System Architecture

```
User visits a website
        |
Chrome Extension (background.js) detects URL
        |
POST /scan -> FastAPI Backend (localhost:8000)
        |
+-------+-------+-------+-------+
|       |       |       |       |
ML   URLhaus  DNS   WHOIS  Typosquatting
Model   API  Lookup Lookup  Detection
|       |       |       |       |
+-------+-------+-------+-------+
        |
Combine all signals -> Final verdict + Risk Score
        |
Extension popup shows result
Dashboard updates with scan history
Warning banner injected on phishing pages
IoC report available for download
```

---

## Project Structure

```
PhishGuard/
├── main.py                        # FastAPI backend server
├── phishguard_model.pkl           # Trained XGBoost model
├── feature_names.pkl              # Feature column names
├── dashboard.html                 # Analytics dashboard with IoC export
├── requirements.txt               # Python dependencies
└── chrome_extension/
    ├── manifest.json              # Chrome extension config
    ├── background.js              # Service worker
    ├── popup.html                 # Extension popup UI
    ├── popup.js                   # Popup logic
    ├── content.js                 # Content script
    └── icons/
        ├── icon16.png
        ├── icon48.png
        └── icon128.png
```

---

## Machine Learning Model

### Dataset
- **Source:** Web Page Phishing Detection Dataset (Kaggle)
- **Size:** 11,430 URLs — 50% phishing, 50% legitimate
- **Features:** 87 pre-extracted URL and page-level features

### Features Used (87 total)

| Category | Features |
|----------|----------|
| URL Structure | length_url, length_hostname, nb_dots, nb_hyphens, nb_slashes, nb_at, nb_qm |
| Security Signals | ip, punycode, port, https_token, shortening_service |
| Brand Detection | brand_in_subdomain, brand_in_path, domain_in_brand, phish_hints |
| Domain Analysis | random_domain, abnormal_subdomain, nb_subdomains, prefix_suffix |
| Word Analysis | length_words_raw, shortest_word_host, longest_word_path, avg_words_raw |
| Page Features | page_rank, domain_age, web_traffic, google_index, dns_record |

### Model Performance

| Metric | Score |
|--------|-------|
| Accuracy | 92.5% |
| ROC-AUC | 0.97 |
| Precision | 0.93 |
| Recall | 0.92 |
| F1 Score | 0.92 |
| Scan Speed | ~20ms |

### Algorithm
**XGBoost (Extreme Gradient Boosting)**
- 500 decision trees
- Max depth: 8
- Learning rate: 0.05
- Subsample: 0.8

### Verdict Thresholds
| Risk Score | Verdict |
|-----------|---------|
| 0% - 39% | SAFE |
| 40% - 69% | SUSPICIOUS |
| 70% - 100% | PHISHING |

---

## Setup and Installation

### Prerequisites
- Python 3.10+
- Google Chrome
- Git

### Step 1 - Clone the repository
```bash
git clone https://github.com/atharvmadan10/PHISHGUARD.git
cd PHISHGUARD
```

### Step 2 - Install dependencies
```bash
pip install fastapi uvicorn xgboost scikit-learn pandas joblib requests python-whois
```

### Step 3 - Start the API server
```bash
python -m uvicorn main:app --port 8000
```

Server runs at `http://localhost:8000`

### Step 4 - Load Chrome Extension
1. Open Chrome and go to `chrome://extensions`
2. Enable **Developer Mode** (top right)
3. Click **Load unpacked**
4. Select the `chrome_extension/` folder

### Step 5 - Open Dashboard
Double click `dashboard.html` to open in browser.

---

## API Reference

### Endpoints

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/` | Health check |
| GET | `/health` | Detailed status with CTI info |
| POST | `/scan` | Scan a URL |
| GET | `/history` | Last 50 scanned URLs |
| GET | `/stats` | Verdict counts |
| GET | `/docs` | Swagger UI |

### Example Scan Request
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal-secure-login.xyz/account"}'
```

### Example Response
```json
{
  "url": "http://paypal-secure-login.xyz/account",
  "verdict": "PHISHING",
  "risk_score": 0.9951,
  "ml_confidence": 0.9951,
  "urlhaus_flagged": false,
  "urlhaus_threat": null,
  "virustotal_detections": null,
  "dns_resolved": false,
  "dns_ip": null,
  "whois_domain_age": null,
  "whois_registrar": null,
  "typosquatting_target": "paypal.com",
  "typosquatting_distance": 2,
  "features_summary": {
    "length_url": 45,
    "nb_dots": 1,
    "nb_hyphens": 2,
    "has_ip": false,
    "suspicious_tld": true,
    "phish_hints": 4
  },
  "threat_signals": [
    "Suspicious TLD",
    "Typosquatting: looks like paypal.com (distance=2)",
    "4 phishing keyword(s) in URL"
  ],
  "scan_time_ms": 921.0,
  "timestamp": "2026-05-18T14:00:00Z"
}
```

---

## IoC Report Export

The dashboard supports exporting structured IoC (Indicator of Compromise) reports:

- Click **IoC** button on any scan row for individual report
- Click **Export IoC Report** for bulk export of all scans
- Reports include: verdict, risk score, CTI results, DNS/WHOIS forensics, threat signals, recommended action
- Downloads as `.json` file

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| ML Model | XGBoost, scikit-learn, Pandas |
| Backend API | FastAPI, Python 3.12 |
| Threat Intelligence | URLhaus API, VirusTotal API |
| Forensics | python-whois, socket (DNS) |
| Extension | JavaScript, Chrome Manifest V3 |
| Dashboard | HTML, CSS, Chart.js |
| Dataset | Web Page Phishing Detection (Kaggle) |

---

## Dataset Resources

- **URLhaus API** - Live malicious URL database
- **Web Page Phishing Detection Dataset** - Kaggle benchmark dataset (11,430 URLs, 87 features)
- **VirusTotal API** - Multi-engine threat scanning

---

## Future Improvements

- VirusTotal API key integration (currently requires env variable)
- React + Tailwind dashboard
- Docker containerization
- Firefox extension support
- Cloud deployment

---

## Mentors

- Naitik - 8178596442
- Aarsh - 9520316522

---

## License

MIT License
