# AI-Based Android Cybercrime Investigation and Mobile Evidence Analysis System

A Flask web prototype based on the supplied MCA project synopsis. It supports authorised evidence intake, SHA-256 hashing and re-verification, basic artifact parsing, SMS screening, URL lexical risk indicators, optional APK static analysis, candidate evidence correlation, event timelines and PDF reporting.

## 1. Important scope and safety
- Use only devices, files and accounts for which you have lawful authority and permission.
- This prototype analyses user-provided exports and supported files. It is **not** a universal Android extractor.
- It does not bypass locks, encryption, application sandboxing or access controls.
- It does not guarantee deleted-message recovery.
- APK analysis is static only. Submitted APKs are never installed or executed.
- AI scores and indicators are investigative leads, not proof of crime, identity or guilt.
- Preserve originals and use copies for examination where practicable.

## 2. Requirements
- Windows 10/11, macOS or Linux
- Python 3.11 recommended
- 4 GB RAM minimum; 8 GB recommended
- Internet required only to install packages; application works locally afterwards

## 3. Install on Windows (PowerShell)
```powershell
cd android_cybercrime_investigation
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000

If PowerShell blocks activation, run:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

## 4. Initial local login
- Username: `admin`
- Password: `ChangeThisPassword123!`

This is a development-only default. Before deployment, set strong values:
```powershell
$env:ADMIN_USERNAME="youradmin"
$env:ADMIN_PASSWORD="a-long-unique-password"
$env:SECRET_KEY="a-long-random-secret"
python app.py
```
The initial admin account is created only when the database is first initialised. For an existing database, change credentials through a proper account-management migration before production use. Do not expose the development server directly to the public internet.

## 5. Supported input formats
- CSV: header columns such as `message`, `body`, `sms`, `url`, `timestamp`, `date`, `time`
- JSON: list of records or object with `records` / `messages`
- TXT / LOG: each non-empty line is inspected; URLs become URL artifacts and other lines become SMS-like text
- SQLite / DB: read-only inspection of tables (up to 5,000 rows per table); common message and URL columns are heuristically recognised
- APK: static manifest/permission analysis if Androguard is installed
- XML: URL extraction from text

The parser is deliberately conservative and generic. Android artifact schemas vary by device, OS, app and acquisition method. Verify extracted records against the original source and document unsupported formats.

## 6. Sample test data
Create a CSV named `sample_sms.csv`:
```csv
timestamp,message
2026-11-20 09:10:00,"URGENT: Your bank account is blocked. Verify your KYC at https://account-check.example"
2026-11-20 09:12:00,"Hi, the project review starts at 2 PM in the lab"
```
Create a CSV named `sample_urls.csv`:
```csv
timestamp,url
2026-11-20 09:11:00,http://192.0.2.10/login/verify
2026-11-20 09:15:00,https://example.org/news
```
These are illustrative test strings; `.example` and TEST-NET addresses are reserved for documentation/testing.

## 7. Current modules
1. Investigator login (single local admin account)
2. Case creation and case register
3. Evidence upload with file type and size checks
4. SHA-256 hash at intake and re-verification
5. CSV, JSON, TXT, SQLite, XML and LOG parsers
6. SMS phishing-like screening using TF-IDF + Logistic Regression baseline and visible keyword indicators
7. URL lexical risk indicators
8. Optional Androguard APK static feature extraction
9. Candidate cross-artifact correlation using shared domains / same-day timestamps
10. Chronological timeline
11. Audit-style processing history
12. Consolidated PDF report

## 8. Model limitations and research evaluation
The built-in SMS corpus is intentionally small and is suitable only to demonstrate the pipeline. It is **not** a research-grade model and its scores must not be presented as validated real-world accuracy. Replace/extend it with appropriately licensed datasets (for example, UCI SMS Spam Collection plus labelled phishing examples), create train/validation/test splits, prevent leakage, and report precision, recall, F1, confusion matrix and class balance. URL scoring is currently transparent lexical heuristics, not a trained threat-intelligence verdict. Reputation lookups are not enabled by default. APK static indicators are not proof of malicious behaviour.

For a formal experiment, compare predictions against a held-out labelled set and document dataset source, licensing, preprocessing, model parameters, random seed and limitations.

## 9. Suggested next development steps
- Add role-based user management and password reset
- Add CSRF protection, secure cookies, rate limiting and encrypted evidence storage
- Add format-specific parsers validated against ALEAPP / Autopsy output
- Add an investigator-reviewed entity graph and configurable time windows
- Add SHAP explanations after training a suitably validated model
- Add optional threat-intelligence integrations only after privacy, terms and API-key review
- Add test suite and controlled ground-truth scenarios
- Deploy behind HTTPS, a production WSGI server and restricted access

## 10. Project structure
```text
android_cybercrime_investigation/
├── app.py
├── forensic.py
├── reporting.py
├── requirements.txt
├── README.md
├── templates/
├── static/
├── uploads/
├── reports/
└── instance/          # database created automatically
```

## 11. Troubleshooting
- `ModuleNotFoundError`: activate `.venv` and run `pip install -r requirements.txt`.
- APK parser unavailable: confirm `androguard` installed; APK is still stored and hashed.
- Empty extraction: check CSV/JSON headers and file format; see supported formats.
- Port in use: set `$env:PORT="5001"` before `python app.py`.
- Upload too large: maximum is 50 MB in this prototype.

## Academic note
This is a student prototype, not a certified forensic suite. Validate every parser and algorithm experimentally, keep originals intact, and clearly distinguish observed evidence from inferred indicators.
