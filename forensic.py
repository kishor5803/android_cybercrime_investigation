import csv, json, hashlib, re, sqlite3, math
from pathlib import Path
from urllib.parse import urlparse

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def _normalise_record(row):
    row = {str(k).lower().strip(): v for k, v in row.items()}
    keys = " ".join(row.keys())
    if any(k in keys for k in ("message", "sms", "body", "text")):
        content = row.get("message") or row.get("sms") or row.get("body") or row.get("text") or ""
        kind = "sms"
    elif any(k in keys for k in ("url", "uri", "domain")):
        content = row.get("url") or row.get("uri") or row.get("domain") or ""
        kind = "url"
    elif any(k in keys for k in ("apk", "package", "app_name")):
        content = row.get("package") or row.get("apk") or row.get("app_name") or ""
        kind = "apk"
    else:
        content = json.dumps(row, ensure_ascii=False)
        kind = row.get("artifact_type", "record")
    when = row.get("timestamp") or row.get("date") or row.get("time") or row.get("datetime") or ""
    return {"artifact_type": str(kind).lower(), "event_time": str(when), "content": str(content)}

def parse_evidence_file(path, ext):
    path = Path(path)
    records = []
    if ext == "csv":
        with open(path, newline="", encoding="utf-8-sig", errors="replace") as f:
            for row in csv.DictReader(f):
                records.append(_normalise_record(row))
    elif ext == "json":
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        if isinstance(data, dict): data = data.get("records", data.get("messages", [data]))
        if isinstance(data, list):
            records = [_normalise_record(x) if isinstance(x, dict) else {"artifact_type":"record","content":str(x),"event_time":""} for x in data]
    elif ext in ("txt", "log"):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line: continue
            urls = re.findall(r"https?://[^\s<>\"']+", line)
            records.append({"artifact_type":"url","event_time":"","content":urls[0]}) if urls else records.append({"artifact_type":"sms","event_time":"","content":line})
    elif ext in ("db", "sqlite", "sqlite3"):
        # Read-only database inspection; only known common table/column patterns are imported.
        uri = f"file:{path.resolve()}?mode=ro"
        con = sqlite3.connect(uri, uri=True)
        try:
            tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            for table in tables:
                safe = table.replace('"', '""')
                cols = [r[1] for r in con.execute(f'PRAGMA table_info("{safe}")')]
                if not cols: continue
                try:
                    cur = con.execute(f'SELECT * FROM "{safe}" LIMIT 5000')
                    for values in cur.fetchall():
                        row = dict(zip(cols, values))
                        rec = _normalise_record(row)
                        if rec["artifact_type"] in ("sms", "url", "apk") or rec["content"]:
                            records.append(rec)
                except sqlite3.Error:
                    continue
        finally:
            con.close()
    elif ext == "apk":
        records.append({"artifact_type":"apk","event_time":"","content":path.name})
    elif ext == "xml":
        text = path.read_text(encoding="utf-8", errors="replace")
        for url in re.findall(r'https?://[^\s<>"\']+', text):
            records.append({"artifact_type":"url","event_time":"","content":url})
        if not records: records.append({"artifact_type":"record","event_time":"","content":text[:5000]})
    return records

# Small transparent baseline corpus: educational demonstration only. Replace/extend with
# licensed public datasets and evaluate on a held-out test set before making claims.
SMS_TRAIN = [
("Congratulations! You won a free prize. Claim now at http://claim-prize.example",1),
("URGENT: Your bank account is blocked. Verify your details immediately",1),
("Your package is waiting. Pay a small fee using this link",1),
("Click here to update your KYC or your account will be suspended",1),
("You have won a cash reward. Send your OTP to receive it",1),
("Unusual login detected. Confirm your password at this link",1),
("Your electricity bill is overdue. Pay now to avoid disconnection",1),
("Dear customer, share your card details to reverse this transaction",1),
("Meeting is scheduled for tomorrow at 10 AM",0),
("Hi, are we still meeting for lunch today?",0),
("Your appointment is confirmed for Monday",0),
("The class notes are available in the student portal",0),
("Thank you for your payment. Receipt is attached",0),
("Please call me when you reach home",0),
("Your order has been shipped and is on the way",0),
("The project review starts at 2 PM in the lab",0),
]

try:
    from ml_engine import ForensicMLEngine
    _ML_ENGINE = ForensicMLEngine.get_instance()
except ImportError:
    try:
        from android_cybercrime_investigation.ml_engine import ForensicMLEngine
        _ML_ENGINE = ForensicMLEngine.get_instance()
    except Exception:
        _ML_ENGINE = None
except Exception:
    _ML_ENGINE = None

def analyse_sms(text):
    if _ML_ENGINE:
        try:
            return _ML_ENGINE.analyze_sms_xai(text)
        except Exception:
            pass

    text = str(text)
    signals = []
    lower = text.lower()
    patterns = {
        "urgency": r"\b(urgent|immediately|now|today|blocked|suspended|expire)\b",
        "credential request": r"\b(password|otp|pin|cvv|card details|kyc|verify)\b",
        "reward bait": r"\b(won|winner|prize|reward|free cash|claim)\b",
        "link present": r"https?://|www\."
    }
    for label, pattern in patterns.items():
        if re.search(pattern, lower): signals.append(label)
    score = min(95.0, len(signals) * 25.0)
    label = "Suspicious / phishing-like" if score >= 50 else "No strong phishing signal"
    return {"label":label,"score":score,"signals":signals,"model":"Rule-based heuristic fallback","token_contributions":[],"explanation":f"Heuristic screening score: {score}%"}

def explain_sms(result):
    return result.get("explanation") or ("Detected indicators: " + (", ".join(result.get("signals", [])) if result.get("signals") else "no configured keyword indicators") + f". Model screening score: {result.get('score', 0)}%.")

def url_features(url):
    raw = str(url).strip()
    candidate = raw if "://" in raw else "http://" + raw
    p = urlparse(candidate)
    host = (p.hostname or "").lower()
    return {
        "https": p.scheme == "https",
        "host_length": len(host),
        "url_length": len(raw),
        "has_ip_host": bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host)),
        "has_at_symbol": "@" in raw,
        "many_subdomains": len(host.split(".")) > 3,
        "suspicious_terms": any(x in raw.lower() for x in ["login", "verify", "secure", "update", "bank", "wallet", "gift", "claim"]),
        "punycode": "xn--" in host,
        "host": host
    }

def analyse_url(url):
    if _ML_ENGINE:
        try:
            return _ML_ENGINE.analyze_url_xai(url)
        except Exception:
            pass

    f = url_features(url)
    score, reasons = 0, []
    if not f["https"]: score += 12; reasons.append("not HTTPS")
    if f["has_ip_host"]: score += 25; reasons.append("IP address used as host")
    if f["has_at_symbol"]: score += 20; reasons.append("@ symbol in URL")
    if f["many_subdomains"]: score += 12; reasons.append("many subdomains")
    if f["suspicious_terms"]: score += 18; reasons.append("sensitive/action words in URL")
    if f["punycode"]: score += 20; reasons.append("punycode hostname")
    if f["url_length"] > 100: score += 10; reasons.append("unusually long URL")
    score = min(99, score)
    label = "High-risk indicators" if score >= 50 else ("Some risk indicators" if score >= 25 else "No strong lexical indicators")
    return {"label":label,"score":score,"features":f,"reasons":reasons,"model":"Rule-based lexical engine","explanation":", ".join(reasons) if reasons else "No anomalous lexical risk indicators detected."}

def explain_url(result):
    return result.get("explanation") or (", ".join(result.get("reasons", [])) if result.get("reasons") else "No configured lexical risk indicators detected.")

def analyse_apk(path):
    result = {"label":"Static analysis unavailable","score":0,"package":"","permissions":[],"urls":[],"warnings":[]}
    try:
        from androguard.core.apk import APK
        apk = APK(str(path))
        perms = apk.get_permissions() or []
        urls = []
        try:
            for dex in apk.get_all_dex():
                # Do not execute DEX. Search printable strings only.
                for match in re.findall(rb'https?://[A-Za-z0-9./?=_%-]+', dex):
                    urls.append(match.decode("utf-8", "ignore"))
        except Exception:
            pass
        result["package"] = apk.get_package() or ""
        result["permissions"] = perms[:100]
        result["urls"] = sorted(set(urls))[:100]
        high = [p for p in perms if any(k in p.lower() for k in ["sms", "call_phone", "read_contacts", "record_audio", "location", "read_phone_state"])]
        score = min(95, len(high) * 12 + (15 if urls else 0))
        result["score"] = score
        result["label"] = "Review recommended" if score >= 35 else "No strong configured static indicators"
        result["warnings"] = ["Permissions and embedded strings are indicators only; they do not prove malicious behaviour."]
    except ImportError:
        result["warnings"] = ["Install androguard to enable APK manifest/static feature extraction."]
    except Exception as exc:
        result["warnings"] = [f"APK parsing error: {exc}"]
    return result

def correlate_artifacts(rows):
    links = []
    for i, a in enumerate(rows):
        for b in rows[i+1:]:
            ca, cb = (a.get("content") or "").lower(), (b.get("content") or "").lower()
            shared = None
            urls_a = set(re.findall(r"(?:https?://)?(?:www\.)?([a-z0-9.-]+\.[a-z]{2,})", ca))
            urls_b = set(re.findall(r"(?:https?://)?(?:www\.)?([a-z0-9.-]+\.[a-z]{2,})", cb))
            common = urls_a & urls_b
            if common: shared = "Shared domain: " + sorted(common)[0]
            elif a.get("event_time") and b.get("event_time") and a.get("event_time")[:10] == b.get("event_time")[:10]:
                shared = "Same recorded date (temporal proximity only)"
            if shared:
                links.append({"a":a.get("artifact_type","artifact"),"a_content":ca[:100],"b":b.get("artifact_type","artifact"),
                              "b_content":cb[:100],"reason":shared,"caution":"Candidate relationship; manual validation required."})
    return links[:300]

def build_timeline(rows):
    out = []
    for r in rows:
        out.append({"time":r.get("event_time") or "Time not supplied","type":r.get("artifact_type","record"),
                    "content":(r.get("content") or "")[:180],"indicator":r.get("indicator") or "",
                    "score":r.get("risk_score")})
    return out
