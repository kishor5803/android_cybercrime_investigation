import math, re
from urllib.parse import urlparse
import numpy as np

# ---------------------------------------------------------------------------
# Training Corpora (Representative Android Phishing / Smishing & Benign Data)
# ---------------------------------------------------------------------------

SMS_DATASET = [
    # Phishing / Smishing (Label: 1)
    ("URGENT: Your SBI bank account has been locked. Complete your KYC update at https://sbi-kyc-verify.net to restore access immediately.", 1),
    ("Dear customer, your credit card transaction of Rs 48,990 was approved. If not done by you, click http://dispute-alert.info/cancel", 1),
    ("Congratulations! You have won cash prize of Rs 25,00,000 in Kaun Banega Crorepati. Contact Mr. Sharma to claim reward now.", 1),
    ("Your electricity connection will be disconnected tonight at 9:30 PM due to unpaid bill. Call electricity officer now or pay at http://bill-pay.link", 1),
    ("Income Tax Refund of Rs 15,490 has been approved. Please verify your bank account number at http://incometax-refunds-portal.org/login", 1),
    ("Your Netflix subscription payment failed. Update your card details immediately to avoid account suspension: https://netflix-update-billing.cc", 1),
    ("Important security alert: We detected unauthorized login from Russia. Change your Google account password immediately: http://192.168.1.100/login", 1),
    ("India Post: Your package cannot be delivered due to wrong address. Update your address and pay re-delivery charge Rs 25: https://indiapost-parcel-tracking.vip", 1),
    ("Pre-approved personal loan of Rs 5,00,000 without collateral. Low interest rate 4.5%. Click to disburse loan immediately: http://easy-loan-disbursal.net", 1),
    ("Your WhatsApp account will expire in 24 hours. Verify your mobile number and enter OTP at http://whatsapp-renew.online", 1),
    ("ALERT: HDFC Bank card suspended due to unusual activity. Click here to reactivate your debit card: http://hdfc-reactivate-card.top", 1),
    ("You received 1 new secure voicemail message. Listen to your recording at http://voice-box-msg.xyz/listen", 1),
    ("Customs clearance required for international shipment #IN98212. Pay custom duties online to release package: http://customs-pay-duty.link", 1),
    ("Cryptocurrency alert: 0.85 BTC deposited to your wallet. Confirm receipt and withdraw funds: http://crypto-wallet-verify.com/claim", 1),
    ("Work from home part time job opportunity: Earn Rs 3,000 to 5,000 daily with simple YouTube like tasks. Join Telegram group now.", 1),
    ("Urgent notice: Your PAN card is not linked to your bank account. Avoid Rs 10,000 fine. Update PAN immediately at http://pan-aadhaar-link.org", 1),
    ("Telecom alert: Your SIM card will be deactivated due to pending verification. Call customer care or update KYC right now.", 1),
    ("Final warning: Unpaid toll violation notice. Pay pending challan online to avoid legal action: http://fastag-challan-pay.co", 1),
    ("Free iPhone 15 Pro giveaway! You are today's lucky visitor. Spin the wheel and claim your gift: http://lucky-gift-wheel.site/claim", 1),
    ("Security notice: One-Time Password (OTP) for Rs 12,500 is 849201. Do not share your OTP with anyone.", 1),
    ("Your Amazon order #402-8192 cannot be shipped. Please confirm your CVV and card details to resume shipping: http://amazon-shipment-confirm.info", 1),
    ("Dear user, suspicious activity detected on your PayPal account. Re-verify your identity at http://paypal-security-center.club", 1),
    ("Urgent: Your EPF provident fund claim has been rejected. Resubmit banking credentials: http://epf-claim-update.biz", 1),
    ("Dear traveler, your flight reservation is cancelled. Claim full refund with instant voucher at http://air-ticket-refund.top", 1),

    # Benign Messages (Label: 0)
    ("Hi, are we still meeting for lunch at 1 PM today near the cafeteria?", 0),
    ("The project review has been scheduled for tomorrow at 10 AM in Conference Room B.", 0),
    ("Thank you for your payment of Rs 1,200 for broadband bill. Your transaction ID is TXN892189. Services active.", 0),
    ("Your Swiggy order from Biryani House has been picked up and is arriving in 20 minutes.", 0),
    ("Class notes for the Distributed Systems lecture have been uploaded to the university portal.", 0),
    ("Mom, I have reached Bangalore safely. Will call you after checking into the hotel.", 0),
    ("Your appointment with Dr. Mehta is confirmed for Wednesday at 4:30 PM. Please arrive 15 minutes early.", 0),
    ("Team, please remember to submit your weekly timesheets and sprint reports by 5 PM Friday.", 0),
    ("OTP for logging into your college portal is 492012. Valid for 10 minutes. Do not share this OTP.", 0),
    ("Your Flipkart delivery package is out for delivery with agent Ramesh (Phone: 9876543210).", 0),
    ("Happy birthday! Wishing you a wonderful year ahead filled with joy and success.", 0),
    ("Could you please send me the revised PDF report for the seminar presentation?", 0),
    ("Metro recharge of Rs 500 was successful. Current card balance is Rs 620.", 0),
    ("The lab examination has been postponed to next Monday due to the departmental symposium.", 0),
    ("Don't forget to buy milk and vegetables on your way home this evening.", 0),
    ("Your Uber ride is arriving now. White Swift Dzire, license plate KA 03 AB 1234.", 0),
    ("Library notice: Please return 'Digital Forensics and Cyber Crime Investigation' before due date 30th Nov.", 0),
    ("Let's catch up over coffee this weekend. Let me know what time works best for you.", 0),
    ("Your monthly mobile postpaid bill of Rs 499 for cycle ending 20th Nov is generated. No action needed if paid.", 0),
    ("The code review comments have been resolved. Branch ready for merge into main.", 0),
    ("Please find attached the minutes of the MCA department faculty meeting.", 0),
    ("Hey, did you finish the assignment for artificial intelligence? Need some clarification on Q3.", 0),
    ("Reminder: Blood donation camp tomorrow from 9 AM to 3 PM in the college auditorium.", 0),
    ("Your bank statement for the month of October is now ready to download via official netbanking.", 0),
]

URL_DATASET = [
    # Malicious / Phishing URLs (Label: 1)
    ("http://192.168.1.100/login/verify.php", 1),
    ("http://104.28.19.44/bank/sbi/update-kyc.html", 1),
    ("https://sbi-kyc-verify-account-update.net/login", 1),
    ("http://hdfc.secure-banking-portal.top/authenticate", 1),
    ("http://incometax-refunds-direct-deposit.org/claim", 1),
    ("https://paypal-security-update-center.club/signin", 1),
    ("http://claim-free-iphone15-cash-reward.site/spin", 1),
    ("http://netflix-billing-resolve-payment.cc/account", 1),
    ("http://indiapost-parcel-redelivery-tracking.vip/pay", 1),
    ("http://whatsapp-account-verification-code.online/otp", 1),
    ("http://easy-cash-loan-instant-disbursal.biz/apply", 1),
    ("http://fastag-challan-penalty-payment.co/pay-now", 1),
    ("http://amazon-unusual-sign-in-detected.info/confirm", 1),
    ("http://epf-claim-settlement-portal.biz/kyc", 1),
    ("http://air-ticket-refund-instant-voucher.top/cancel", 1),
    ("http://crypto-wallet-free-bitcoin-drop.xyz/wallet", 1),
    ("http://xn--googl-pra.com/security/login", 1),
    ("http://customs-clearance-parcel-tax.link/payment", 1),
    ("http://198.51.100.25/apk/download/malicious.apk", 1),
    ("http://lucky-winner-draw-2026.click/claim-prize", 1),

    # Benign / Legitimate URLs (Label: 0)
    ("https://www.google.com/search?q=cybercrime+investigation", 0),
    ("https://github.com/torvalds/linux", 0),
    ("https://en.wikipedia.org/wiki/Digital_forensics", 0),
    ("https://www.onlinesbi.sbi/", 0),
    ("https://www.hdfcbank.com/personal", 0),
    ("https://www.amazon.in/gp/bestsellers", 0),
    ("https://stackoverflow.com/questions/tagged/python", 0),
    ("https://docs.python.org/3/library/sqlite3.html", 0),
    ("https://scikit-learn.org/stable/modules/classes.html", 0),
    ("https://www.netflix.com/browse", 0),
    ("https://www.indiapost.gov.in/vas/pages/indiaposthome.aspx", 0),
    ("https://www.swiggy.com/restaurants", 0),
    ("https://pypi.org/project/Flask/", 0),
    ("https://www.microsoft.com/en-in/", 0),
    ("https://www.kaggle.com/datasets", 0),
    ("https://edition.cnn.com/world", 0),
    ("https://www.bbc.com/news", 0),
    ("https://developer.android.com/guide", 0),
    ("https://web.whatsapp.com/", 0),
    ("https://www.incometax.gov.in/iec/foportal/", 0),
]

# ---------------------------------------------------------------------------
# Shannon Entropy & URL Feature Extraction
# ---------------------------------------------------------------------------

def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of a string (higher entropy indicates randomness / obfuscation)."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return round(-sum(p * math.log2(p) for p in prob), 3)

def extract_url_feature_vector(raw_url: str):
    """Extracts numerical features from a URL string for ML classification."""
    raw = str(raw_url).strip()
    candidate = raw if "://" in raw else "http://" + raw
    try:
        p = urlparse(candidate)
    except Exception:
        p = urlparse("http://" + raw)
    
    host = (p.hostname or "").lower()
    full_url = raw.lower()
    
    has_ip = 1 if bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host)) else 0
    is_https = 1 if p.scheme == "https" else 0
    has_at = 1 if "@" in full_url else 0
    has_punycode = 1 if "xn--" in host else 0
    
    dots_count = host.count(".")
    hyphen_count = full_url.count("-")
    digit_count = sum(c.isdigit() for c in full_url)
    url_length = len(full_url)
    host_length = len(host)
    entropy = calculate_entropy(host)
    
    suspicious_terms = ["login", "verify", "secure", "update", "bank", "wallet", "gift", "claim", 
                        "account", "kyc", "otp", "disbursal", "refund", "redelivery", "bonus"]
    terms_count = sum(1 for term in suspicious_terms if term in full_url)
    
    features = [
        url_length,
        host_length,
        dots_count,
        hyphen_count,
        digit_count,
        entropy,
        has_ip,
        is_https,
        has_at,
        has_punycode,
        terms_count
    ]
    
    dict_features = {
        "url_length": url_length,
        "host_length": host_length,
        "dots_count": dots_count,
        "hyphen_count": hyphen_count,
        "digit_count": digit_count,
        "entropy": entropy,
        "has_ip": bool(has_ip),
        "is_https": bool(is_https),
        "has_at": bool(has_at),
        "has_punycode": bool(has_punycode),
        "terms_count": terms_count,
        "hostname": host
    }
    
    return np.array(features, dtype=float), dict_features

# ---------------------------------------------------------------------------
# ML Model Engine & Benchmarking
# ---------------------------------------------------------------------------

class ForensicMLEngine:
    _instance = None

    def __init__(self):
        self.sms_vectorizer = None
        self.sms_models = {}
        self.sms_metrics = {}
        self.url_scaler = None
        self.url_models = {}
        self.url_metrics = {}
        self.top_sms_features = {"phishing": [], "benign": []}
        self.train_all()

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = ForensicMLEngine()
        return cls._instance

    def train_all(self):
        self._train_sms_classifiers()
        self._train_url_classifiers()

    def _train_sms_classifiers(self):
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.naive_bayes import MultinomialNB
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
        from sklearn.model_selection import StratifiedKFold

        texts = [x[0] for x in SMS_DATASET]
        labels = [x[1] for x in SMS_DATASET]

        self.sms_vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            lowercase=True,
            sublinear_tf=True,
            token_pattern=r"(?u)\b\w+\b|https?://\S+"
        )
        X = self.sms_vectorizer.fit_transform(texts)
        y = np.array(labels)

        # 3 distinct candidate classifiers
        candidates = {
            "Logistic Regression": LogisticRegression(class_weight="balanced", random_state=42, C=2.0),
            "Multinomial Naive Bayes": MultinomialNB(alpha=0.5),
            "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
        }

        feature_names = self.sms_vectorizer.get_feature_names_out()

        for name, clf in candidates.items():
            # Perform 5-fold cross validation for robust, academically sound metrics
            skf = StratifiedKFold(n_splits=4, shuffle=True, random_state=42)
            y_preds = np.zeros(len(y))
            y_probs = np.zeros(len(y))

            for train_idx, test_idx in skf.split(X, y):
                clf_clone = candidates[name].__class__(**clf.get_params())
                clf_clone.fit(X[train_idx], y[train_idx])
                y_preds[test_idx] = clf_clone.predict(X[test_idx])
                if hasattr(clf_clone, "predict_proba"):
                    y_probs[test_idx] = clf_clone.predict_proba(X[test_idx])[:, 1]

            acc = accuracy_score(y, y_preds)
            prec = precision_score(y, y_preds, zero_division=0)
            rec = recall_score(y, y_preds, zero_division=0)
            f1 = f1_score(y, y_preds, zero_division=0)
            cm = confusion_matrix(y, y_preds).tolist() # [[TN, FP], [FN, TP]]

            # Fit on full data for production inference
            clf.fit(X, y)
            self.sms_models[name] = clf
            self.sms_metrics[name] = {
                "accuracy": round(acc * 100, 2),
                "precision": round(prec * 100, 2),
                "recall": round(rec * 100, 2),
                "f1_score": round(f1 * 100, 2),
                "confusion_matrix": {
                    "tn": cm[0][0],
                    "fp": cm[0][1],
                    "fn": cm[1][0],
                    "tp": cm[1][1]
                }
            }

        # Extract top linear feature weights from Logistic Regression for Explainable AI
        lr = self.sms_models["Logistic Regression"]
        coefs = lr.coef_[0]
        top_pos_idx = np.argsort(coefs)[::-1][:15]
        top_neg_idx = np.argsort(coefs)[:15]

        self.top_sms_features["phishing"] = [
            {"token": feature_names[i], "weight": round(float(coefs[i]), 3)} for i in top_pos_idx
        ]
        self.top_sms_features["benign"] = [
            {"token": feature_names[i], "weight": round(float(coefs[i]), 3)} for i in top_neg_idx
        ]

    def _train_url_classifiers(self):
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.linear_model import LogisticRegression
        from sklearn.preprocessing import StandardScaler
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
        from sklearn.model_selection import StratifiedKFold

        X_raw = [extract_url_feature_vector(item[0])[0] for item in URL_DATASET]
        y = np.array([item[1] for item in URL_DATASET])

        self.url_scaler = StandardScaler()
        X = self.url_scaler.fit_transform(X_raw)

        url_candidates = {
            "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42, max_depth=6),
            "Logistic Regression": LogisticRegression(random_state=42)
        }

        for name, clf in url_candidates.items():
            skf = StratifiedKFold(n_splits=4, shuffle=True, random_state=42)
            y_preds = np.zeros(len(y))

            for train_idx, test_idx in skf.split(X, y):
                c_clone = clf.__class__(**clf.get_params())
                c_clone.fit(X[train_idx], y[train_idx])
                y_preds[test_idx] = c_clone.predict(X[test_idx])

            acc = accuracy_score(y, y_preds)
            prec = precision_score(y, y_preds, zero_division=0)
            rec = recall_score(y, y_preds, zero_division=0)
            f1 = f1_score(y, y_preds, zero_division=0)
            cm = confusion_matrix(y, y_preds).tolist()

            clf.fit(X, y)
            self.url_models[name] = clf
            self.url_metrics[name] = {
                "accuracy": round(acc * 100, 2),
                "precision": round(prec * 100, 2),
                "recall": round(rec * 100, 2),
                "f1_score": round(f1 * 100, 2),
                "confusion_matrix": {
                    "tn": cm[0][0],
                    "fp": cm[0][1],
                    "fn": cm[1][0],
                    "tp": cm[1][1]
                }
            }

    # -----------------------------------------------------------------------
    # Explainable AI (XAI) Inference Methods
    # -----------------------------------------------------------------------

    def analyze_sms_xai(self, text: str, preferred_model: str = "Logistic Regression"):
        """Performs classification and Explainable AI token attribution breakdown."""
        text = str(text)
        lower = text.lower()
        signals = []

        patterns = {
            "urgency": r"\b(urgent|immediately|now|today|blocked|suspended|expire|final warning)\b",
            "credential request": r"\b(password|otp|pin|cvv|card details|kyc|verify|pan)\b",
            "reward / lottery bait": r"\b(won|winner|prize|reward|free cash|claim|lucky|gift)\b",
            "threat / coercion": r"\b(legal action|fine|arrest|disconnected|deactivated)\b",
            "link present": r"https?://|www\."
        }
        for label, pat in patterns.items():
            if re.search(pat, lower):
                signals.append(label)

        clf = self.sms_models.get(preferred_model) or self.sms_models["Logistic Regression"]
        tfidf_vec = self.sms_vectorizer.transform([text])
        prob = float(clf.predict_proba(tfidf_vec)[0][1])
        base_score = round(prob * 100, 1)

        # Rule heuristic blending to avoid false confidence from unseen tokens
        score = base_score
        if signals:
            score = min(99.0, max(score, len(signals) * 20.0))

        # Explainable AI (XAI): Calculate token-level contributions
        # We retrieve the feature names matching the words in the message and their linear weights
        feature_names = self.sms_vectorizer.get_feature_names_out()
        lr_coefs = self.sms_models["Logistic Regression"].coef_[0]

        nz_indices = tfidf_vec.nonzero()[1]
        token_contributions = []

        for idx in nz_indices:
            token = feature_names[idx]
            weight = float(lr_coefs[idx])
            tfidf_val = float(tfidf_vec[0, idx])
            impact_score = round(weight * tfidf_val, 3)
            token_contributions.append({
                "token": token,
                "weight": round(weight, 3),
                "impact": impact_score,
                "direction": "phishing" if weight > 0 else "benign"
            })

        # Sort tokens by magnitude of impact
        token_contributions.sort(key=lambda x: abs(x["impact"]), reverse=True)

        label = "Suspicious / Phishing-like" if score >= 50.0 else "Benign / No strong phishing signal"

        return {
            "label": label,
            "score": score,
            "signals": signals,
            "model": preferred_model,
            "token_contributions": token_contributions[:10],
            "explanation": self._format_sms_explanation(signals, score, token_contributions)
        }

    def _format_sms_explanation(self, signals, score, tokens):
        phish_tokens = [t["token"] for t in tokens if t["direction"] == "phishing"][:5]
        benign_tokens = [t["token"] for t in tokens if t["direction"] == "benign"][:3]

        parts = []
        if signals:
            parts.append(f"Heuristic indicators detected: {', '.join(signals)}.")
        if phish_tokens:
            parts.append(f"Key words driving phishing score: {', '.join(phish_tokens)}.")
        if benign_tokens:
            parts.append(f"Words mitigating risk: {', '.join(benign_tokens)}.")

        if not parts:
            return f"Low confidence classification. Model screening score: {score}%."
        return " ".join(parts) + f" (Overall risk screening score: {score}%)"

    def analyze_url_xai(self, raw_url: str):
        """Analyzes a URL using lexical feature engineering and Random Forest ML model."""
        raw = str(raw_url).strip()
        feat_vec, feat_dict = extract_url_feature_vector(raw)
        
        # Scale and predict
        scaled = self.url_scaler.transform([feat_vec])
        rf_clf = self.url_models["Random Forest"]
        ml_prob = float(rf_clf.predict_proba(scaled)[0][1])
        ml_score = round(ml_prob * 100, 1)

        # Lexical reasons
        reasons = []
        if not feat_dict["is_https"]:
            reasons.append("Unencrypted connection (HTTP instead of HTTPS)")
        if feat_dict["has_ip"]:
            reasons.append("Host is an IP address rather than a registered domain")
        if feat_dict["has_at"]:
            reasons.append("Contains '@' symbol (often used for credential redirection)")
        if feat_dict["has_punycode"]:
            reasons.append("Punycode hostname detected (homograph phishing spoof)")
        if feat_dict["entropy"] > 3.6:
            reasons.append(f"Elevated domain entropy ({feat_dict['entropy']}), suggesting DGA or obfuscation")
        if feat_dict["terms_count"] > 0:
            reasons.append(f"Contains {feat_dict['terms_count']} sensitive/action keyword(s) in URL")
        if feat_dict["url_length"] > 75:
            reasons.append(f"Unusually long URL ({feat_dict['url_length']} characters)")

        # Combine ML probability with lexical rules
        combined_score = round(0.6 * ml_score + 0.4 * min(100.0, len(reasons) * 22.0), 1)
        if reasons and combined_score < 40.0:
            combined_score = min(95.0, len(reasons) * 20.0)

        label = "High Risk (Phishing / Malicious)" if combined_score >= 60.0 else (
            "Medium Risk (Suspicious Indicators)" if combined_score >= 30.0 else "Low Risk (Standard Lexical Profile)"
        )

        return {
            "label": label,
            "score": combined_score,
            "ml_score": ml_score,
            "features": feat_dict,
            "reasons": reasons,
            "model": "Random Forest + Lexical Feature Analysis",
            "explanation": ", ".join(reasons) if reasons else "No anomalous lexical or structural risk indicators found."
        }

    def get_benchmark_report(self):
        """Returns comprehensive academic benchmark metrics for the evaluation dashboard."""
        return {
            "sms": {
                "dataset_size": len(SMS_DATASET),
                "phishing_count": sum(1 for x in SMS_DATASET if x[1] == 1),
                "benign_count": sum(1 for x in SMS_DATASET if x[1] == 0),
                "models": self.sms_metrics,
                "top_features": self.top_sms_features
            },
            "url": {
                "dataset_size": len(URL_DATASET),
                "phishing_count": sum(1 for x in URL_DATASET if x[1] == 1),
                "benign_count": sum(1 for x in URL_DATASET if x[1] == 0),
                "models": self.url_metrics,
                "feature_names": [
                    "URL Length", "Host Length", "Dots Count", "Hyphen Count",
                    "Digit Count", "Shannon Entropy", "IP Address Host",
                    "Is HTTPS", "@ Symbol Present", "Punycode Host", "Sensitive Terms Count"
                ]
            }
        }

