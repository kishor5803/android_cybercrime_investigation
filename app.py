import os, re, json, csv, sqlite3, hashlib, uuid, mimetypes
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from forensic import (
    sha256_file, parse_evidence_file, analyse_sms, analyse_url, analyse_apk,
    correlate_artifacts, build_timeline, explain_sms, explain_url
)
from ml_engine import ForensicMLEngine
from reporting import create_case_report

ROOT = Path(__file__).resolve().parent
UPLOAD_DIR = ROOT / "uploads"
REPORT_DIR = ROOT / "reports"
DB_PATH = ROOT / "instance" / "forensics.db"
ALLOWED_EXTENSIONS = {"csv", "json", "txt", "db", "sqlite", "sqlite3", "apk", "xml", "log"}
MAX_CONTENT_LENGTH = 50 * 1024 * 1024

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "CHANGE-ME-before-deployment-" + uuid.uuid4().hex)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

def db():
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'investigator'
        );
        CREATE TABLE IF NOT EXISTS cases(
          id INTEGER PRIMARY KEY, case_code TEXT UNIQUE NOT NULL, title TEXT NOT NULL, description TEXT,
          investigator TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS evidence(
          id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL, original_name TEXT NOT NULL, stored_name TEXT NOT NULL,
          file_type TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL, source TEXT, acquired_at TEXT,
          uploaded_at TEXT NOT NULL, FOREIGN KEY(case_id) REFERENCES cases(id)
        );
        CREATE TABLE IF NOT EXISTS artifacts(
          id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL, evidence_id INTEGER, artifact_type TEXT NOT NULL,
          event_time TEXT, content TEXT, indicator TEXT, risk_score REAL, details TEXT,
          FOREIGN KEY(case_id) REFERENCES cases(id), FOREIGN KEY(evidence_id) REFERENCES evidence(id)
        );
        CREATE TABLE IF NOT EXISTS audit(
          id INTEGER PRIMARY KEY, case_id INTEGER, action TEXT NOT NULL, detail TEXT, created_at TEXT NOT NULL
        );
        """)
        user = con.execute("SELECT id FROM users WHERE username='admin'").fetchone()
        if not user:
            username = os.environ.get("ADMIN_USERNAME", "admin")
            password = os.environ.get("ADMIN_PASSWORD", "ChangeThisPassword123!")
            con.execute("INSERT OR IGNORE INTO users(username,password_hash,role) VALUES(?,?,?)",
                        (username, generate_password_hash(password), "admin"))

def audit(case_id, action, detail=""):
    with db() as con:
        con.execute("INSERT INTO audit(case_id,action,detail,created_at) VALUES(?,?,?,?)",
                    (case_id, action, detail[:2000], datetime.now(timezone.utc).isoformat()))

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def allowed(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.errorhandler(413)
def too_large(_):
    flash("File exceeds the 50 MB upload limit.", "error")
    return redirect(request.referrer or url_for("dashboard"))

@app.route("/")
def index():
    return redirect(url_for("dashboard") if session.get("user") else url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with db() as con:
            user = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    with db() as con:
        cases = con.execute("SELECT * FROM cases ORDER BY id DESC LIMIT 8").fetchall()
        counts = {
            "cases": con.execute("SELECT COUNT(*) FROM cases").fetchone()[0],
            "evidence": con.execute("SELECT COUNT(*) FROM evidence").fetchone()[0],
            "artifacts": con.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0],
            "flags": con.execute("SELECT COUNT(*) FROM artifacts WHERE risk_score>=60").fetchone()[0]
        }
        recent = con.execute("""SELECT a.*,c.case_code FROM audit a LEFT JOIN cases c ON a.case_id=c.id
                                ORDER BY a.id DESC LIMIT 8""").fetchall()
    return render_template("dashboard.html", cases=cases, counts=counts, recent=recent)

@app.route("/cases", methods=["GET", "POST"])
@login_required
def cases():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        if not title:
            flash("Case title is required.", "error")
        else:
            code = "CASE-" + datetime.now().strftime("%y%m%d") + "-" + uuid.uuid4().hex[:6].upper()
            with db() as con:
                con.execute("INSERT INTO cases(case_code,title,description,investigator,created_at) VALUES(?,?,?,?,?)",
                            (code, title, description, session["user"], datetime.now(timezone.utc).isoformat()))
                cid = con.execute("SELECT last_insert_rowid()").fetchone()[0]
            audit(cid, "CASE_CREATED", title)
            return redirect(url_for("case_detail", case_id=cid))
    with db() as con:
        rows = con.execute("SELECT c.*,COUNT(e.id) evidence_count FROM cases c LEFT JOIN evidence e ON e.case_id=c.id GROUP BY c.id ORDER BY c.id DESC").fetchall()
    return render_template("cases.html", cases=rows)

@app.route("/case/<int:case_id>")
@login_required
def case_detail(case_id):
    with db() as con:
        case = con.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not case: abort(404)
        evidence = con.execute("SELECT * FROM evidence WHERE case_id=? ORDER BY id DESC", (case_id,)).fetchall()
        raw_artifacts = con.execute("SELECT * FROM artifacts WHERE case_id=? ORDER BY id DESC LIMIT 100", (case_id,)).fetchall()
        artifacts = []
        for r in raw_artifacts:
            item = dict(r)
            try:
                item["parsed_details"] = json.loads(item.get("details") or "{}")
            except Exception:
                item["parsed_details"] = {}
            artifacts.append(item)
        timeline = build_timeline([dict(x) for x in con.execute("SELECT * FROM artifacts WHERE case_id=? ORDER BY event_time", (case_id,)).fetchall()])
        audit_rows = con.execute("SELECT * FROM audit WHERE case_id=? ORDER BY id DESC LIMIT 15", (case_id,)).fetchall()
    return render_template("case_detail.html", case=case, evidence=evidence, artifacts=artifacts, timeline=timeline, audit_rows=audit_rows)

@app.route("/case/<int:case_id>/upload", methods=["POST"])
@login_required
def upload_evidence(case_id):
    with db() as con:
        case = con.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if not case: abort(404)
    f = request.files.get("evidence")
    if not f or not f.filename:
        flash("Choose an evidence file.", "error")
        return redirect(url_for("case_detail", case_id=case_id))
    if not allowed(f.filename):
        flash("Unsupported file type. Allowed: CSV, JSON, TXT, SQLite/DB, APK, XML, LOG.", "error")
        return redirect(url_for("case_detail", case_id=case_id))
    original = secure_filename(f.filename)
    stored = uuid.uuid4().hex + "_" + original
    target = UPLOAD_DIR / stored
    f.save(target)
    digest = sha256_file(target)
    ext = original.rsplit(".", 1)[-1].lower()
    source = request.form.get("source", "User-provided / authorised export")
    acquired = request.form.get("acquired_at", "")
    with db() as con:
        con.execute("""INSERT INTO evidence(case_id,original_name,stored_name,file_type,size,sha256,source,acquired_at,uploaded_at)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    (case_id, original, stored, ext, target.stat().st_size, digest, source, acquired,
                     datetime.now(timezone.utc).isoformat()))
        evidence_id = con.execute("SELECT last_insert_rowid()").fetchone()[0]
    audit(case_id, "EVIDENCE_UPLOADED", f"{original}; SHA-256={digest}")
    try:
        records = parse_evidence_file(target, ext)
        added = 0
        for rec in records:
            atype = rec.get("artifact_type", "record")
            content = str(rec.get("content", ""))[:10000]
            event_time = str(rec.get("event_time", ""))[:100]
            indicator = ""
            score = None
            details = {}
            if atype == "sms":
                result = analyse_sms(content)
                indicator, score = result["label"], result["score"]
                details = {
                    "explanation": explain_sms(result),
                    "model": result.get("model", ""),
                    "signals": result.get("signals", []),
                    "token_contributions": result.get("token_contributions", [])
                }
            elif atype == "url":
                result = analyse_url(content)
                indicator, score = result["label"], result["score"]
                details = {
                    "explanation": explain_url(result),
                    "features": result.get("features", {}),
                    "reasons": result.get("reasons", []),
                    "model": result.get("model", "")
                }
            elif atype == "apk":
                result = analyse_apk(target)
                indicator, score = result["label"], result["score"]
                details = result
            with db() as con:
                con.execute("""INSERT INTO artifacts(case_id,evidence_id,artifact_type,event_time,content,indicator,risk_score,details)
                                VALUES(?,?,?,?,?,?,?,?)""",
                            (case_id, evidence_id, atype, event_time, content, indicator, score, json.dumps(details)))
            added += 1
        audit(case_id, "EVIDENCE_PROCESSED", f"{added} artifact record(s) parsed")
        flash(f"Evidence preserved and processed. SHA-256: {digest[:20]}… | {added} artifact(s) extracted.", "success")
    except Exception as exc:
        audit(case_id, "PROCESSING_ERROR", str(exc))
        flash(f"Evidence stored and hashed, but parsing reported: {exc}", "error")
    return redirect(url_for("case_detail", case_id=case_id))

@app.route("/case/<int:case_id>/verify/<int:evidence_id>")
@login_required
def verify_evidence(case_id, evidence_id):
    with db() as con:
        row = con.execute("SELECT * FROM evidence WHERE id=? AND case_id=?", (evidence_id, case_id)).fetchone()
    if not row: abort(404)
    path = UPLOAD_DIR / row["stored_name"]
    current = sha256_file(path) if path.exists() else "MISSING"
    match = current == row["sha256"]
    audit(case_id, "HASH_VERIFIED", f"{row['original_name']}: {'MATCH' if match else 'MISMATCH'}")
    flash(f"Integrity {'verified: hash matches' if match else 'WARNING: hash mismatch or file missing'}.", "success" if match else "error")
    return redirect(url_for("case_detail", case_id=case_id))

@app.route("/case/<int:case_id>/analyse")
@login_required
def analyse_case(case_id):
    with db() as con:
        case = con.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        rows = [dict(r) for r in con.execute("SELECT * FROM artifacts WHERE case_id=?", (case_id,)).fetchall()]
    if not case: abort(404)
    links = correlate_artifacts(rows)
    audit(case_id, "CORRELATION_RUN", f"{len(links)} relationship(s) generated")
    return render_template("correlation.html", case=case, links=links)

@app.route("/case/<int:case_id>/report")
@login_required
def report(case_id):
    with db() as con:
        case = con.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not case: abort(404)
        evidence = [dict(x) for x in con.execute("SELECT * FROM evidence WHERE case_id=?", (case_id,)).fetchall()]
        artifacts = [dict(x) for x in con.execute("SELECT * FROM artifacts WHERE case_id=?", (case_id,)).fetchall()]
    path = REPORT_DIR / f"{case['case_code']}_investigation_report.pdf"
    create_case_report(dict(case), evidence, artifacts, path)
    audit(case_id, "REPORT_GENERATED", path.name)
    return send_file(path, as_attachment=True, download_name=path.name)

@app.route("/api/case/<int:case_id>/timeline")
@login_required
def timeline_api(case_id):
    with db() as con:
        rows = [dict(x) for x in con.execute("SELECT * FROM artifacts WHERE case_id=? ORDER BY event_time", (case_id,)).fetchall()]
    return {"events": build_timeline(rows)}

@app.route("/models")
@login_required
def models_dashboard():
    engine = ForensicMLEngine.get_instance()
    benchmarks = engine.get_benchmark_report()
    return render_template("models.html", benchmarks=benchmarks)

@app.route("/api/models/test", methods=["POST"])
@login_required
def models_test_api():
    data = request.get_json(silent=True) or {}
    mode = data.get("type", "sms").lower()
    text = data.get("input", "").strip()
    if not text:
        return {"error": "Input text cannot be empty."}, 400
    
    engine = ForensicMLEngine.get_instance()
    if mode == "sms":
        selected_model = data.get("model", "Logistic Regression")
        result = engine.analyze_sms_xai(text, preferred_model=selected_model)
        return {"status": "ok", "mode": "sms", "result": result}
    elif mode == "url":
        result = engine.analyze_url_xai(text)
        return {"status": "ok", "mode": "url", "result": result}
    return {"error": "Unsupported test mode."}, 400

@app.route("/health")
def health():
    return {"status": "ok", "application": "Android Cybercrime Investigation System"}

if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)
