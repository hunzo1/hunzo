import os
import json
import secrets
from datetime import datetime
from functools import wraps
from flask import (Flask, render_template, request, jsonify,
                   session, redirect, url_for, g)
from dotenv import load_dotenv

load_dotenv()

from config import Config
from database import (init_db, get_user_by_id, save_check,
                      get_user_checks, get_user_stats, get_check_by_token,
                      get_api_key, save_api_key, delete_api_key,
                      get_daily_usage, increment_usage)
from auth import register_user, login_user
from crypto import encrypt_api_key, decrypt_api_key, mask_api_key
from analyzer import analyze_code

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY

# Init DB on startup
with app.app_context():
    init_db()

# ── Auth decorator ────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        g.user = get_user_by_id(session["user_id"])
        if not g.user:
            session.clear()
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ── Public routes ─────────────────────────────────────────
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method == "GET":
        return render_template("signup.html")
    data = request.get_json()
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()
    success, result = register_user(email, password)
    if success:
        session["user_id"] = result["id"]
        session.permanent = True
        return jsonify({"success": True, "redirect": "/dashboard"})
    return jsonify({"success": False, "error": result}), 400

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method == "GET":
        return render_template("login.html")
    data = request.get_json()
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()
    success, result = login_user(email, password)
    if success:
        session["user_id"] = result["id"]
        session.permanent = True
        return jsonify({"success": True, "redirect": "/dashboard"})
    return jsonify({"success": False, "error": result}), 401

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# ── Protected routes ──────────────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    stats = get_user_stats(g.user["id"])
    recent = get_user_checks(g.user["id"], limit=5)
    api_key_row = get_api_key(g.user["id"])
    masked_key = None
    if api_key_row:
        decrypted = decrypt_api_key(api_key_row["encrypted_key"])
        masked_key = mask_api_key(decrypted)
    return render_template("dashboard.html",
                           user=g.user,
                           stats=stats,
                           recent=recent,
                           masked_key=masked_key)

@app.route("/analyze")
@login_required
def analyze_page():
    api_key_row = get_api_key(g.user["id"])
    has_key = bool(api_key_row)
    masked_key = None
    if api_key_row:
        decrypted = decrypt_api_key(api_key_row["encrypted_key"])
        masked_key = mask_api_key(decrypted)
    return render_template("analyze.html",
                           user=g.user,
                           has_key=has_key,
                           masked_key=masked_key)

@app.route("/history")
@login_required
def history():
    checks = get_user_checks(g.user["id"], limit=50)
    return render_template("history.html",
                           user=g.user,
                           checks=checks)

@app.route("/settings")
@login_required
def settings():
    api_key_row = get_api_key(g.user["id"])
    masked_key = None
    if api_key_row:
        decrypted = decrypt_api_key(api_key_row["encrypted_key"])
        masked_key = mask_api_key(decrypted)
    return render_template("settings.html",
                           user=g.user,
                           masked_key=masked_key,
                           api_key_row=api_key_row)

# ── API endpoints ─────────────────────────────────────────
@app.route("/api/save-key", methods=["POST"])
@login_required
def api_save_key():
    data = request.get_json()
    api_key = data.get("api_key", "").strip()
    if not api_key:
        return jsonify({"error": "No API key provided"}), 400
    if not api_key.startswith("gsk_"):
        return jsonify({"error": "Invalid Groq API key format"}), 400
    encrypted = encrypt_api_key(api_key)
    save_api_key(g.user["id"], encrypted)
    masked = mask_api_key(api_key)
    return jsonify({"success": True, "masked_key": masked})

@app.route("/api/delete-key", methods=["POST"])
@login_required
def api_delete_key():
    delete_api_key(g.user["id"])
    return jsonify({"success": True})

@app.route("/api/analyze", methods=["POST"])
@login_required
def api_analyze():
    data = request.get_json()
    code = data.get("code", "").strip()
    use_saved = data.get("use_saved", True)

    if not code:
        return jsonify({"error": "No code provided"}), 400
    if len(code) > 15000:
        return jsonify({"error": "Code too long (max 15,000 chars)"}), 400

    # Get API key
    api_key = None
    if use_saved:
        key_row = get_api_key(g.user["id"])
        if key_row:
            api_key = decrypt_api_key(key_row["encrypted_key"])

    # Fallback to key in request
    if not api_key:
        api_key = data.get("api_key", "").strip()

    if not api_key:
        return jsonify({"error": "No API key found. Please add your Groq key in settings."}), 400

    # Check rate limit for free users
    if g.user["plan"] == "free":
        usage = get_daily_usage(user_id=g.user["id"])
        count = usage["check_count"] if usage else 0
        if count >= Config.FREE_DAILY_CHECKS:
            return jsonify({
                "error": f"Daily limit reached ({Config.FREE_DAILY_CHECKS} checks/day on free plan). Upgrade to Pro for unlimited checks."
            }), 429

    # Run analysis
    try:
        result = analyze_code(code, api_key)
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500

    # Generate share token
    share_token = secrets.token_urlsafe(16)

    # Save to history
    save_check(
        user_id=g.user["id"],
        code=code,
        language=result.get("language", "unknown"),
        score=result["trust_score"],
        risk_level=result["risks"]["risk_level"],
        packages_status=result["packages"]["status"],
        logic_sound=1 if result["logic"].get("logic_sound") else 0,
        full_report=json.dumps(result),
        share_token=share_token
    )

    # Update usage
    increment_usage(user_id=g.user["id"])

    # Update API key last used
    from database import update_api_key_last_used
    update_api_key_last_used(g.user["id"])

    result["share_token"] = share_token
    return jsonify(result)

@app.route("/report/<token>")
def shared_report(token):
    check = get_check_by_token(token)
    if not check:
        return "Report not found", 404
    report = json.loads(check["full_report"])
    return render_template("report.html", check=check, report=report)

@app.route("/health")
def health():
    return jsonify({"status": "ok", "app": "Hunzo"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
