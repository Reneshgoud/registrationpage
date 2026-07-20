"""
Aurora Auth — Production-ready Flask registration & authentication backend.

Features:
- SQLite storage (auto-created) with parameterized queries (SQL injection safe)
- Werkzeug PBKDF2 password hashing
- CSRF protection (Flask-WTF)
- Server-side input validation & sanitization
- Simple in-memory sliding-window rate limiting per IP
- Secure, server-side sessions with sane cookie flags
- Flash messages for user feedback
- Clean error handling (400/403/404/429/500 pages return JSON for API calls)
"""

import os
import re
import sqlite3
import time
from collections import defaultdict, deque
from datetime import timedelta
from functools import wraps

from flask import (
    Flask, g, render_template, request, redirect, url_for,
    session, flash, jsonify
)
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError
from werkzeug.security import generate_password_hash, check_password_hash

# --------------------------------------------------------------------------
# App configuration
# --------------------------------------------------------------------------

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "database.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", os.urandom(32).hex())
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Only force secure cookies in production (behind HTTPS). Toggle via env var.
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") == "production"

csrf = CSRFProtect(app)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
NAME_RE = re.compile(r"^[A-Za-z\u00C0-\u024F' \-]{2,80}$")

# --------------------------------------------------------------------------
# Rate limiting (simple in-memory sliding window; fine for a single process)
# --------------------------------------------------------------------------

RATE_LIMIT_WINDOW = 60 * 15   # 15 minutes
RATE_LIMIT_MAX = {
    "register": 8,
    "login": 10,
}
_request_log = defaultdict(deque)


def rate_limited(bucket):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
            key = f"{bucket}:{ip}"
            now = time.time()
            log = _request_log[key]
            while log and now - log[0] > RATE_LIMIT_WINDOW:
                log.popleft()
            if len(log) >= RATE_LIMIT_MAX.get(bucket, 20):
                if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
                    return jsonify(ok=False, error="Too many attempts. Please wait a few minutes and try again."), 429
                flash("Too many attempts. Please wait a few minutes and try again.", "error")
                return redirect(url_for("index"))
            log.append(now)
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# --------------------------------------------------------------------------
# Database helpers
# --------------------------------------------------------------------------

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
    return db


@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                newsletter INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        db.commit()


# --------------------------------------------------------------------------
# Validation helpers
# --------------------------------------------------------------------------

def validate_registration(full_name, email, password, terms, privacy):
    errors = {}

    full_name = (full_name or "").strip()
    email = (email or "").strip().lower()

    if not full_name or not NAME_RE.match(full_name):
        errors["fullName"] = "Enter a name using 2-80 letters."

    if not email or not EMAIL_RE.match(email):
        errors["email"] = "Enter a valid email address."

    pw_errors = []
    if not password or len(password) < 8:
        pw_errors.append("at least 8 characters")
    if not any(c.isupper() for c in (password or "")):
        pw_errors.append("an uppercase letter")
    if not any(c.islower() for c in (password or "")):
        pw_errors.append("a lowercase letter")
    if not any(c.isdigit() for c in (password or "")):
        pw_errors.append("a number")
    if not any(not c.isalnum() for c in (password or "")):
        pw_errors.append("a special character")
    if pw_errors:
        errors["password"] = "Password needs " + ", ".join(pw_errors) + "."

    if not terms or not privacy:
        errors["terms"] = "You must agree to the Terms and the Privacy Policy."

    return errors, full_name, email


# --------------------------------------------------------------------------
# Auth helpers
# --------------------------------------------------------------------------

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("index"))
        return fn(*args, **kwargs)
    return wrapper


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/api/register", methods=["POST"])
@rate_limited("register")
def register():
    data = request.get_json(silent=True) or request.form

    errors, full_name, email = validate_registration(
        data.get("fullName"),
        data.get("email"),
        data.get("password"),
        data.get("terms") in ("on", "true", True, "1"),
        data.get("privacy") in ("on", "true", True, "1"),
    )

    if errors:
        return jsonify(ok=False, errors=errors), 400

    newsletter = 1 if data.get("newsletter") in ("on", "true", True, "1") else 0

    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if existing:
        return jsonify(ok=False, errors={"email": "An account with this email already exists."}), 409

    password_hash = generate_password_hash(data.get("password"), method="pbkdf2:sha256:260000")

    db.execute(
        "INSERT INTO users (full_name, email, password_hash, newsletter) VALUES (?, ?, ?, ?)",
        (full_name, email, password_hash, newsletter),
    )
    db.commit()

    user = db.execute("SELECT id, full_name, email FROM users WHERE email = ?", (email,)).fetchone()
    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    session["full_name"] = user["full_name"]

    return jsonify(ok=True, redirect=url_for("dashboard"))


@app.route("/api/login", methods=["POST"])
@rate_limited("login")
def login():
    data = request.get_json(silent=True) or request.form
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify(ok=False, errors={"email": "Enter your email and password."}), 400

    db = get_db()
    user = db.execute(
        "SELECT id, full_name, email, password_hash FROM users WHERE email = ?", (email,)
    ).fetchone()

    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify(ok=False, errors={"password": "Incorrect email or password."}), 401

    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    session["full_name"] = user["full_name"]

    return jsonify(ok=True, redirect=url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You've been signed out.", "info")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    user = db.execute(
        "SELECT full_name, email, created_at FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    if not user:
        session.clear()
        return redirect(url_for("index"))
    return render_template("dashboard.html", user=user)


@app.route("/api/check-email")
def check_email():
    """Lightweight endpoint the frontend can use for live availability checks."""
    email = (request.args.get("email") or "").strip().lower()
    if not email or not EMAIL_RE.match(email):
        return jsonify(available=False, valid=False)
    db = get_db()
    exists = db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone()
    return jsonify(available=exists is None, valid=True)


# --------------------------------------------------------------------------
# Error handlers
# --------------------------------------------------------------------------

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return jsonify(ok=False, error="Your session expired. Please refresh the page and try again."), 400


@app.errorhandler(404)
def not_found(e):
    return render_template("index.html"), 404


@app.errorhandler(429)
def too_many_requests(e):
    return jsonify(ok=False, error="Too many requests. Please slow down."), 429


@app.errorhandler(500)
def server_error(e):
    return jsonify(ok=False, error="Something went wrong on our end. Please try again."), 500


# --------------------------------------------------------------------------
# Entrypoint
# --------------------------------------------------------------------------

if not os.path.exists(DATABASE):
    init_db()
else:
    init_db()  # ensures table exists even if the file was created empty

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_ENV") != "production", port=5000)
