import os
import sqlite3
from functools import wraps
from urllib.parse import urljoin, urlparse

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from flask_wtf import CSRFProtect
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")
csrf = CSRFProtect(app)

DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")
RESET_SALT = "password-reset"
serializer = URLSafeTimedSerializer(app.secret_key)

COURSES = [
    {
        "id": "offensive",
        "title": "Offensive Security",
        "tagline": "Think like an attacker to defend better.",
        "icon": "🎯",
        "level": "Intermediate",
        "progress": 35,
        "lessons": [
            "Reconnaissance and OSINT fundamentals",
            "Web application vulnerability classes (OWASP Top 10)",
            "Network scanning and enumeration concepts",
            "Authentication and session weaknesses",
            "Reporting and responsible disclosure",
        ],
    },
    {
        "id": "defensive",
        "title": "Defensive Security",
        "tagline": "Detect, respond, and harden systems.",
        "icon": "🛡️",
        "level": "Beginner",
        "progress": 60,
        "lessons": [
            "Log analysis and SIEM basics",
            "The incident response lifecycle",
            "Threat hunting fundamentals",
            "Hardening and secure configuration",
            "Detection engineering basics",
        ],
    },
    {
        "id": "ai-security",
        "title": "AI & LLM Security",
        "tagline": "Securing machine learning systems.",
        "icon": "🤖",
        "level": "Advanced",
        "progress": 10,
        "lessons": [
            "Prompt injection: why it happens",
            "Data poisoning and model supply chain risk",
            "Output handling and sandboxing",
            "AI red teaming methodology",
            "Guardrails and evaluation",
        ],
    },
    {
        "id": "cloud-security",
        "title": "Cloud Security",
        "tagline": "Secure workloads across AWS, Azure, and GCP.",
        "icon": "☁️",
        "level": "Intermediate",
        "progress": 0,
        "lessons": [
            "Shared responsibility model explained",
            "Identity and access management fundamentals",
            "Network controls: VPCs, security groups, and segmentation",
            "Storage misconfiguration and data exposure",
            "Logging, monitoring, and cloud-native detection",
            "Container and Kubernetes security basics",
        ],
    },
    {
        "id": "edr",
        "title": "Endpoint Detection & Response",
        "tagline": "Detect, investigate, and respond to threats on the endpoint.",
        "icon": "🖥️",
        "level": "Intermediate",
        "progress": 0,
        "lessons": [
            "EDR architecture: sensors, telemetry, and cloud analytics",
            "Process, file, and network activity monitoring",
            "Behavioral detection vs. signature-based detection",
            "Triage and investigation of endpoint alerts",
            "Isolating and remediating compromised hosts",
            "Building detection rules from MITRE ATT&CK techniques",
        ],
    },
    {
        "id": "data-security",
        "title": "Data Security",
        "tagline": "Classify, protect, and govern data across its lifecycle.",
        "icon": "🔐",
        "level": "Intermediate",
        "progress": 0,
        "lessons": [
            "Data classification and sensitivity labeling",
            "Encryption at rest and in transit",
            "Data loss prevention (DLP) fundamentals",
            "Access control and least privilege for data stores",
            "Data masking, tokenization, and anonymization",
            "Compliance frameworks: GDPR, HIPAA, and PCI DSS basics",
        ],
    },
]


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(exception=None):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        """
    )
    db.commit()
    db.close()


init_db()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


@app.context_processor
def inject_user():
    return {"current_user_name": session.get("user_name")}


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not name or not email or not password:
            flash("Please fill in all fields.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
        else:
            db = get_db()
            existing = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
            if existing:
                flash("An account with that email already exists.", "error")
            else:
                db.execute(
                    "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                    (name, email, generate_password_hash(password)),
                )
                db.commit()
                flash("Account created. Please log in.", "success")
                return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            flash(f"Welcome back, {user['name']}!", "success")
            next_url = request.args.get("next", "")
            site_url = urlparse(request.host_url)
            redirect_url = urlparse(urljoin(request.host_url, next_url))
            if redirect_url.scheme in ("http", "https") and redirect_url.netloc == site_url.netloc:
                return redirect(next_url)
            return redirect(url_for("home"))

        flash("Invalid email or password.", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    reset_link = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        # Same message regardless of whether the account exists, so the
        # form can't be used to enumerate registered emails.
        flash("If an account exists for that email, a reset link is ready below.", "success")
        if user:
            token = serializer.dumps(email, salt=RESET_SALT)
            reset_link = url_for("reset_password", token=token, _external=True)

    return render_template("forgot_password.html", reset_link=reset_link)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = serializer.loads(token, salt=RESET_SALT, max_age=3600)
    except SignatureExpired:
        flash("That reset link has expired. Please request a new one.", "error")
        return redirect(url_for("forgot_password"))
    except BadSignature:
        flash("That reset link is invalid.", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        if password != confirm:
            flash("Passwords do not match.", "error")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
        else:
            db = get_db()
            db.execute(
                "UPDATE users SET password_hash = ? WHERE email = ?",
                (generate_password_hash(password), email),
            )
            db.commit()
            flash("Your password has been updated. Please log in.", "success")
            return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)


@app.route("/")
@login_required
def home():
    total = sum(len(c["lessons"]) for c in COURSES)
    return render_template("index.html", courses=COURSES, total_lessons=total)


@app.route("/course/<course_id>")
@login_required
def course(course_id):
    match = next((c for c in COURSES if c["id"] == course_id), None)
    if match is None:
        abort(404)
    return render_template("course.html", course=match)


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes"))