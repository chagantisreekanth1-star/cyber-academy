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
        "modules": [
            {
                "name": "Reconnaissance",
                "lessons": [
                    {
                        "title": "Reconnaissance and OSINT fundamentals",
                        "description": "Gather intelligence on a target using public sources before ever touching its systems.",
                    },
                    {
                        "title": "Network scanning and enumeration concepts",
                        "description": "Map hosts, open ports, and running services to build a picture of the attack surface.",
                    },
                ],
            },
            {
                "name": "Web Application Attacks",
                "lessons": [
                    {
                        "title": "Web application vulnerability classes (OWASP Top 10)",
                        "description": "Survey the most common web flaws — injection, broken auth, XSS, and more — and how they're exploited.",
                    },
                    {
                        "title": "Authentication and session weaknesses",
                        "description": "Identify weak login flows, session fixation, and token handling issues attackers target first.",
                    },
                ],
            },
            {
                "name": "Reporting & Disclosure",
                "lessons": [
                    {
                        "title": "Reporting and responsible disclosure",
                        "description": "Turn findings into a clear report and disclose them to vendors in a way that gets fixes shipped.",
                    },
                ],
            },
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
            {
                "title": "Log analysis and SIEM basics",
                "description": "Read raw logs and use a SIEM to correlate events into signals worth investigating.",
            },
            {
                "title": "The incident response lifecycle",
                "description": "Walk through preparation, detection, containment, eradication, and recovery for a security incident.",
            },
            {
                "title": "Threat hunting fundamentals",
                "description": "Proactively search for signs of compromise instead of waiting for an alert to fire.",
            },
            {
                "title": "Hardening and secure configuration",
                "description": "Reduce attack surface by locking down default settings, services, and permissions.",
            },
            {
                "title": "Detection engineering basics",
                "description": "Write detection rules that catch real attacker behavior without drowning the team in noise.",
            },
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
            {
                "title": "Prompt injection: why it happens",
                "description": "Understand how untrusted input can hijack an LLM's instructions and steer its behavior.",
            },
            {
                "title": "Data poisoning and model supply chain risk",
                "description": "See how tainted training data or third-party models can compromise a system downstream.",
            },
            {
                "title": "Output handling and sandboxing",
                "description": "Treat model output as untrusted input and contain what it's allowed to do next.",
            },
            {
                "title": "AI red teaming methodology",
                "description": "Systematically probe a model for jailbreaks, leakage, and unsafe behavior before attackers do.",
            },
            {
                "title": "Guardrails and evaluation",
                "description": "Build and test guardrails that catch unsafe requests and responses in production.",
            },
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
            {
                "title": "Shared responsibility model explained",
                "description": "Draw the line between what your cloud provider secures and what's on you.",
            },
            {
                "title": "Identity and access management fundamentals",
                "description": "Design least-privilege roles and policies so a single compromised credential can't take down everything.",
            },
            {
                "title": "Network controls: VPCs, security groups, and segmentation",
                "description": "Isolate workloads and control traffic flow with virtual networks and firewall rules.",
            },
            {
                "title": "Storage misconfiguration and data exposure",
                "description": "Spot the bucket and database misconfigurations that lead to public data leaks.",
            },
            {
                "title": "Logging, monitoring, and cloud-native detection",
                "description": "Turn on the right cloud logs and alerts to catch suspicious activity as it happens.",
            },
            {
                "title": "Container and Kubernetes security basics",
                "description": "Secure images, runtime configuration, and cluster access for containerized workloads.",
            },
        ],
    },
    {
        "id": "edr",
        "title": "Endpoint Detection & Response",
        "tagline": "Detect, investigate, and respond to threats on the endpoint.",
        "icon": "🖥️",
        "level": "Intermediate",
        "progress": 0,
        "modules": [
            {
                "name": "Detection & Response",
                "lessons": [
                    {
                        "title": "EDR architecture: sensors, telemetry, and cloud analytics",
                        "description": "See how endpoint sensors collect telemetry and feed it to cloud-based detection engines.",
                    },
                    {
                        "title": "Process, file, and network activity monitoring",
                        "description": "Track what's running, what's changing on disk, and what's talking to the network.",
                    },
                    {
                        "title": "Behavioral detection vs. signature-based detection",
                        "description": "Compare catching known bad hashes against catching suspicious patterns of behavior.",
                    },
                    {
                        "title": "Triage and investigation of endpoint alerts",
                        "description": "Work through an EDR alert queue to separate real threats from noise.",
                    },
                    {
                        "title": "Isolating and remediating compromised hosts",
                        "description": "Contain an infected endpoint and clean it up without tipping off the attacker.",
                    },
                    {
                        "title": "Building detection rules from MITRE ATT&CK techniques",
                        "description": "Map real attacker techniques to detection logic using the ATT&CK framework.",
                    },
                ],
            },
            {
                "name": "Vulnerability Management",
                "lessons": [
                    {
                        "title": "Vulnerability scanning fundamentals",
                        "description": "Run authenticated and unauthenticated scans to discover missing patches and misconfigurations on endpoints.",
                    },
                    {
                        "title": "CVSS scoring and prioritization",
                        "description": "Score vulnerabilities by severity and exploitability to decide what to remediate first.",
                    },
                    {
                        "title": "Patch management and remediation workflows",
                        "description": "Move from a scan finding to a deployed fix without breaking production systems.",
                    },
                    {
                        "title": "Vulnerability assessment reporting",
                        "description": "Communicate risk to stakeholders and track remediation progress over time.",
                    },
                ],
            },
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
            {
                "title": "Data classification and sensitivity labeling",
                "description": "Sort data by sensitivity so the right controls get applied to the right assets.",
            },
            {
                "title": "Encryption at rest and in transit",
                "description": "Protect data as it's stored and as it moves between systems.",
            },
            {
                "title": "Data loss prevention (DLP) fundamentals",
                "description": "Detect and block sensitive data from leaving through email, uploads, or removable media.",
            },
            {
                "title": "Access control and least privilege for data stores",
                "description": "Limit who and what can read or write sensitive data to only what's necessary.",
            },
            {
                "title": "Data masking, tokenization, and anonymization",
                "description": "Reduce exposure by replacing real sensitive values with safe substitutes where possible.",
            },
            {
                "title": "Compliance frameworks: GDPR, HIPAA, and PCI DSS basics",
                "description": "Get oriented on the major data-protection regulations and what they require.",
            },
        ],
    },
]


def lesson_count(course):
    if "modules" in course:
        return sum(len(module["lessons"]) for module in course["modules"])
    return len(course["lessons"])


for _course in COURSES:
    _course["lesson_count"] = lesson_count(_course)


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
    total = sum(c["lesson_count"] for c in COURSES)
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