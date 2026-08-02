import base64
import hashlib
import io
import logging
import os
import re
import secrets
import smtplib
import sqlite3
import time
from datetime import timedelta
from email.message import EmailMessage
from functools import wraps
from urllib.parse import urljoin, urlparse

import pyotp
import qrcode
from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from flask_wtf import CSRFProtect
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")
csrf = CSRFProtect(app)

logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")
RESET_SALT = "password-reset"
serializer = URLSafeTimedSerializer(app.secret_key)

MFA_ISSUER = "Cyber Academy"

IDLE_TIMEOUT_SECONDS = 300
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(seconds=IDLE_TIMEOUT_SECONDS)

MAIL_SERVER = os.environ.get("MAIL_SERVER")
MAIL_PORT = int(os.environ.get("MAIL_PORT", "587"))
MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
MAIL_USE_SSL = os.environ.get("MAIL_USE_SSL", "false").lower() in ("1", "true", "yes")
MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "true").lower() in ("1", "true", "yes") and not MAIL_USE_SSL
MAIL_FROM = os.environ.get("MAIL_FROM", MAIL_USERNAME)

EMAIL_OTP_TTL_SECONDS = 600
EMAIL_OTP_RESEND_COOLDOWN = 30

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
        "modules": [
            {
                "name": "Log Analysis & SIEM",
                "lessons": [
                    {
                        "title": "What logs are",
                        "description": "Understand what a log entry is — a timestamped record with a severity, source, and message — and where different systems write them.",
                        "content": [
                            "A log is a timestamped record of an event. Almost every system writes them: operating systems, web servers, firewalls, databases, applications, and network devices.",
                            "A single log entry (a \"log line\") typically contains a timestamp, a severity level, a source, and a message describing what happened. For example, a web server might record every request with the visitor's IP address, the page requested, and the response code.",
                        ],
                    },
                    {
                        "title": "Common types of logs",
                        "description": "Tell system, application, security, network, and audit logs apart, and know where each one lives on Linux and Windows.",
                        "content": [
                            "The main categories you'll encounter are system logs (OS-level events, startups, hardware issues), application logs (events from a specific program), security logs (logins, permission changes, access attempts), network logs (traffic, connections, firewall decisions), and audit logs (a trail of who did what, for compliance).",
                            "On Linux these often live in /var/log/; on Windows they're in the Event Viewer.",
                        ],
                    },
                    {
                        "title": "Why analyze logs",
                        "description": "See the four main reasons to analyze logs: troubleshooting, security monitoring, performance monitoring, and compliance.",
                        "content": [
                            "The main reasons are troubleshooting (finding why something broke), security monitoring (detecting intrusions, unusual access, or attacks), performance monitoring (spotting slowdowns and bottlenecks), and compliance/auditing (proving what happened for regulations like PCI-DSS or HIPAA).",
                        ],
                    },
                    {
                        "title": "The log analysis process",
                        "description": "Collect, normalize, parse, and correlate logs from multiple sources to turn scattered entries into a coherent picture.",
                        "content": [
                            "A typical workflow is: collect logs from all your sources into one place, normalize them into a consistent format so different sources can be compared, parse them to pull out fields (IP, timestamp, error code), then search, filter, and correlate events to find patterns.",
                            "Correlation is key — one log line rarely tells the whole story, but linking events across sources reveals what actually happened.",
                        ],
                    },
                    {
                        "title": "Log severity levels",
                        "description": "Use DEBUG through CRITICAL severity levels to filter out routine noise and focus on real problems.",
                        "content": [
                            "Most systems use levels roughly ordered as: DEBUG, INFO, WARN, ERROR, and CRITICAL/FATAL. Filtering by level lets you ignore routine noise and focus on problems.",
                        ],
                    },
                    {
                        "title": "Common tools",
                        "description": "Get comfortable with grep, awk, sed, and tail -f for quick digging, and know when a SIEM like the ELK Stack, Splunk, or Sentinel is the better tool.",
                        "content": [
                            "Basic command-line tools include grep (search), awk and sed (extract and transform), tail -f (watch logs live), and cut/sort/uniq for counting.",
                            "For larger environments, log management and SIEM platforms are used — the ELK/Elastic Stack (Elasticsearch, Logstash, Kibana), Splunk, Graylog, and Microsoft Sentinel are the ones most often mentioned in courses.",
                        ],
                    },
                    {
                        "title": "Key techniques",
                        "description": "Apply filtering, pattern recognition, anomaly detection, correlation, and visualization to make logs tell a story.",
                        "content": [
                            "The core techniques are filtering (narrowing to relevant entries), pattern recognition (spotting recurring errors), anomaly detection (flagging what deviates from normal), correlation (linking related events), and visualization (dashboards and charts that make trends obvious).",
                        ],
                    },
                    {
                        "title": "Worked example: finding brute-force logins",
                        "description": "Use grep on /var/log/auth.log to pull failed SSH attempts and spot a brute-force attack by counting attempts per IP.",
                        "content": [
                            "To find all failed SSH login attempts on a Linux server, you might run something like grep \"Failed password\" /var/log/auth.log, then pipe it through tools to count attempts per IP address — a spike from one IP suggests a brute-force attack.",
                        ],
                    },
                ],
            },
            {
                "name": "Splunk",
                "lessons": [
                    {
                        "title": "Splunk fundamentals & architecture",
                        "description": "See how forwarders, indexers, and search heads move data from input to indexing to search, with a tour of Splunk Web.",
                    },
                    {
                        "title": "Getting data in (data ingestion)",
                        "description": "Bring data into Splunk from files, monitored directories, and forwarders, and see how source types and indexes organize it.",
                    },
                    {
                        "title": "Search fundamentals (SPL)",
                        "description": "Write basic searches with keywords, Boolean operators, and the time range picker, and chain commands together with the pipe.",
                    },
                    {
                        "title": "Core SPL commands",
                        "description": "Shape and aggregate results with stats, chart, timechart, table, eval, and other everyday SPL commands.",
                    },
                    {
                        "title": "Fields",
                        "description": "Work with extracted and calculated fields, plus an intro to regex-based extraction, aliases, and lookups.",
                    },
                    {
                        "title": "Knowledge objects",
                        "description": "Save searches as reports and set up alerts that trigger on a schedule or in real time.",
                    },
                    {
                        "title": "Dashboards & visualizations",
                        "description": "Turn saved searches into dashboard panels and choose the right chart type for the data.",
                    },
                    {
                        "title": "Basic administration",
                        "description": "Get oriented on user roles and permissions, index management, and where Splunk's .conf files live.",
                    },
                ],
            },
            {
                "name": "Incident Response",
                "lessons": [
                    {
                        "title": "The incident response lifecycle",
                        "description": "Walk through preparation, detection, containment, eradication, and recovery for a security incident.",
                    },
                    {
                        "title": "Threat hunting fundamentals",
                        "description": "Proactively search for signs of compromise instead of waiting for an alert to fire.",
                    },
                ],
            },
            {
                "name": "Hardening & Detection",
                "lessons": [
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
        "id": "network-security",
        "title": "Network Security Fundamentals",
        "tagline": "Secure the network layer — from TCP/IP to next-gen firewalls and Zero Trust.",
        "icon": "🌐",
        "level": "Beginner",
        "progress": 0,
        "modules": [
            {
                "name": "Networking Foundations",
                "lessons": [
                    {
                        "title": "OSI models and TCP/IP protocols",
                        "description": "Understand how the OSI and TCP/IP models describe how data moves across a network.",
                    },
                    {
                        "title": "Network routing and infrastructure",
                        "description": "See how routers, switches, and routing protocols move traffic between networks.",
                    },
                    {
                        "title": "DHCP configuration",
                        "description": "Configure DHCP to automatically assign IP addresses and network settings to devices.",
                    },
                    {
                        "title": "Network administration and device management",
                        "description": "Manage network devices day to day: configuration, monitoring, and change control.",
                    },
                ],
            },
            {
                "name": "Network Security & Threat Mitigation",
                "lessons": [
                    {
                        "title": "Foundational network security concepts",
                        "description": "Cover the core principles that keep a network secure: confidentiality, integrity, and availability applied to network design.",
                    },
                    {
                        "title": "Secure network computing environment maintenance",
                        "description": "Keep a network environment secure over time through patching, monitoring, and configuration reviews.",
                    },
                    {
                        "title": "Network security threat identification and mitigation",
                        "description": "Identify common network-based threats and the controls used to mitigate them.",
                    },
                    {
                        "title": "Network isolation and appliance protection",
                        "description": "Segment networks and harden security appliances so a breach in one zone doesn't spread.",
                    },
                ],
            },
            {
                "name": "Firewalls, Zero Trust & Cryptography",
                "lessons": [
                    {
                        "title": "Next-generation firewall technologies",
                        "description": "Understand how NGFWs go beyond port and protocol filtering with app awareness and threat prevention.",
                    },
                    {
                        "title": "Zero Trust network access principles",
                        "description": "Apply \"never trust, always verify\" to network access instead of trusting anything inside the perimeter.",
                    },
                    {
                        "title": "Cryptography and encryption methods",
                        "description": "Cover the core encryption concepts that protect data as it moves across the network.",
                    },
                ],
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


def iter_lessons(course):
    if "modules" in course:
        for module in course["modules"]:
            yield from module["lessons"]
    else:
        yield from course["lessons"]


def slugify(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def find_lesson(course, slug):
    for lesson in iter_lessons(course):
        if lesson["slug"] == slug:
            return lesson
    return None


for _course in COURSES:
    _course["lesson_count"] = lesson_count(_course)
    for _lesson in iter_lessons(_course):
        _lesson["slug"] = slugify(_lesson["title"])


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
    existing_columns = {row[1] for row in db.execute("PRAGMA table_info(users)")}
    if "mfa_secret" not in existing_columns:
        db.execute("ALTER TABLE users ADD COLUMN mfa_secret TEXT")
    if "mfa_enabled" not in existing_columns:
        db.execute("ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0")
    if "mfa_method" not in existing_columns:
        db.execute("ALTER TABLE users ADD COLUMN mfa_method TEXT")
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


@app.before_request
def enforce_idle_timeout():
    if "user_id" not in session:
        return None

    now = time.time()
    last_activity = session.get("last_activity", now)
    if now - last_activity > IDLE_TIMEOUT_SECONDS:
        session.clear()
        flash("You've been logged out due to inactivity.", "error")
        return redirect(url_for("login", next=request.path))

    session["last_activity"] = now
    session.permanent = True
    return None


@app.context_processor
def inject_user():
    return {"current_user_name": session.get("user_name")}


def safe_redirect_target(next_url):
    if not next_url:
        return url_for("home")
    site_url = urlparse(request.host_url)
    redirect_url = urlparse(urljoin(request.host_url, next_url))
    if redirect_url.scheme in ("http", "https") and redirect_url.netloc == site_url.netloc:
        return next_url
    return url_for("home")


def complete_login(user):
    session.clear()
    session["user_id"] = user["id"]
    session["user_name"] = user["name"]


def qr_code_data_uri(uri):
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    encoded = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def generate_email_otp():
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_otp(code):
    return hashlib.sha256(code.encode()).hexdigest()


def send_email(to_address, subject, body):
    if not MAIL_SERVER or not MAIL_USERNAME or not MAIL_PASSWORD:
        raise RuntimeError(
            "Email is not configured. Set MAIL_SERVER, MAIL_USERNAME, and MAIL_PASSWORD."
        )
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = MAIL_FROM
    msg["To"] = to_address
    msg.set_content(body)

    try:
        if MAIL_USE_SSL:
            with smtplib.SMTP_SSL(MAIL_SERVER, MAIL_PORT, timeout=10) as smtp:
                smtp.login(MAIL_USERNAME, MAIL_PASSWORD)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(MAIL_SERVER, MAIL_PORT, timeout=10) as smtp:
                if MAIL_USE_TLS:
                    smtp.starttls()
                smtp.login(MAIL_USERNAME, MAIL_PASSWORD)
                smtp.send_message(msg)
    except Exception:
        app.logger.exception(
            "Failed to send email via %s:%s (ssl=%s, tls=%s, user=%s)",
            MAIL_SERVER, MAIL_PORT, MAIL_USE_SSL, MAIL_USE_TLS, MAIL_USERNAME,
        )
        raise


def send_otp_email(to_address, code):
    send_email(
        to_address,
        f"Your {MFA_ISSUER} verification code",
        f"Your verification code is {code}. It expires in 10 minutes.\n\n"
        "If you didn't request this, you can ignore this email.",
    )


def start_email_otp(user, prefix):
    code = generate_email_otp()
    session[f"{prefix}_hash"] = hash_otp(code)
    session[f"{prefix}_expires"] = time.time() + EMAIL_OTP_TTL_SECONDS
    session[f"{prefix}_sent_at"] = time.time()
    send_otp_email(user["email"], code)


def check_email_otp(code, prefix):
    code_hash = session.get(f"{prefix}_hash")
    expires = session.get(f"{prefix}_expires")
    if not code_hash or not expires or time.time() > expires:
        return False
    return hash_otp(code) == code_hash


def clear_email_otp(prefix):
    session.pop(f"{prefix}_hash", None)
    session.pop(f"{prefix}_expires", None)
    session.pop(f"{prefix}_sent_at", None)


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
            next_url = request.args.get("next", "")
            if user["mfa_enabled"]:
                session["mfa_user_id"] = user["id"]
                session["mfa_next"] = next_url
                if user["mfa_method"] == "email":
                    try:
                        start_email_otp(user, "mfa_login_email")
                    except Exception:
                        session.pop("mfa_user_id", None)
                        session.pop("mfa_next", None)
                        flash("We couldn't send a verification email. Please try again shortly.", "error")
                        return redirect(url_for("login"))
                    flash("We emailed you a 6-digit verification code.", "success")
                return redirect(url_for("mfa_verify"))

            complete_login(user)
            flash(f"Welcome back, {user['name']}!", "success")
            return redirect(safe_redirect_target(next_url))

        flash("Invalid email or password.", "error")

    return render_template("login.html")


@app.route("/mfa/verify", methods=["GET", "POST"])
def mfa_verify():
    user_id = session.get("mfa_user_id")
    if user_id is None:
        return redirect(url_for("login"))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None or not user["mfa_enabled"]:
        session.pop("mfa_user_id", None)
        session.pop("mfa_next", None)
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        if user["mfa_method"] == "email":
            valid = check_email_otp(code, "mfa_login_email")
        else:
            valid = pyotp.TOTP(user["mfa_secret"]).verify(code, valid_window=1)

        if valid:
            next_url = session.pop("mfa_next", "")
            session.pop("mfa_user_id", None)
            clear_email_otp("mfa_login_email")
            complete_login(user)
            flash(f"Welcome back, {user['name']}!", "success")
            return redirect(safe_redirect_target(next_url))

        flash("That code is invalid or has expired.", "error")

    return render_template("mfa_verify.html", mfa_method=user["mfa_method"], email=user["email"])


@app.route("/mfa/resend", methods=["POST"])
def mfa_resend():
    user_id = session.get("mfa_user_id")
    if user_id is None:
        return redirect(url_for("login"))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None or not user["mfa_enabled"] or user["mfa_method"] != "email":
        return redirect(url_for("mfa_verify"))

    last_sent = session.get("mfa_login_email_sent_at", 0)
    if time.time() - last_sent < EMAIL_OTP_RESEND_COOLDOWN:
        flash("Please wait a moment before requesting another code.", "error")
        return redirect(url_for("mfa_verify"))

    try:
        start_email_otp(user, "mfa_login_email")
        flash("We sent you a new code.", "success")
    except Exception:
        flash("We couldn't send a verification email. Please try again shortly.", "error")

    return redirect(url_for("mfa_verify"))


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
        flash("If an account exists for that email, a reset link is on its way.", "success")
        if user:
            token = serializer.dumps(email, salt=RESET_SALT)
            link = url_for("reset_password", token=token, _external=True)
            try:
                send_email(
                    user["email"],
                    f"Reset your {MFA_ISSUER} password",
                    "We received a request to reset your password. Use the link below "
                    f"within the next hour:\n\n{link}\n\n"
                    "If you didn't request this, you can ignore this email.",
                )
                app.logger.info("Password reset email accepted by SMTP server for %s", email)
            except Exception:
                reset_link = link
        else:
            app.logger.info("Password reset requested for unregistered email: %s", email)

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


@app.route("/security")
@login_required
def security():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    return render_template("security.html", mfa_enabled=bool(user["mfa_enabled"]), mfa_method=user["mfa_method"])


@app.route("/mfa/setup", methods=["GET", "POST"])
@login_required
def mfa_setup():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    if user["mfa_enabled"]:
        return redirect(url_for("security"))

    secret = session.get("mfa_setup_secret")
    if not secret:
        secret = pyotp.random_base32()
        session["mfa_setup_secret"] = secret

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        totp = pyotp.TOTP(secret)
        if totp.verify(code, valid_window=1):
            db.execute(
                "UPDATE users SET mfa_secret = ?, mfa_method = 'totp', mfa_enabled = 1 WHERE id = ?",
                (secret, user["id"]),
            )
            db.commit()
            session.pop("mfa_setup_secret", None)
            flash("Two-factor authentication is now enabled.", "success")
            return redirect(url_for("security"))

        flash("That code is invalid or has expired. Try the latest code from your app.", "error")

    provisioning_uri = pyotp.TOTP(secret).provisioning_uri(name=user["email"], issuer_name=MFA_ISSUER)
    qr_data_uri = qr_code_data_uri(provisioning_uri)
    return render_template("mfa_setup.html", secret=secret, qr_data_uri=qr_data_uri)


@app.route("/mfa/setup/email", methods=["GET", "POST"])
@login_required
def mfa_setup_email():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    if user["mfa_enabled"]:
        return redirect(url_for("security"))

    if request.method == "POST":
        if "resend" in request.form:
            last_sent = session.get("mfa_setup_email_sent_at", 0)
            if time.time() - last_sent < EMAIL_OTP_RESEND_COOLDOWN:
                flash("Please wait a moment before requesting another code.", "error")
            else:
                try:
                    start_email_otp(user, "mfa_setup_email")
                    flash("We sent you a new code.", "success")
                except Exception:
                    flash("We couldn't send a verification email. Please try again shortly.", "error")
        else:
            code = request.form.get("code", "").strip()
            if check_email_otp(code, "mfa_setup_email"):
                db.execute(
                    "UPDATE users SET mfa_method = 'email', mfa_secret = NULL, mfa_enabled = 1 WHERE id = ?",
                    (user["id"],),
                )
                db.commit()
                clear_email_otp("mfa_setup_email")
                flash("Two-factor authentication via email is now enabled.", "success")
                return redirect(url_for("security"))

            flash("That code is invalid or has expired.", "error")

    if "mfa_setup_email_hash" not in session:
        try:
            start_email_otp(user, "mfa_setup_email")
            flash("We emailed you a verification code.", "success")
        except Exception:
            flash("We couldn't send a verification email. Check your mail configuration and try again.", "error")

    return render_template("mfa_setup_email.html", email=user["email"])


@app.route("/mfa/disable", methods=["POST"])
@login_required
def mfa_disable():
    password = request.form.get("password", "")
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()

    if not check_password_hash(user["password_hash"], password):
        flash("Incorrect password.", "error")
    else:
        db.execute(
            "UPDATE users SET mfa_secret = NULL, mfa_method = NULL, mfa_enabled = 0 WHERE id = ?",
            (user["id"],),
        )
        db.commit()
        flash("Two-factor authentication has been disabled.", "success")

    return redirect(url_for("security"))


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


@app.route("/course/<course_id>/lesson/<lesson_slug>")
@login_required
def lesson(course_id, lesson_slug):
    course_match = next((c for c in COURSES if c["id"] == course_id), None)
    if course_match is None:
        abort(404)
    lesson_match = find_lesson(course_match, lesson_slug)
    if lesson_match is None:
        abort(404)
    return render_template("lesson.html", course=course_match, lesson=lesson_match)


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes"))