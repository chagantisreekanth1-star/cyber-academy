from flask import Flask, render_template, abort

app = Flask(__name__)

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
]


@app.route("/")
def home():
    total = sum(len(c["lessons"]) for c in COURSES)
    return render_template("index.html", courses=COURSES, total_lessons=total)


@app.route("/course/<course_id>")
def course(course_id):
    match = next((c for c in COURSES if c["id"] == course_id), None)
    if match is None:
        abort(404)
    return render_template("course.html", course=match)


if __name__ == "__main__":
    app.run(debug=True)