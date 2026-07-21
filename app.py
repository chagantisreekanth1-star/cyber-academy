from flask import Flask, render_template, abort

app = Flask(__name__)

COURSES = [
    {
        "id": "offensive",
        "title": "Offensive Security",
        "tagline": "Think like an attacker to defend better.",
        "lessons": [
            "Reconnaissance and OSINT fundamentals",
            "Web application vulnerability classes (OWASP Top 10)",
            "Network scanning concepts",
            "Reporting and responsible disclosure",
        ],
    },
    {
        "id": "defensive",
        "title": "Defensive Security",
        "tagline": "Detect, respond, and harden.",
        "lessons": [
            "Log analysis and SIEM basics",
            "Incident response lifecycle",
            "Threat hunting fundamentals",
            "Hardening and secure configuration",
        ],
    },
    {
        "id": "ai-security",
        "title": "AI & LLM Security",
        "tagline": "Securing machine learning systems.",
        "lessons": [
            "Prompt injection and why it happens",
            "Data poisoning and model supply chain risk",
            "Output handling and sandboxing",
            "AI red teaming methodology",
        ],
    },
]


@app.route("/")
def home():
    return render_template("index.html", courses=COURSES)


@app.route("/course/<course_id>")
def course(course_id):
    match = next((c for c in COURSES if c["id"] == course_id), None)
    if match is None:
        abort(404)
    return render_template("course.html", course=match)


if __name__ == "__main__":
    app.run(debug=True)