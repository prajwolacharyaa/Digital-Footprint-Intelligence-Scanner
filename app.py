from flask import Flask, render_template, request, jsonify, make_response
from dotenv import load_dotenv
from services.hibp_service import get_breaches
from services.gravatar_service import get_gravatar
from services.threat_engine import calculate_threat, get_risk_label, get_recommendations
from services.free_risk_service import get_free_risk_signals
from datetime import datetime
import io
import re

load_dotenv()

app = Flask(__name__)
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


@app.route("/")
def home():
    return render_template("index.html")


def build_report(email):
    breaches_result = get_breaches(email)
    breaches = breaches_result.get("breaches", [])
    free_risk = get_free_risk_signals(email)
    threat = calculate_threat(breaches, breaches_result, free_risk)
    risk = get_risk_label(threat)

    return {
        "email": email,
        "breaches": breaches,
        "breach_count": len(breaches),
        "breach_source": breaches_result.get("source", "unknown"),
        "lookup_status": breaches_result.get("status", "unknown"),
        "lookup_message": breaches_result.get("message", ""),
        "free_risk": free_risk,
        "risk_signals": free_risk.get("signals", []),
        "gravatar": get_gravatar(email),
        "threat_score": threat,
        "risk": risk,
        "recommendations": get_recommendations(threat, breaches_result),
        "scanned_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
    }


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()

    if not email or not EMAIL_RE.match(email):
        return jsonify({"error": "Enter a valid email address before scanning."}), 400

    return jsonify(build_report(email))


def escape_pdf_text(value):
    return str(value).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def make_pdf(lines):
    stream = io.StringIO()
    stream.write("BT\n/F1 20 Tf\n50 780 Td\n")
    first = True
    for text, size, gap in lines:
        if first:
            first = False
        else:
            stream.write(f"0 -{gap} Td\n")
        stream.write(f"/F1 {size} Tf\n({escape_pdf_text(text)}) Tj\n")
    stream.write("ET")
    content = stream.getvalue().encode("latin-1", "replace")

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream",
    ]

    pdf = io.BytesIO()
    pdf.write(b"%PDF-1.4\n")
    offsets = []
    for index, obj in enumerate(objects, start=1):
        offsets.append(pdf.tell())
        pdf.write(f"{index} 0 obj\n".encode())
        pdf.write(obj)
        pdf.write(b"\nendobj\n")
    xref_at = pdf.tell()
    pdf.write(f"xref\n0 {len(objects) + 1}\n".encode())
    pdf.write(b"0000000000 65535 f \n")
    for offset in offsets:
        pdf.write(f"{offset:010d} 00000 n \n".encode())
    pdf.write(f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF".encode())
    return pdf.getvalue()


@app.route("/report/pdf", methods=["POST"])
def report_pdf():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()

    if not email or not EMAIL_RE.match(email):
        return jsonify({"error": "A valid email is required to build the PDF report."}), 400

    report = build_report(email)
    lines = [
        ("Digital Footprint Intelligence Report", 20, 24),
        (f"Email: {report['email']}", 12, 24),
        (f"Scanned at: {report['scanned_at']}", 12, 18),
        (f"Risk: {report['risk']} | Score: {report['threat_score']}/100", 14, 26),
        (f"Known breaches: {report['breach_count']}", 12, 22),
        (f"Lookup status: {report['lookup_message']}", 10, 20),
        (f"Free risk source: {report['free_risk'].get('source', 'free signals')}", 10, 20),
        ("Breaches", 14, 28),
    ]

    if report["breaches"]:
        for breach in report["breaches"][:12]:
            name = breach.get("Name", "Unknown breach")
            date = breach.get("BreachDate", "Unknown date")
            domain = breach.get("Domain", "")
            lines.append((f"- {name} {f'({domain})' if domain else ''} - {date}", 10, 16))
    else:
        lines.append(("- No public breaches were returned for this email.", 10, 16))

    lines.append(("Free Risk Signals", 14, 28))
    for signal in report.get("risk_signals", [])[:8]:
        lines.append((f"- {signal.get('label')}: {signal.get('detail')}", 9, 14))

    lines.append(("Recommendations", 14, 28))
    for item in report["recommendations"][:8]:
        lines.append((f"- {item}", 10, 16))

    pdf = make_pdf(lines)
    response = make_response(pdf)
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = f"attachment; filename=footprint-report-{email.replace('@', '-at-')}.pdf"
    return response


if __name__ == "__main__":
    app.run(debug=True)
