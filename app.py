from flask import Flask, render_template, request, jsonify
from services.hibp_service import get_breaches
from services.gravatar_service import get_gravatar
from services.threat_engine import calculate_threat

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    email = data.get("email")

    breaches = get_breaches(email)
    gravatar = get_gravatar(email)
    threat_score = calculate_threat(breaches)

    if threat_score >= 70:
        risk = "CRITICAL"
    elif threat_score >= 50:
        risk = "HIGH"
    elif threat_score >= 20:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return jsonify({
        "email": email,
        "breaches": breaches,
        "gravatar": gravatar,
        "threat_score": threat_score,
        "risk": risk,
        "recommendations": [
            "Enable MFA",
            "Use unique passwords",
            "Rotate compromised passwords"
        ]
    })

if __name__ == "__main__":
    app.run(debug=True)