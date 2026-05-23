import os
import re
import socket
import requests

DISPOSABLE_DOMAINS = {
    "10minutemail.com",
    "guerrillamail.com",
    "mailinator.com",
    "tempmail.com",
    "temp-mail.org",
    "yopmail.com",
    "throwawaymail.com",
    "sharklasers.com",
    "getnada.com",
    "trashmail.com",
    "fakeinbox.com",
    "dispostable.com",
}

COMMON_PROVIDERS = {
    "gmail.com",
    "outlook.com",
    "hotmail.com",
    "icloud.com",
    "yahoo.com",
    "proton.me",
    "protonmail.com",
    "aol.com",
}

RISKY_TLDS = {"zip", "mov", "top", "xyz", "click", "country", "stream", "gq", "tk", "work"}
ROLE_PREFIXES = {"admin", "support", "info", "contact", "sales", "billing", "security", "help"}
RANDOMISH_RE = re.compile(r"^(?=.*\d)[a-z0-9._%+-]{16,}$")


def _add_signal(signals, label, status, impact, detail):
    signals.append({
        "label": label,
        "status": status,
        "impact": impact,
        "detail": detail,
    })


def _domain_exists(domain):
    try:
        socket.getaddrinfo(domain, None)
        return True
    except socket.gaierror:
        return False


def _gravatar_exists(email):
    digest_url = requests.utils.quote(email.strip().lower(), safe="")
    # Gravatar lookup still needs the MD5 hash in the URL; import locally to keep this service standalone.
    import hashlib
    hashed = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
    url = f"https://www.gravatar.com/avatar/{hashed}?d=404"
    try:
        response = requests.get(url, timeout=6, allow_redirects=False)
        return response.status_code == 200
    except requests.RequestException:
        return None


def _emailrep_lookup(email):
    key = os.getenv("EMAILREP_API_KEY")
    if not key:
        return None

    try:
        response = requests.get(
            f"https://emailrep.io/{email}",
            headers={"Key": key, "User-Agent": "Digital-Footprint-Intelligence-Scanner"},
            timeout=10,
        )
    except requests.RequestException:
        return None

    if response.status_code != 200:
        return None
    return response.json()


def get_free_risk_signals(email):
    local, domain = email.rsplit("@", 1)
    tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
    signals = []
    score = 0

    if domain in DISPOSABLE_DOMAINS:
        score += 35
        _add_signal(signals, "Disposable email domain", "warning", 35, "Temporary inbox domains are commonly used for throwaway accounts and abuse.")
    else:
        _add_signal(signals, "Disposable email domain", "good", 0, "Domain is not in the built-in disposable provider list.")

    exists = _domain_exists(domain)
    if exists:
        _add_signal(signals, "Domain resolves", "good", 0, "The email domain resolves in DNS.")
    else:
        score += 25
        _add_signal(signals, "Domain resolves", "warning", 25, "The email domain did not resolve from this machine.")

    if domain in COMMON_PROVIDERS:
        _add_signal(signals, "Provider reputation", "good", 0, "This is a common mailbox provider.")
    elif exists:
        score += 8
        _add_signal(signals, "Provider reputation", "info", 8, "Custom or less common domains need extra context.")

    if tld in RISKY_TLDS:
        score += 15
        _add_signal(signals, "TLD risk", "warning", 15, f".{tld} is often overrepresented in spam or abuse datasets.")
    else:
        _add_signal(signals, "TLD risk", "good", 0, "Top-level domain is not on the local risky-TLD list.")

    if local in ROLE_PREFIXES:
        score += 10
        _add_signal(signals, "Role account", "info", 10, "Role inboxes are public-facing and receive more unsolicited mail.")
    elif RANDOMISH_RE.match(local):
        score += 12
        _add_signal(signals, "Address pattern", "info", 12, "The local part looks random or auto-generated.")
    else:
        _add_signal(signals, "Address pattern", "good", 0, "The local part does not look disposable or auto-generated.")

    gravatar = _gravatar_exists(email)
    if gravatar is True:
        score += 8
        _add_signal(signals, "Public Gravatar", "info", 8, "A public Gravatar avatar exists, which means the email has some public footprint.")
    elif gravatar is False:
        _add_signal(signals, "Public Gravatar", "good", 0, "No public Gravatar avatar was found.")
    else:
        _add_signal(signals, "Public Gravatar", "info", 0, "Could not check Gravatar from this network.")

    emailrep = _emailrep_lookup(email)
    if emailrep:
        details = emailrep.get("details", {})
        if emailrep.get("suspicious"):
            score += 35
            _add_signal(signals, "EmailRep suspicious", "warning", 35, "EmailRep marked this address as suspicious.")
        if details.get("credentials_leaked") or details.get("data_breach"):
            score += 30
            _add_signal(signals, "EmailRep exposure", "warning", 30, "EmailRep reports leaked credentials or breach exposure.")
        if details.get("spam") or details.get("malicious_activity"):
            score += 30
            _add_signal(signals, "EmailRep abuse", "warning", 30, "EmailRep reports spam or malicious activity signals.")
        if not any(signal["label"].startswith("EmailRep") for signal in signals):
            _add_signal(signals, "EmailRep", "good", 0, "EmailRep returned no high-risk indicators.")
    else:
        _add_signal(signals, "EmailRep", "info", 0, "Optional: add a free EMAILREP_API_KEY for richer reputation checks.")

    return {
        "score": min(score, 100),
        "signals": signals,
        "source": "free_local_signals" if not emailrep else "free_local_signals+emailrep",
        "message": "Free risk score generated from domain, pattern, Gravatar, and optional EmailRep signals.",
    }
