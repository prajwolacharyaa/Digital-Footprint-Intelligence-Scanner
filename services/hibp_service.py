import os
import requests

HIBP_API = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
USER_AGENT = "Digital-Footprint-Intelligence-Scanner"


def _normalize_breach(item):
    return {
        "Name": item.get("Name", "Unknown"),
        "Title": item.get("Title") or item.get("Name", "Unknown"),
        "Domain": item.get("Domain", ""),
        "BreachDate": item.get("BreachDate", "Unknown"),
        "PwnCount": item.get("PwnCount", 0),
        "DataClasses": item.get("DataClasses", []),
        "IsVerified": item.get("IsVerified", False),
        "IsSensitive": item.get("IsSensitive", False),
    }


def get_breaches(email):
    api_key = os.getenv("HIBP_API_KEY")
    if not api_key:
        return {
            "status": "api_key_missing",
            "source": "hibp",
            "message": "",
            "breaches": [],
        }

    headers = {
        "hibp-api-key": api_key,
        "user-agent": USER_AGENT,
    }
    params = {
        "truncateResponse": "false",
    }

    try:
        response = requests.get(HIBP_API.format(email=email), headers=headers, params=params, timeout=12)
    except requests.RequestException as exc:
        return {
            "status": "network_error",
            "source": "hibp",
            "message": f"Could not reach HIBP: {exc}",
            "breaches": [],
        }

    if response.status_code == 200:
        return {
            "status": "ok",
            "source": "hibp",
            "message": "Live HIBP lookup completed.",
            "breaches": [_normalize_breach(item) for item in response.json()],
        }

    if response.status_code == 404:
        return {
            "status": "ok",
            "source": "hibp",
            "message": "",
            "breaches": [],
        }

    if response.status_code in (401, 403):
        message = ""
    elif response.status_code == 429:
        message = "HIBP rate limit reached. Try again later."
    else:
        message = f"HIBP returned HTTP {response.status_code}."

    return {
        "status": "lookup_error",
        "source": "hibp",
        "message": message,
        "breaches": [],
    }
