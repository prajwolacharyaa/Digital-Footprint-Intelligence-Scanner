import hashlib


def get_gravatar(email):
    normalized = email.strip().lower().encode("utf-8")
    hashed = hashlib.md5(normalized).hexdigest()
    return f"https://www.gravatar.com/avatar/{hashed}?s=160&d=identicon&r=g"
