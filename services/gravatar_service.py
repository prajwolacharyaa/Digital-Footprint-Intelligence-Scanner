import hashlib

def get_gravatar(email):
    hashed = hashlib.md5(email.strip().lower().encode()).hexdigest()
    return f"https://www.gravatar.com/avatar/{hashed}"