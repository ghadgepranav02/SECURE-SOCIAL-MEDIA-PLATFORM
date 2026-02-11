import os
import json
import hashlib
import binascii
import time
from datetime import datetime, timedelta


def load_store(path):
    if not os.path.exists(path):
        store = {'users': {}, 'messages': []}
        with open(path, 'w') as f:
            json.dump(store, f, indent=2)
        return store
    with open(path, 'r') as f:
        return json.load(f)


def save_store(path, store):
    with open(path, 'w') as f:
        json.dump(store, f, indent=2)


def create_user(path, username, password, bio=''):
    store = load_store(path)
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    password_hash = salt.hex() + ':' + dk.hex()
    store['users'][username] = {
        'password_hash': password_hash,
        'bio': bio,
        'failed_logins': 0,
        'created': datetime.utcnow().isoformat(),
        'flagged': False
    }
    save_store(path, store)


def verify_password(stored_hash, password_attempt):
    try:
        salt_hex, dk_hex = stored_hash.split(':')
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(dk_hex)
        test = hashlib.pbkdf2_hmac('sha256', password_attempt.encode(), salt, 100000)
        return binascii.hexlify(test) == binascii.hexlify(expected)
    except Exception:
        return False


def password_strength(password):
    score = 0
    if len(password) >= 8:
        score += 1
    if any(c.islower() for c in password) and any(c.isupper() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in '!@#$%^&*()-_=+[]{};:,.<>/?' for c in password):
        score += 1
    if score <= 1:
        return 'Weak'
    if score == 2 or score == 3:
        return 'Medium'
    return 'Strong'


def compute_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()


def check_fake_account(store, username):
    user = store['users'].get(username, {})
    # rules
    short_username = len(username) < 4
    many_failed = user.get('failed_logins', 0) > 3
    empty_profile = not user.get('bio')
    # high message frequency: >5 messages sent in last 60 seconds
    now = datetime.utcnow()
    msgs = [m for m in store['messages'] if m['sender'] == username]
    recent = 0
    for m in msgs:
        t = datetime.fromisoformat(m['timestamp'])
        if now - t <= timedelta(seconds=60):
            recent += 1
    high_freq = recent > 5
    return short_username or many_failed or empty_profile or high_freq
