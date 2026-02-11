from crypto_utils import load_store, save_store, create_user, check_fake_account, compute_hash
from datetime import datetime, timedelta
import os

DATA_FILE = os.path.join(os.path.dirname(__file__), 'data_store.json')


def ensure_user(path, username, password, bio=''):
    store = load_store(path)
    if username not in store['users']:
        create_user(path, username, password, bio)
        store = load_store(path)
    return store


def main():
    path = DATA_FILE
    now = datetime.utcnow()
    store = load_store(path)

    # 1) Very short username
    ensure_user(path, 'abc', 'Test@1234', bio='')

    # 2) Multiple failed logins (>3)
    ensure_user(path, 'userfail', 'Test@1234', bio='normal')
    store = load_store(path)
    store['users']['userfail']['failed_logins'] = 4

    # 3) Empty profile info
    ensure_user(path, 'emptybio', 'Test@1234', bio='')

    # 4) High message frequency (>5 in last 60s)
    ensure_user(path, 'fastsender', 'Test@1234', bio='i send fast')
    # Add 6 messages from fastsender with recent timestamps
    for i in range(6):
        t = (now - timedelta(seconds=i * 5)).isoformat()
        msg = {
            'sender': 'fastsender',
            'recipient': 'anyone',
            'ciphertext': 'DUMMY',
            'hash': compute_hash('DUMMY'),
            'key': 'SECRET',
            'timestamp': t
        }
        store['messages'].append(msg)

    save_store(path, store)

    # Re-load and check each user
    store = load_store(path)
    users_to_check = ['abc', 'userfail', 'emptybio', 'fastsender']
    for u in users_to_check:
        flagged = check_fake_account(store, u)
        print(f"User: {u}  -> Flagged: {flagged}")
        print('Record:', store['users'].get(u))
        print('---')


if __name__ == '__main__':
    main()
