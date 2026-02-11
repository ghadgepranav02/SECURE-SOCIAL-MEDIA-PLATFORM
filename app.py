from flask import Flask, render_template, request, redirect, url_for, session, flash
from datetime import datetime, timedelta
import os
from playfair import playfair_encrypt, playfair_decrypt
from transposition import transposition_encrypt, transposition_decrypt
from crypto_utils import (
    load_store, save_store, create_user, verify_password, password_strength,
    compute_hash, check_fake_account
)

app = Flask(__name__)
app.secret_key = os.urandom(24)

DATA_FILE = os.path.join(os.path.dirname(__file__), 'data_store.json')


@app.before_first_request
def ensure_store():
    load_store(DATA_FILE)


@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        bio = request.form.get('bio', '')
        strength = password_strength(password)
        store = load_store(DATA_FILE)
        if username in store['users']:
            flash('Username already exists')
        elif strength == 'Weak':
            flash('Password too weak')
        else:
            create_user(DATA_FILE, username, password, bio)
            flash('Registered successfully. Please log in.')
            return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        store = load_store(DATA_FILE)
        user = store['users'].get(username)
        if not user:
            flash('Invalid credentials')
            return render_template('login.html')
        ok = verify_password(user['password_hash'], password)
        if ok:
            session['username'] = username
            # Keep failed_logins count (don't reset) - stays flagged if accumulated >3
            save_store(DATA_FILE, store)
            return redirect(url_for('dashboard'))
        else:
            user['failed_logins'] = user.get('failed_logins', 0) + 1
            if user['failed_logins'] > 3:
                user['flagged'] = True
            save_store(DATA_FILE, store)
            flash('Invalid credentials')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    store = load_store(DATA_FILE)
    user = store['users'].get(username, {})
    # flag suspicious accounts
    user['flagged'] = check_fake_account(store, username)
    save_store(DATA_FILE, store)
    inbox = []
    for idx, m in enumerate(store['messages']):
        if m['recipient'] == username:
            sender_flagged = check_fake_account(store, m['sender'])
            inbox.append({'idx': idx, 'm': m, 'sender_flagged': sender_flagged})
    sent = [{'idx': idx, 'm': m} for idx, m in enumerate(store['messages']) if m['sender'] == username]
    return render_template('dashboard.html', user=user, inbox=inbox, sent=sent)


@app.route('/compose', methods=['GET', 'POST'])
def compose():
    if 'username' not in session:
        return redirect(url_for('login'))
    store = load_store(DATA_FILE)
    usernames = list(store['users'].keys())
    if request.method == 'POST':
        sender = session['username']
        recipient = request.form['recipient']
        plaintext = request.form['message']
        key = request.form.get('key') or 'SECRET'
        # encryption: Playfair then Columnar Transposition
        step1 = playfair_encrypt(plaintext, key)
        ciphertext = transposition_encrypt(step1, key)
        msg_hash = compute_hash(ciphertext)
        msg = {
            'sender': sender,
            'recipient': recipient,
            'ciphertext': ciphertext,
            'hash': msg_hash,
            'key': key,
            'timestamp': datetime.utcnow().isoformat()
        }
        store['messages'].append(msg)
        save_store(DATA_FILE, store)
        flash('Message sent (encrypted)')
        return redirect(url_for('dashboard'))
    return render_template('compose.html', users=usernames)


@app.route('/message/<int:idx>')
def view_message(idx):
    if 'username' not in session:
        return redirect(url_for('login'))
    store = load_store(DATA_FILE)
    try:
        msg = store['messages'][idx]
    except IndexError:
        flash('Message not found')
        return redirect(url_for('dashboard'))
    # verify ownership
    if session['username'] not in (msg['recipient'], msg['sender']):
        flash('Access denied')
        return redirect(url_for('dashboard'))
    # check if sender is flagged
    sender = msg['sender']
    sender_user = store['users'].get(sender, {})
    sender_flagged = check_fake_account(store, sender)
    # verify integrity
    current_hash = compute_hash(msg['ciphertext'])
    tampered = current_hash != msg['hash']
    plaintext = None
    if not tampered:
        step1 = transposition_decrypt(msg['ciphertext'], msg['key'])
        plaintext = playfair_decrypt(step1, msg['key'])
    return render_template('message_view.html', msg=msg, plaintext=plaintext, tampered=tampered, sender_flagged=sender_flagged, idx=idx)


if __name__ == '__main__':
    app.run(debug=True)
