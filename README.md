# Secure Social Media Platform (Academic Demo)

This small Flask application demonstrates classical cryptography concepts from a cryptography & system security syllabus. It focuses on privacy, authentication, encryption (Product Cipher: Playfair + Columnar Transposition), integrity (hashing), and simple rule-based fake-account detection.

Contents
- `app.py`: Flask application (routes for register, login, compose, view message).
- `playfair.py`: Playfair cipher implementation (encrypt/decrypt).
- `transposition.py`: Columnar transposition cipher (encrypt/decrypt).
- `crypto_utils.py`: Password hashing (PBKDF2), password strength checker, store helpers, integrity hashing, fake-account checks.
- `twofa_utils.py`: helper functions for generating and emailing one-time passwords (OTP) and checking expiration.
- `data_store.json`: Simple JSON store for users and messages.
- `templates/` and `static/`: minimal UI
- `requirements.txt`: dependencies

Architecture & Folder Structure (after 2FA upgrade)

- css_project/
  - app.py                     – main Flask application (registration, login, 2FA, messaging)
  - playfair.py                – Playfair cipher routines
  - transposition.py           – Columnar transposition routines
  - crypto_utils.py            – hashing, strength checks, fake-account rules
  - twofa_utils.py             – OTP generation, expiration logic, email sender
  - data_store.json            – simple JSON database for users and messages
  - requirements.txt           – Python dependencies (Flask)
  - templates/                 – HTML templates (now includes verify_otp.html)
  - static/                    – CSS files

How to run (Windows)

1. Create a virtualenv and install dependencies:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

2. Set optional environment variables for OTP email delivery (Gmail example):

```powershell
$env:OTP_SMTP_USER="your@gmail.com"        # SMTP login
$env:OTP_SMTP_PASS="your‑app‑password"      # app password or smtp password
$env:OTP_SMTP_SENDER="your@gmail.com"      # From address
$env:OTP_SMTP_SERVER="smtp.gmail.com"      # default: smtp.gmail.com
$env:OTP_SMTP_PORT="587"                   # default: 587 (TLS)
$env:OTP_VALID_MINUTES="3"                 # OTP expiry window (2‑5 minutes)
```

If you omit `OTP_SMTP_USER`/`OTP_SMTP_PASS`, the app will automatically
print each generated OTP to the console instead of trying to send an email –
this makes it very easy to test the 2FA logic without any mail setup.

3. Run the app:

```powershell
python app.py
```

4. Open http://127.0.0.1:5000 in a browser.

Design & Explanation (for report / viva)

1) User Authentication Module
- Registration collects username, password, email and optional bio. Email is required for the 2FA step that follows a correct password.
- Password strength checker (`crypto_utils.password_strength`) enforces: minimum 8 chars, mixed case, digits and special chars. Shows Weak/Medium/Strong.
- Passwords stored securely using PBKDF2-HMAC-SHA256 with 100k iterations and a random 16-byte salt. Stored as `salt_hex:dk_hex`.
- After a correct password is entered during login, the server generates a 6‑digit one-time password (OTP), stores it in the session along with an expiry timestamp (configurable 2–5 minutes), and sends the OTP via email to the address on file.
- The `/verify_otp` route prompts the user for the code. Only when the entered OTP matches and is within the expiry window is the session `username` set and the dashboard/license granted.

Why PBKDF2? It demonstrates hashing with salt and stretching to resist brute-force (educational; in production use well-tested libs).

2) Secure Messaging Module (Product Cipher)
- Encryption flow: Plaintext -> Playfair -> Columnar Transposition -> store ciphertext.

---

### New Module: Two‑Factor Authentication (2FA)

After the traditional username/password step the application requires a second
verification factor. This is implemented as an **email‑based one‑time password
(OTP)**, demonstrating the concept of time‑based tokens and showing how 2FA
strengthens authentication.

* **OTP generation** is a 6‑digit numeric code produced with simple random
  numbers (`twofa_utils.generate_otp`). While not cryptographically strong, it
  suffices for the academic demo. In a real system a time‑based algorithm (e.g.
  TOTP) and secure RNG should be used.
* **OTP expiry**: the code is valid for a short window (configurable 2–5

> NOTE: requirements.txt has been reduced to Flask & gunicorn for Render deployment.
> Render logged Python 3.13 even though `runtime.txt` specifies 3.10.13; you can override the version in the service settings if needed.

  minutes). Upon generation the server stores both the code and an ISO
  timestamp in the Flask session (`otp_expiry`). When the user submits the
  code the server checks the current time against the expiry; if the timestamp
  has passed the OTP is rejected and the login flow restarts.
* **Delivery**: the code is sent using Python's built-in `smtplib` to a
  Gmail SMTP server (or any other SMTP service). The SMTP credentials are read
  from environment variables to avoid hard‑coding secrets (`OTP_SMTP_USER`,
  `OTP_SMTP_PASS`, etc.). For the viva you can either configure a real Gmail
  account (using an app password) or simply modify `twofa_utils.send_otp_email`
  to print the OTP to console.

**Flow overview (see flowchart later):**
1. User submits username and password.
2. Server verifies password using existing PBKDF2 logic.
3. If valid, server calls `generate_otp()` and computes expiry time.
4. OTP and expiry are stored in `session` and the code is emailed.
5. User is redirected to `/verify_otp` where they enter the code.
6. Server checks code match and expiry; on success, session is finalised and
   user enters the dashboard. On failure or timeout the login attempt is
   aborted.

Security rationale:

* A stolen password alone is not enough to access the account; the attacker
  also needs the OTP sent to the victim's email.
* Time‑limiting the OTP prevents brute‑forcing because attackers only have a
  few minutes to guess the code before it changes or expires.
* 2FA mitigates account takeover, phishing, and brute‑force attacks, which are
  common threats in social media contexts.

This module is designed to be simple enough for viva explanation yet powerful
enough to illustrate how an additional authentication factor improves security.

---
- Playfair: substitution digraph cipher using a 5x5 key table (I/J combined). Steps:
  1. Prepare key table (remove duplicates, fill alphabet without J).
  2. Preprocess plaintext (remove non-letters, convert J->I, create digraphs inserting X between identical letters, pad final pair with X if needed).
  3. For each digraph apply Playfair rules: same row -> shift right; same column -> shift down; rectangle -> swap columns.
- Columnar Transposition: treat Playfair output, write row-wise into a grid with column count = key length, read columns according to alphabetical order of key letters. For decryption reverse the process.

Example encryption steps (for viva):
- Plaintext: HELLO
- Playfair (key=SECRET) -> intermediate_cipher
- Transposition (key=SECRET) -> final_ciphertext

Decryption reverses: Transposition decrypt -> Playfair decrypt -> get plaintext (note padding X may appear).

3) Data Integrity Module
- Each stored message includes SHA-256 hash of the final ciphertext (`crypto_utils.compute_hash`).
- When viewing a message the app recomputes the hash and compares; if mismatch displays "Data Tampered".

4) Fake Account Detection Module (rule-based)
- Rules implemented in `crypto_utils.check_fake_account`:
  - Very short username (len < 4)
  - Multiple failed logins (>3)
  - Empty profile info (bio missing)
  - High message frequency (>5 messages in last 60s)
- If any rule triggers the user is `flagged` and dashboard shows this.

Optional Concepts (explanation-only)
- Diffie-Hellman key exchange: explain steps, group, shared secret derivation. (Not implemented; include in report as conceptual secure channel establishment.)
- Public-key encryption concept: explain RSA/ECC basics and how they'd replace shared symmetric keys for key-exchange.

Security justification
- Passwords: salted PBKDF2 reduces risk of offline brute-force.
- Integrity: SHA-256 detects message tampering.
- Product cipher: combining substitution (Playfair) and permutation (transposition) demonstrates confusion and diffusion principles from Claude Shannon.

Limitations & Possible Improvements
- Key management: currently the encryption key is a shared secret entered manually. Implement Diffie-Hellman for ephemeral shared keys.
- Use TLS for server transport (Flask dev server is not TLS).
- The 2FA email step uses plain SMTP. In production use a trusted third‑party service or enforce stronger rate limiting and monitor for OTP abuse.
- Replace classical ciphers with modern authenticated encryption (AES-GCM) for production.
- Store messages in a proper DB and apply access control, rate limiting, and logging.

Flowchart (brief)
- User registers -> Password hashed -> stored
- User logs in -> session created
- Compose message -> Playfair encrypt -> Transposition encrypt -> hash -> store
- View message -> verify hash -> decrypt transposition -> decrypt Playfair -> display or report tampered

Mapping to course outcomes (CO1–CO4)
- CO1 (Understand classical ciphers): Playfair and transposition implemented and documented.
- CO2 (Apply hashing & integrity): PBKDF2 + SHA-256 used for auth and message integrity.
- CO3 (Authentication & session security): registration/login flows, password policy, failed login handling.
- CO4 (Threat analysis and detection): rule-based fake-account detection and tamper checks.

Files of interest
- `app.py` (run server) — [app.py](app.py)
- `playfair.py` (algorithm) — [playfair.py](playfair.py)
- `transposition.py` (algorithm) — [transposition.py](transposition.py)
- `crypto_utils.py` (hashing & detection) — [crypto_utils.py](crypto_utils.py)
