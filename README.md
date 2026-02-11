# Secure Social Media Platform (Academic Demo)

This small Flask application demonstrates classical cryptography concepts from a cryptography & system security syllabus. It focuses on privacy, authentication, encryption (Product Cipher: Playfair + Columnar Transposition), integrity (hashing), and simple rule-based fake-account detection.

Contents
- `app.py`: Flask application (routes for register, login, compose, view message).
- `playfair.py`: Playfair cipher implementation (encrypt/decrypt).
- `transposition.py`: Columnar transposition cipher (encrypt/decrypt).
- `crypto_utils.py`: Password hashing (PBKDF2), password strength checker, store helpers, integrity hashing, fake-account checks.
- `data_store.json`: Simple JSON store for users and messages.
- `templates/` and `static/`: minimal UI
- `requirements.txt`: dependencies

Architecture & Folder Structure

- css_project/
  - app.py
  - playfair.py
  - transposition.py
  - crypto_utils.py
  - data_store.json
  - requirements.txt
  - templates/
  - static/

How to run (Windows)

1. Create a virtualenv and install dependencies:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

2. Run the app:

```powershell
python app.py
```

3. Open http://127.0.0.1:5000 in a browser.

Design & Explanation (for report / viva)

1) User Authentication Module
- Registration collects username, password and optional bio.
- Password strength checker (`crypto_utils.password_strength`) enforces: minimum 8 chars, mixed case, digits and special chars. Shows Weak/Medium/Strong.
- Passwords stored securely using PBKDF2-HMAC-SHA256 with 100k iterations and a random 16-byte salt. Stored as `salt_hex:dk_hex`.

Why PBKDF2? It demonstrates hashing with salt and stretching to resist brute-force (educational; in production use well-tested libs).

2) Secure Messaging Module (Product Cipher)
- Encryption flow: Plaintext -> Playfair -> Columnar Transposition -> store ciphertext.
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
