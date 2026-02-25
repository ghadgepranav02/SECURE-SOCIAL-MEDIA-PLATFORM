import random
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta


def generate_otp(length: int = 6) -> str:
    """Return a random numeric OTP of given length.

    For academic simplicity we use `random.randint`; in production use a
    cryptographically secure generator like `secrets.choice`.
    """
    return ''.join(str(random.randint(0, 9)) for _ in range(length))


def send_otp_email(recipient: str, otp: str, config: dict) -> bool:
    """Attempt to send the OTP to `recipient` using SMTP parameters in
    `config`.

    The `config` dict is expected to contain at least:
      * server: smtp server address
      * port: smtp port (usually 587 for TLS)
      * username: login user
      * password: login password or app-specific password
      * sender: "from" address
      * otp_valid_minutes: (optional) used in message body

    Returns True on success (or simulation) and False on failure.

    Debugging helpers have been added so that the chosen configuration and
    any SMTP exception will be printed to the console.  This aids in
    diagnosing why an email never arrives.
    """
    print(f"[twofa_utils] send_otp_email called with config={config}")

    msg = EmailMessage()
    msg['Subject'] = 'Your SecureSocial OTP'
    msg['From'] = config.get('sender', config.get('username'))
    msg['To'] = recipient
    valid = config.get('otp_valid_minutes', 3)
    msg.set_content(
        f"Your one-time password (OTP) is: {otp}\n"
        f"It will expire in {valid} minutes."
    )

    # if no SMTP credentials have been provided, fall back to console output
    if not config.get('username') or not config.get('password'):
        # this makes it simple to test the OTP without a real email account
        print(f"[twofa_utils] (simulated email) OTP for {recipient}: {otp}")
        return True
    try:
        # choose SSL if port 465 is requested (Gmail alt + avoids some firewall blocks)
        if config.get('port') == 465:
            smtp_class = smtplib.SMTP_SSL
        else:
            smtp_class = smtplib.SMTP

        with smtp_class(config['server'], config['port']) as smtp:
            # For non-SSL connections we must start TLS explicitly
            if smtp_class is smtplib.SMTP:
                smtp.ehlo()
                smtp.starttls()
            smtp.login(config['username'], config['password'])
            smtp.send_message(msg)
        print(f"[twofa_utils] email sent successfully to {recipient}")
        return True
    except SystemExit as e:
        # smtplib may raise SystemExit when low-level socket exits,
        # catch it separately so our worker doesn't quit.
        print("[twofa_utils] SMTP connection failed (SystemExit):", e)
        return False
    except Exception as e:
        # printing instead of logging for academic clarity
        print("[twofa_utils] failed to send email:", e)
        return False


# helper for OTP expiration; used by app rather than storing logic here

def otp_expired(expiry_iso: str) -> bool:
    try:
        expiry = datetime.fromisoformat(expiry_iso)
        return datetime.utcnow() > expiry
    except Exception:
        return True
