# FAKE ACCOUNT DETECTION MODULE DEMO
# Shows all 4 detection rules in action

from crypto_utils import load_store, check_fake_account
from datetime import datetime, timedelta

def main():
    store = load_store('data_store.json')

    print("=" * 70)
    print("FAKE ACCOUNT DETECTION - 4 DETECTION RULES")
    print("=" * 70)

    print("\nRULE 1: Very short username (< 4 characters)")
    print("RULE 2: Multiple failed logins (> 3 failed attempts)")
    print("RULE 3: Empty profile info (no bio)")
    print("RULE 4: High message frequency (> 5 messages in 60s)")

    print("\n" + "=" * 70)
    print("CURRENT DATA STORE ANALYSIS:")
    print("=" * 70)

    for username in store['users'].keys():
        user = store['users'][username]
        flagged = check_fake_account(store, username)
        
        # Extract individual rule checks
        short_user = len(username) < 4
        many_failed = user.get('failed_logins', 0) > 3
        empty_bio = not user.get('bio')
        
        now = datetime.now(datetime.UTC) if hasattr(datetime, 'UTC') else datetime.utcnow()
        msgs = [m for m in store['messages'] if m['sender'] == username]
        recent = sum(1 for m in msgs if now - datetime.fromisoformat(m['timestamp'].replace('Z', '+00:00')) <= timedelta(seconds=60))
        high_freq = recent > 5
        
        result = "FLAGGED" if flagged else "OK"
        print(f"\n[{result}] {username}")
        print(f"    Rule 1 (short name < 4): {short_user} [len={len(username)}]")
        print(f"    Rule 2 (failed login > 3): {many_failed} [count={user.get('failed_logins', 0)}]")
        print(f"    Rule 3 (empty bio): {empty_bio}")
        print(f"    Rule 4 (high freq >5 msgs/60s): {high_freq} [recent={recent}]")
        if flagged:
            triggers = []
            if short_user: triggers.append("Rule1-ShortName")
            if many_failed: triggers.append("Rule2-FailedLogins")
            if empty_bio: triggers.append("Rule3-EmptyBio")
            if high_freq: triggers.append("Rule4-HighFreq")
            print(f"    TRIGGERS: {', '.join(triggers)}")

    print("\n" + "=" * 70)
    print("UI DISPLAY:")
    print("  - Dashboard: Shows 'Flagged: Yes/No' at top")
    print("  - Inbox: Shows [FAKE] badge next to flagged sender")
    print("  - Message view: Shows WARNING alert if sender flagged")
    print("=" * 70)

if __name__ == '__main__':
    main()
