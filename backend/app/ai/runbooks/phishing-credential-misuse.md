# Phishing followed by credential misuse

Applies when a user clicks a phishing link and suspicious sign-ins follow.

Signs: email click alert from the endpoint tool, impossible-travel or improbable-access alerts, repeated MFA push requests (MFA fatigue) for the same user.

Steps:
1. Verify the sign-ins with the user through a known channel.
2. Revoke the user's sessions and reset credentials; review MFA methods.
3. Search for the same sender, URL and attachment across mailboxes.
4. Check for mailbox rules, OAuth grants and new MFA devices added by the attacker.
5. Containment actions such as session revocation require approval.
