"""Print the current TOTP code for a dev user: ``python -m app.tools.totp <email>``.

Reads infrastructure/secrets/dev-users.json (written by ``scripts/dev seed``). Dev only.
"""

import json
import sys
from pathlib import Path

from app.core.security import current_totp

DEV_USERS = Path(__file__).resolve().parents[3] / "infrastructure" / "secrets" / "dev-users.json"


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: python -m app.tools.totp <email>")
        return 2
    users = json.loads(DEV_USERS.read_text(encoding="utf-8"))["users"]
    match = next((u for u in users if u["email"].lower() == argv[0].lower()), None)
    if match is None or not match.get("totp_secret"):
        print("no TOTP secret for that user (unknown user, or MFA not required)")
        return 1
    print(current_totp(match["totp_secret"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
