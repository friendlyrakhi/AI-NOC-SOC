"""Write the OpenAPI document: ``python -m app.tools.export_openapi [--check]``.

The committed ``backend/openapi/openapi.json`` is the API contract (docs/05 §intro). The
frontend generates its TypeScript types from it. ``--check`` fails if code and file differ.
"""

import json
import secrets
import sys
from pathlib import Path

from pydantic import SecretStr

from app.config import Settings
from app.main import create_app

OUT = Path(__file__).resolve().parents[2] / "openapi" / "openapi.json"


def render() -> str:
    app = create_app(Settings(master_key=SecretStr(secrets.token_hex(32))))
    return json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n"


def main(argv: list[str]) -> int:
    doc = render()
    if "--check" in argv:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != doc:
            print("openapi.json is out of date: run `uv run python -m app.tools.export_openapi`")
            return 1
        print("openapi.json is up to date")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(doc, encoding="utf-8", newline="\n")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
