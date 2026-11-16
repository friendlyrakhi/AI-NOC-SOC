"""Golden normalization tests: vendor payload -> expected normalized records.

Regenerate after an intentional mapping change and review the diff:
    uv run python connectors/catalog/tests/test_golden.py --regen
"""

import asyncio
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from nocsoc_connector_sdk import ConnectorContext, RawRecord
from nocsoc_connectors import REGISTRY

GOLDEN = Path(__file__).parent / "golden"
NOW = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
TENANT = "00000000-0000-4000-8000-0000000000aa"


def samples(connector_id: str) -> list[dict[str, object]]:
    cls = REGISTRY[connector_id]
    conn = cls(ConnectorContext(tenant_id=TENANT, instance_id="golden", clock=lambda: NOW))
    out = []
    for stream in cls.streams:
        rec = asyncio.run(conn.fetch(stream, None)).records[0]
        out.append({"stream": stream, "record": rec.model_dump(mode="json", by_alias=True)})
    if connector_id == "generic.webhook":
        conn = cls(
            ConnectorContext(tenant_id=TENANT, instance_id="golden", clock=lambda: NOW),
            {
                "title_path": "alert.name",
                "severity_path": "alert.level",
                "host_path": "target.host",
                "id_path": "alert.id",
            },
        )
        for stream, rec in conn.parse_webhook(
            {"alert": {"id": "abc-1", "name": "Disk full", "level": "critical"}, "target": {"host": "web-01"}}
        ):
            out.append({"stream": stream, "record": rec.model_dump(mode="json", by_alias=True)})
    return out


def expected(connector_id: str) -> list[dict[str, object]]:
    cls = REGISTRY[connector_id]
    return [
        {
            **s,
            "normalized": [
                n.model_dump(mode="json")
                for n in cls.normalize(str(s["stream"]), RawRecord.model_validate(s["record"]))
            ],
        }
        for s in samples(connector_id)
    ]


@pytest.mark.parametrize("connector_id", sorted(REGISTRY))
def test_golden(connector_id: str) -> None:
    path = GOLDEN / f"{connector_id}.json"
    assert path.exists(), f"missing golden file; run {__file__} --regen"
    cases = json.loads(path.read_text(encoding="utf-8"))
    cls = REGISTRY[connector_id]
    assert cases, "golden file has no cases"
    for case in cases:
        got = [
            n.model_dump(mode="json") for n in cls.normalize(case["stream"], RawRecord.model_validate(case["record"]))
        ]
        assert got == case["normalized"], f"{connector_id}/{case['stream']} normalization changed"


if __name__ == "__main__" and "--regen" in sys.argv:
    GOLDEN.mkdir(exist_ok=True)
    for cid in sorted(REGISTRY):
        (GOLDEN / f"{cid}.json").write_text(
            json.dumps(expected(cid), indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print("wrote", cid)
