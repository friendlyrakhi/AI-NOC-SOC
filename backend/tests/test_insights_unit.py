"""P6 unit tests: the search façade (SEC-ISO-03), KPI arithmetic, CSV neutralisation, PDF output."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from app.analytics import tenant_setting
from app.kpis import build_kpis
from app.pdf import Document
from app.reports import safe_cell
from app.searchstore import (
    EventQuery,
    entities_index,
    entity_document,
    entity_query_body,
    event_document,
    event_query_body,
    events_index,
    events_pattern,
)

T1 = uuid.UUID("11111111-1111-1111-1111-111111111111")
T2 = uuid.UUID("22222222-2222-2222-2222-222222222222")


# ---------------------------------------------------------------- index names come only from the tenant
def test_index_names_are_derived_from_the_tenant_only() -> None:
    at = datetime(2026, 11, 17, tzinfo=UTC)
    assert events_index(T1, at) == "t-11111111111111111111111111111111-events-2026.11"
    assert events_pattern(T1) == "t-11111111111111111111111111111111-events-*"
    assert entities_index(T1) == "t-11111111111111111111111111111111-entities"
    assert events_pattern(T1) != events_pattern(T2)
    with pytest.raises(ValueError, match="badly formed"):
        events_pattern("t-*,other")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "query",
    [
        EventQuery(),
        EventQuery(text="*"),
        EventQuery(text="mimikatz OR *", domain="soc", severity=["high"], ip="10.0.0.1", mitre=["T1003"]),
    ],
)
def test_every_event_query_filters_on_the_tenant(query: EventQuery) -> None:
    body = event_query_body(T1, query, size=10, aggregations=True)
    filters = body["query"]["bool"]["filter"]
    assert {"term": {"tenant_id": str(T1)}} in filters
    assert "script" not in json.dumps(body)


def test_entity_query_filters_on_tenant_and_permitted_kinds() -> None:
    body = entity_query_body(T2, "INC-000001", ["incident"], 5)
    assert body["query"]["bool"]["filter"] == [{"term": {"tenant_id": str(T2)}}, {"terms": {"kind": ["incident"]}}]
    assert body["query"]["bool"]["must"][0]["simple_query_string"]["query"] == "INC-000001*"


@pytest.mark.parametrize(
    "raw",
    [
        {"index": "t-*"},
        {"tenant_id": str(T2)},
        {"query": {"match_all": {}}},
        {"mitre": ["T1059; DROP"]},
        {"ip": "999.1.1.1"},
        {"connector": "Bad Name"},
        {"text": "x" * 301},
    ],
)
def test_event_query_rejects_anything_outside_the_contract(raw: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        EventQuery.model_validate(raw)


def test_event_query_window_is_bounded() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValueError, match="30 days"):
        EventQuery(since=now - timedelta(days=31), until=now).window()
    with pytest.raises(ValueError, match="30 days"):
        EventQuery(since=now, until=now - timedelta(hours=1)).window()
    since, until = EventQuery().window(now)
    assert until - since == timedelta(hours=24)


def test_documents_carry_their_tenant_and_drop_bad_ips() -> None:
    cols = [
        "tenant_id",
        "event_id",
        "domain",
        "class",
        "severity",
        "observed_at",
        "connector",
        "instance_id",
        "source_id",
        "title",
        "asset",
        "actor_user",
        "src_ip",
        "dst_ip",
        "outcome",
        "mitre",
        "attributes",
    ]
    row = [T1, "e1", "soc", "detection", "high", datetime(2026, 11, 17, 10), "x", T2, "s", "t", "", "",
           "not-an-ip", "10.0.0.2", "", [], '{"k": "v"}']  # fmt: skip
    index, doc_id, doc = event_document(row, cols)
    assert index == events_index(T1, datetime(2026, 11, 17, tzinfo=UTC)) and doc_id == "e1"
    assert doc["tenant_id"] == str(T1) and "src_ip" not in doc and doc["dst_ip"] == "10.0.0.2"
    index, doc_id, doc = entity_document(T2, "incident", "abc", title="x", subtitle="")
    assert index == entities_index(T2) and doc_id == "incident:abc" and "subtitle" not in doc


def test_clickhouse_tenant_setting_never_empty() -> None:
    assert tenant_setting(T1) == str(T1)
    assert tenant_setting([T1, T2]) == f"{T1},{T2}"
    for bad in (None, []):
        with pytest.raises(ValueError, match="require a tenant"):
            tenant_setting(bad)
    with pytest.raises(ValueError, match="badly formed"):
        tenant_setting(["x' OR 1=1"])  # type: ignore[list-item]


# ---------------------------------------------------------------- KPI arithmetic
def test_kpis_from_counts() -> None:
    k = {
        x.key: x
        for x in build_kpis(
            {
                "total": 4,
                "open": 1,
                "acked": 2,
                "ack_ms": 120_000,
                "resolved": 1,
                "res_ms": 3_600_000,
                "ack_due": 4,
                "ack_met": 3,
                "res_due": 2,
                "res_met": 1,
                "automated": 1,
            },
            {"total": 10, "not_escalated": 7},
        )
    }
    assert k["incidents_opened"].value == 4 and k["open_incidents"].basis == 1
    assert k["mtta"].value == 60 and k["mttr"].value == 3600
    assert k["ack_sla"].value == 0.75 and (k["ack_sla"].numerator, k["ack_sla"].basis) == (3, 4)
    assert k["automation_rate"].value == 0.25 and k["noise_ratio"].value == 0.7


def test_kpis_without_data_are_empty_not_zero() -> None:
    k = {x.key: x for x in build_kpis({}, {})}
    assert k["mtta"].value is None and k["ack_sla"].value is None and k["noise_ratio"].value is None
    assert k["incidents_opened"].value == 0


# ---------------------------------------------------------------- exports
@pytest.mark.parametrize("value", ["=1+1", "+cmd", "-2", "@SUM(A1)", "\t=x"])
def test_csv_formula_cells_are_neutralised(value: str) -> None:
    assert safe_cell(value) == "'" + value


def test_csv_plain_cells_are_unchanged() -> None:
    assert safe_cell("INC-000001") == "INC-000001" and safe_cell(None) == "" and safe_cell(3) == "3"


def test_pdf_is_well_formed_and_escapes_text() -> None:
    doc = Document("Report (test)", landscape=True)
    doc.text('A line with (parentheses) and a backslash \\ and ") Tj (injected')
    doc.table(["A", "B"], [["x" * 50, "y"]] * 120, [10, 5])
    pdf = doc.render()
    assert pdf.startswith(b"%PDF-1.4") and pdf.rstrip().endswith(b"%%EOF")
    assert b"\\(parentheses\\)" in pdf and b"\\) Tj \\(injected" in pdf
    assert pdf.count(b"/Type /Page ") >= 2, "long tables continue on further pages"
    assert b"/MediaBox [0 0 842 595]" in pdf
    xref = int(pdf.rsplit(b"startxref\n", 1)[1].split(b"\n")[0])
    assert pdf[xref:].startswith(b"xref")
