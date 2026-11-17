"""Generates dashboards/platform-slos.json (run after editing; the JSON is committed).

python infrastructure/observability/make_dashboard.py
"""

import json
from pathlib import Path

PROM = {"type": "prometheus", "uid": "prometheus"}
API = 'service_name="nocsoc-api"'


def stat(title, expr, unit, x, y, thresholds, decimals=2, w=4, description=""):
    return {
        "type": "stat",
        "title": title,
        "description": description,
        "datasource": PROM,
        "gridPos": {"h": 4, "w": w, "x": x, "y": y},
        "targets": [{"refId": "A", "expr": expr, "datasource": PROM}],
        "options": {"reduceOptions": {"calcs": ["lastNotNull"]}, "colorMode": "background", "textMode": "value"},
        "fieldConfig": {
            "defaults": {
                "unit": unit,
                "decimals": decimals,
                "noValue": "no data",
                "thresholds": {"mode": "absolute", "steps": thresholds},
            },
            "overrides": [],
        },
    }


def series(title, targets, unit, x, y, w=12, h=8, description=""):
    return {
        "type": "timeseries",
        "title": title,
        "description": description,
        "datasource": PROM,
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "targets": [
            {"refId": chr(65 + i), "expr": e, "legendFormat": legend, "datasource": PROM}
            for i, (e, legend) in enumerate(targets)
        ],
        "fieldConfig": {"defaults": {"unit": unit, "custom": {"lineWidth": 2, "fillOpacity": 0}}, "overrides": []},
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}, "tooltip": {"mode": "multi"}},
    }


def green_above(limit):
    return [{"color": "red", "value": None}, {"color": "green", "value": limit}]


def green_below(limit):
    return [{"color": "green", "value": None}, {"color": "red", "value": limit}]


panels = [
    stat(
        "API availability (1 h)",
        "1 - nocsoc:api_error_ratio:rate1h",
        "percentunit",
        0,
        0,
        green_above(0.995),
        3,
        description="Share of API requests that were not server errors. SLO: 99.5 % over 30 days.",
    ),
    stat(
        "API GET p95 (5 m)",
        "nocsoc:api_read_latency_seconds:p95_5m",
        "s",
        4,
        0,
        green_below(0.3),
        description="NFR-1: p95 of list/get requests below 300 ms.",
    ),
    stat(
        "Ingest latency p95 (5 m)",
        "nocsoc:ingest_latency_seconds:p95_5m",
        "s",
        8,
        0,
        green_below(5),
        description="Connector emitted -> stored. NFR-1: below 5 s.",
    ),
    stat(
        "Ingest rate",
        "sum(nocsoc:ingest_messages:rate1m)",
        "reqps",
        12,
        0,
        [{"color": "blue", "value": None}],
        1,
        description="Raw messages handled per second. NFR-2 target: 1,000 events/s sustained (synthetic).",
    ),
    stat(
        "Telemetry outbox pending",
        "max(nocsoc_outbox_pending)",
        "none",
        16,
        0,
        green_below(1),
        0,
        description="Rows waiting for ClickHouse/OpenSearch after the last relay pass. Should be 0.",
    ),
    stat(
        "Audit anchor problems (24 h)",
        "sum(increase(nocsoc_audit_anchor_problems_total[24h])) or vector(0)",
        "none",
        20,
        0,
        green_below(1),
        0,
        description="Mismatches between the audit log and its external anchors. Must stay 0.",
    ),
    series(
        "API requests by status class",
        [
            (
                f"sum by (http_response_status_code) (rate(http_server_request_duration_seconds_count{{{API}}}[5m]))",
                "{{http_response_status_code}}",
            )
        ],
        "reqps",
        0,
        4,
    ),
    series(
        "API GET p95 by route",
        [("topk(10, nocsoc:api_read_latency_seconds:p95_by_route_5m)", "{{http_route}}")],
        "s",
        12,
        4,
    ),
    series(
        "Ingest throughput by result",
        [("nocsoc:ingest_messages:rate1m", "{{result}}")],
        "reqps",
        0,
        12,
    ),
    series(
        "Ingest latency (connector -> stored)",
        [
            ("histogram_quantile(0.5, sum by (le) (rate(nocsoc_ingest_latency_seconds_bucket[5m])))", "p50"),
            ("nocsoc:ingest_latency_seconds:p95_5m", "p95"),
        ],
        "s",
        12,
        12,
    ),
    series(
        "Projection (Postgres -> ClickHouse facts / OpenSearch)",
        [
            ("sum by (sink) (rate(nocsoc_projector_rows_total[5m]))", "rows/s {{sink}}"),
            ("sum by (sink) (increase(nocsoc_projector_failures_total[5m]))", "failures {{sink}}"),
        ],
        "short",
        0,
        20,
    ),
    series(
        "API error budget remaining (30 days, 99.5 % objective)",
        [
            (
                f"1 - ((sum(increase(http_server_request_duration_seconds_count{{{API},"
                f'http_response_status_code=~"5.."}}[30d])) or vector(0)) / '
                f"clamp_min(sum(increase(http_server_request_duration_seconds_count{{{API}}}[30d])), 1)) / 0.005",
                "budget remaining",
            )
        ],
        "percentunit",
        12,
        20,
    ),
]

dashboard = {
    "uid": "nocsoc-platform-slos",
    "title": "NOC/SOC platform: service health and SLOs",
    "description": "P7 platform dashboard. SLO definitions: docs/operations/slos.md.",
    "tags": ["nocsoc", "slo"],
    "timezone": "browser",
    "schemaVersion": 39,
    "version": 1,
    "editable": False,
    "refresh": "30s",
    "time": {"from": "now-6h", "to": "now"},
    "panels": [{**p, "id": i + 1} for i, p in enumerate(panels)],
}

out = Path(__file__).parent / "dashboards" / "platform-slos.json"
out.write_text(json.dumps(dashboard, indent=2) + "\n", encoding="utf-8")
print(f"wrote {out}")
