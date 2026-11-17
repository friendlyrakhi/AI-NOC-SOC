"""OpenSearch store (P6): per-tenant indices and the query façade (threat model T8, SEC-ISO-03).

Isolation, in layers:
1. **Index names come only from the authenticated tenant.** ``t-{tenant hex}-events-YYYY.MM``
   for canonical events and ``t-{tenant hex}-entities`` for alerts, incidents and assets (global
   search). Clients never pass an index name, pattern or raw query DSL.
2. **Every query also filters on ``tenant_id``**, so a wrong index could still not return
   another tenant's documents.
3. **Constrained queries.** Clients send ``EventQuery``/text; the façade builds the DSL from fixed
   fields and ``simple_query_string`` (no scripts, regex or joins; syntax errors never raise).
4. **Store credentials.** The security plugin is on: the API reads as ``nocsoc_reader`` (read on
   ``t-*`` only), the ingest worker writes as ``nocsoc_indexer`` (write on ``t-*`` only). Only the
   one-shot setup job holds the admin password.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator

logger = logging.getLogger(__name__)

EventClass = Literal["alert", "detection", "authentication", "process", "network", "api_activity", "ticket"]
Severity = Literal["critical", "high", "medium", "low", "info"]
EntityKind = Literal["alert", "incident", "asset"]

MAX_WINDOW = timedelta(days=30)
EVENT_TEXT_FIELDS = ["title^3", "asset.text^2", "actor_user.text^2", "attributes_text", "connector"]
ENTITY_TEXT_FIELDS = ["title^3", "number^4", "subtitle", "text"]
# simple_query_string features allowed (no FUZZY/SLOP/NEAR/ESCAPE tricks needed here).
SQS_FLAGS = "AND|OR|NOT|PHRASE|PREFIX|PRECEDENCE|WHITESPACE"


# ---------------------------------------------------------------- index names (tenant only)
def tenant_key(tenant: uuid.UUID) -> str:
    return uuid.UUID(str(tenant)).hex


def events_index(tenant: uuid.UUID, at: datetime) -> str:
    return f"t-{tenant_key(tenant)}-events-{at.astimezone(UTC):%Y.%m}"


def events_pattern(tenant: uuid.UUID) -> str:
    return f"t-{tenant_key(tenant)}-events-*"


def entities_index(tenant: uuid.UUID) -> str:
    return f"t-{tenant_key(tenant)}-entities"


# ---------------------------------------------------------------- documents
def _ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value)) if value else None
    except ValueError:
        return None


def event_document(row: list[Any], columns: list[str]) -> tuple[str, str, dict[str, Any]]:
    """(index, id, doc) for one canonical ``events`` row (same columns as the ClickHouse insert)."""
    r = dict(zip(columns, row, strict=True))
    tenant = uuid.UUID(str(r["tenant_id"]))
    observed: datetime = r["observed_at"]
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=UTC)
    try:
        attributes = json.loads(r["attributes"] or "{}")
    except ValueError:
        attributes = {}
    doc: dict[str, Any] = {
        "tenant_id": str(tenant),
        "event_id": r["event_id"],
        "domain": r["domain"],
        "class": r["class"],
        "severity": r["severity"],
        "observed_at": observed.isoformat(),
        "connector": r["connector"],
        "instance_id": str(r["instance_id"]),
        "source_id": r["source_id"],
        "title": r["title"],
        "asset": r["asset"] or None,
        "actor_user": r["actor_user"] or None,
        "src_ip": _ip(r["src_ip"]),
        "dst_ip": _ip(r["dst_ip"]),
        "outcome": r["outcome"] or None,
        "mitre": list(r["mitre"] or []),
        "attributes": attributes,
        "attributes_text": " ".join(str(v) for v in attributes.values() if isinstance(v, str | int | float))[:2000],
    }
    return events_index(tenant, observed), r["event_id"], {k: v for k, v in doc.items() if v is not None}


def entity_document(
    tenant: uuid.UUID, kind: EntityKind, entity_id: Any, **fields: Any
) -> tuple[str, str, dict[str, Any]]:
    doc = {"tenant_id": str(tenant), "kind": kind, "id": str(entity_id), **fields}
    if isinstance(doc.get("at"), datetime):
        doc["at"] = doc["at"].isoformat()
    return entities_index(tenant), f"{kind}:{entity_id}", {k: v for k, v in doc.items() if v not in (None, "")}


# ---------------------------------------------------------------- constrained queries
class EventQuery(BaseModel):
    """What a client may ask of the event store. Anything else is rejected (422)."""

    model_config = ConfigDict(extra="forbid")

    text: str = Field(default="", max_length=300, description='Words, "phrases", -exclusions, prefix*.')
    domain: Literal["noc", "soc"] | None = None
    classes: list[EventClass] = Field(default_factory=list, max_length=7)
    severity: list[Severity] = Field(default_factory=list, max_length=5)
    connector: str | None = Field(default=None, max_length=64, pattern=r"^[a-z0-9_.-]+$")
    asset: str | None = Field(default=None, max_length=200)
    actor_user: str | None = Field(default=None, max_length=200)
    ip: str | None = Field(default=None, max_length=45, description="Matches source or destination IP.")
    mitre: list[str] = Field(default_factory=list, max_length=10)
    since: datetime | None = None
    until: datetime | None = None

    @field_validator("mitre")
    @classmethod
    def _techniques(cls, v: list[str]) -> list[str]:
        import re

        for t in v:
            if not re.fullmatch(r"T\d{4}(\.\d{3})?", t):
                raise ValueError(f"not an ATT&CK technique id: {t}")
        return v

    @field_validator("ip")
    @classmethod
    def _valid_ip(cls, v: str | None) -> str | None:
        if v and _ip(v) is None:
            raise ValueError("not an IP address")
        return v

    def window(self, now: datetime | None = None) -> tuple[datetime, datetime]:
        until = self.until or now or datetime.now(UTC)
        since = self.since or until - timedelta(hours=24)
        if since.tzinfo is None:
            since = since.replace(tzinfo=UTC)
        if until.tzinfo is None:
            until = until.replace(tzinfo=UTC)
        if since >= until or until - since > MAX_WINDOW:
            raise ValueError("use a window of up to 30 days")
        return since, until


def event_query_body(tenant: uuid.UUID, q: EventQuery, *, size: int, aggregations: bool = False) -> dict[str, Any]:
    since, until = q.window()
    filters: list[dict[str, Any]] = [
        {"term": {"tenant_id": str(tenant)}},
        {"range": {"observed_at": {"gte": since.isoformat(), "lt": until.isoformat()}}},
    ]
    if q.domain:
        filters.append({"term": {"domain": q.domain}})
    if q.classes:
        filters.append({"terms": {"class": list(q.classes)}})
    if q.severity:
        filters.append({"terms": {"severity": list(q.severity)}})
    if q.connector:
        filters.append({"term": {"connector": q.connector}})
    if q.asset:
        filters.append({"term": {"asset": q.asset}})
    if q.actor_user:
        filters.append({"term": {"actor_user": q.actor_user}})
    if q.ip:
        filters.append({"bool": {"should": [{"term": {"src_ip": q.ip}}, {"term": {"dst_ip": q.ip}}]}})
    if q.mitre:
        filters.append({"terms": {"mitre": list(q.mitre)}})
    must: list[dict[str, Any]] = []
    if q.text.strip():
        must.append(
            {
                "simple_query_string": {
                    "query": q.text,
                    "fields": EVENT_TEXT_FIELDS,
                    "default_operator": "and",
                    "flags": SQS_FLAGS,
                    "lenient": True,
                }
            }
        )
    body: dict[str, Any] = {
        "size": size,
        "timeout": "10s",
        "track_total_hits": 10000,
        "sort": [{"observed_at": "desc"}, {"event_id": "desc"}],
        "query": {"bool": {"filter": filters, "must": must}},
    }
    if aggregations:
        body["aggs"] = {
            "severity": {"terms": {"field": "severity", "size": 5}},
            "asset": {"terms": {"field": "asset", "size": 10}},
            "actor_user": {"terms": {"field": "actor_user", "size": 10}},
            "connector": {"terms": {"field": "connector", "size": 10}},
        }
    return body


def entity_query_body(tenant: uuid.UUID, text: str, kinds: list[str], size: int) -> dict[str, Any]:
    return {
        "size": size,
        "timeout": "5s",
        "query": {
            "bool": {
                "filter": [{"term": {"tenant_id": str(tenant)}}, {"terms": {"kind": kinds}}],
                "must": [
                    {
                        "simple_query_string": {
                            "query": text if text.rstrip().endswith("*") else text.rstrip() + "*",
                            "fields": ENTITY_TEXT_FIELDS,
                            "default_operator": "and",
                            "flags": SQS_FLAGS,
                            "lenient": True,
                        }
                    }
                ],
            }
        },
        "sort": ["_score", {"at": {"order": "desc", "missing": "_last"}}],
    }


# ---------------------------------------------------------------- client
class SearchUnavailableError(Exception):
    pass


class SearchStore:
    """Thin async REST client. One instance per role (reader or indexer)."""

    def __init__(self, url: str, user: str, password: str, *, transport: Any = None, timeout: float = 15) -> None:
        self.client = httpx.AsyncClient(
            base_url=url.rstrip("/"), auth=(user, password), timeout=timeout, transport=transport
        )

    async def close(self) -> None:
        await self.client.aclose()

    async def bulk(self, docs: list[tuple[str, str, dict[str, Any]]]) -> int:
        """Index (upsert by id) documents. Returns the number of failed items."""
        if not docs:
            return 0
        lines = []
        for index, doc_id, doc in docs:
            lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}))
            lines.append(json.dumps(doc, default=str))
        r = await self.client.post(
            "/_bulk", content="\n".join(lines) + "\n", headers={"content-type": "application/x-ndjson"}
        )
        r.raise_for_status()
        body = r.json()
        if not body.get("errors"):
            return 0
        failed = [i for i in body.get("items", []) if next(iter(i.values())).get("error")]
        for item in failed[:3]:
            err = next(iter(item.values()))["error"]
            logger.warning("search index error: %s", err.get("type"))
        return len(failed)

    async def search(self, index: str, body: dict[str, Any]) -> dict[str, Any]:
        try:
            r = await self.client.post(
                f"/{index}/_search",
                params={"ignore_unavailable": "true", "allow_no_indices": "true"},
                json=body,
            )
        except httpx.HTTPError as exc:
            raise SearchUnavailableError(type(exc).__name__) from exc
        if r.status_code >= 500 or r.status_code in (401, 403):
            raise SearchUnavailableError(f"status {r.status_code}")
        r.raise_for_status()
        return dict(r.json())


def hits(result: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    h = result.get("hits", {})
    total = h.get("total", {})
    count = int(total.get("value", 0)) if isinstance(total, dict) else int(total or 0)
    return [x["_source"] for x in h.get("hits", [])], count


def buckets(result: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    return {
        name: [{"value": b["key"], "count": b["doc_count"]} for b in agg.get("buckets", [])]
        for name, agg in result.get("aggregations", {}).items()
    }


# ---------------------------------------------------------------- setup (admin, one-shot)
_KEYWORD_TEXT = {"type": "keyword", "ignore_above": 512, "fields": {"text": {"type": "text"}}}

EVENTS_TEMPLATE = {
    "index_patterns": ["t-*-events-*"],
    "priority": 100,
    "template": {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0, "refresh_interval": "1s"},
        "mappings": {
            "dynamic": "strict",
            "properties": {
                "tenant_id": {"type": "keyword"},
                "event_id": {"type": "keyword"},
                "domain": {"type": "keyword"},
                "class": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "observed_at": {"type": "date"},
                "connector": {"type": "keyword"},
                "instance_id": {"type": "keyword"},
                "source_id": {"type": "keyword"},
                "title": {"type": "text", "fields": {"raw": {"type": "keyword", "ignore_above": 512}}},
                "asset": _KEYWORD_TEXT,
                "actor_user": _KEYWORD_TEXT,
                "src_ip": {"type": "ip"},
                "dst_ip": {"type": "ip"},
                "outcome": {"type": "keyword"},
                "mitre": {"type": "keyword"},
                "attributes": {"type": "object", "enabled": False},
                "attributes_text": {"type": "text"},
            },
        },
    },
}

ENTITIES_TEMPLATE = {
    "index_patterns": ["t-*-entities"],
    "priority": 100,
    "template": {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0, "refresh_interval": "1s"},
        "mappings": {
            "dynamic": "strict",
            "properties": {
                "tenant_id": {"type": "keyword"},
                "kind": {"type": "keyword"},
                "id": {"type": "keyword"},
                "number": {"type": "keyword"},
                "title": {"type": "text", "fields": {"raw": {"type": "keyword", "ignore_above": 512}}},
                "subtitle": {"type": "text"},
                "text": {"type": "text"},
                "severity": {"type": "keyword"},
                "status": {"type": "keyword"},
                "domain": {"type": "keyword"},
                "at": {"type": "date"},
            },
        },
    },
}

RETENTION_POLICY = {
    "policy": {
        "description": "NOC/SOC dev retention: events are deleted 30 days after index creation.",
        "default_state": "hot",
        "states": [
            {
                "name": "hot",
                "actions": [],
                "transitions": [{"state_name": "delete", "conditions": {"min_index_age": "30d"}}],
            },
            {"name": "delete", "actions": [{"delete": {}}], "transitions": []},
        ],
        "ism_template": [{"index_patterns": ["t-*-events-*"], "priority": 100}],
    }
}

ROLES = {
    "nocsoc_reader": {
        "cluster_permissions": ["cluster_composite_ops_ro"],
        "index_permissions": [{"index_patterns": ["t-*"], "allowed_actions": ["read"]}],
    },
    "nocsoc_indexer": {
        "cluster_permissions": ["indices:data/write/bulk"],
        "index_permissions": [
            {
                "index_patterns": ["t-*"],
                "allowed_actions": ["write", "create_index", "indices:admin/mapping/put"],
            }
        ],
    },
}


async def setup(url: str, admin_password: str, users: dict[str, str], *, transport: Any = None) -> None:
    """Idempotent: index templates, the retention policy, roles and the two service users."""
    async with httpx.AsyncClient(
        base_url=url.rstrip("/"), auth=("admin", admin_password), timeout=30, transport=transport
    ) as c:
        (await c.put("/_index_template/nocsoc-events", json=EVENTS_TEMPLATE)).raise_for_status()
        (await c.put("/_index_template/nocsoc-entities", json=ENTITIES_TEMPLATE)).raise_for_status()
        existing = await c.get("/_plugins/_ism/policies/nocsoc-retention")
        if existing.status_code == 404:
            (await c.put("/_plugins/_ism/policies/nocsoc-retention", json=RETENTION_POLICY)).raise_for_status()
        else:
            existing.raise_for_status()
            meta = existing.json()
            (
                await c.put(
                    "/_plugins/_ism/policies/nocsoc-retention",
                    params={"if_seq_no": meta["_seq_no"], "if_primary_term": meta["_primary_term"]},
                    json=RETENTION_POLICY,
                )
            ).raise_for_status()
        for role, spec in ROLES.items():
            (await c.put(f"/_plugins/_security/api/roles/{role}", json=spec)).raise_for_status()
            (
                await c.put(f"/_plugins/_security/api/internalusers/{role}", json={"password": users[role]})
            ).raise_for_status()
            (await c.put(f"/_plugins/_security/api/rolesmapping/{role}", json={"users": [role]})).raise_for_status()
