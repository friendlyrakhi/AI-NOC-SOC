"""Knowledge base: runbooks and KB articles used as AI evidence (pgvector retrieval).

Documents are tenant-scoped (RLS). Publishing needs ``knowledge:publish`` and a step-up, because
anything published becomes model context (threat model LLM04, poisoning). Chunks are embedded by
the AI gateway; documents without chunks (e.g. seeded ones) are indexed lazily on first use.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from app.ai import client
from app.ai.injection import is_suspicious
from app.core.authz.deps import get_principal, requires
from app.core.authz.principal import Principal
from app.core.tenancy.common import record, tenant_tx
from app.errors import ProblemError, not_found
from app.services import Services, get_services

router = APIRouter(prefix="/knowledge", tags=["knowledge"])
Svc = Annotated[Services, Depends(get_services)]
P = Annotated[Principal, Depends(get_principal)]

CHUNK_CHARS = 900
MAX_CHUNKS_PER_DOC = 60


def chunk(body: str) -> list[str]:
    """Paragraph-aware chunks of at most ~CHUNK_CHARS characters."""
    parts = [p.strip() for p in re.split(r"\n\s*\n", body) if p.strip()]
    chunks: list[str] = []
    current = ""
    for p in parts:
        while len(p) > CHUNK_CHARS:
            chunks.append(p[:CHUNK_CHARS])
            p = p[CHUNK_CHARS:]
        if len(current) + len(p) + 2 > CHUNK_CHARS and current:
            chunks.append(current)
            current = p
        else:
            current = f"{current}\n\n{p}" if current else p
    if current:
        chunks.append(current)
    return chunks[:MAX_CHUNKS_PER_DOC]


def _vector(v: list[float]) -> str:
    return "[" + ",".join(f"{x:.6f}" for x in v) + "]"


async def index_doc(services: Services, conn: AsyncConnection, doc_id: UUID, title: str, body: str) -> int:
    pieces = chunk(body)
    model, vectors = await client.embed(services, [f"{title}\n{p}" for p in pieces])
    await conn.execute(text("DELETE FROM knowledge_chunks WHERE doc_id = :d"), {"d": doc_id})
    for i, (piece, vec) in enumerate(zip(pieces, vectors, strict=True)):
        await conn.execute(
            text(
                "INSERT INTO knowledge_chunks (tenant_id, doc_id, ordinal, text, embedding, embedding_model) "
                "VALUES (app_tenant(), :d, :o, :t, CAST(:e AS vector), :m)"
            ),
            {"d": doc_id, "o": i, "t": piece, "e": _vector(vec), "m": model},
        )
    return len(pieces)


async def ensure_indexed(services: Services, conn: AsyncConnection) -> None:
    rows = await conn.execute(
        text(
            "SELECT d.id, d.title, d.body FROM knowledge_docs d "
            "WHERE NOT EXISTS (SELECT 1 FROM knowledge_chunks c WHERE c.doc_id = d.id) LIMIT 50"
        )
    )
    for r in rows.all():
        await index_doc(services, conn, r.id, r.title, r.body)


async def retrieve(services: Services, conn: AsyncConnection, query: str, k: int = 3) -> list[dict[str, Any]]:
    """Top-k chunks for ``query`` within the caller's tenant (RLS), one per document."""
    if not query.strip():
        return []
    await ensure_indexed(services, conn)
    _, (vec,) = await client.embed(services, [query[:4000]])
    rows = await conn.execute(
        text(
            "SELECT DISTINCT ON (d.id) d.id, d.title, d.kind, c.text, c.embedding <=> CAST(:q AS vector) AS distance "
            "FROM knowledge_chunks c JOIN knowledge_docs d ON d.id = c.doc_id "
            "ORDER BY d.id, distance"
        ),
        {"q": _vector(vec)},
    )
    hits = sorted((dict(r._mapping) for r in rows), key=lambda h: h["distance"])
    return [h for h in hits if h["distance"] < 0.95][:k]


# ============================================================ API
class KnowledgeDocOut(BaseModel):
    id: UUID
    kind: Literal["runbook", "kb", "postmortem"]
    title: str
    source: str
    version: int
    chunks: int
    updated_at: datetime


class KnowledgeDocDetail(KnowledgeDocOut):
    body: str


class KnowledgeDocIn(BaseModel):
    kind: Literal["runbook", "kb", "postmortem"] = "runbook"
    title: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=100_000)


class KnowledgeHit(BaseModel):
    doc_id: UUID
    title: str
    kind: str
    excerpt: str
    score: float


_DOC_COLS = (
    "d.id, d.kind, d.title, d.source, d.version, d.updated_at, "
    "(SELECT count(*) FROM knowledge_chunks c WHERE c.doc_id = d.id) AS chunks"
)


@router.get("/docs", response_model=list[KnowledgeDocOut], **requires("knowledge:read"))
async def list_docs(services: Svc, p: P) -> list[KnowledgeDocOut]:
    async with tenant_tx(services, p) as conn:
        rows = await conn.execute(text(f"SELECT {_DOC_COLS} FROM knowledge_docs d ORDER BY d.kind, d.title"))  # nosec B608
        return [KnowledgeDocOut(**r._mapping) for r in rows]


@router.get("/docs/{doc_id}", response_model=KnowledgeDocDetail, **requires("knowledge:read"))
async def get_doc(doc_id: UUID, services: Svc, p: P) -> KnowledgeDocDetail:
    async with tenant_tx(services, p) as conn:
        row = (
            await conn.execute(text(f"SELECT {_DOC_COLS}, d.body FROM knowledge_docs d WHERE d.id = :i"), {"i": doc_id})  # nosec B608
        ).one_or_none()
    if row is None:
        raise not_found("Document")
    return KnowledgeDocDetail(**row._mapping)


@router.post(
    "/docs",
    response_model=KnowledgeDocOut,
    status_code=status.HTTP_201_CREATED,
    **requires("knowledge:publish", step_up=True),
)
async def publish_doc(body: KnowledgeDocIn, services: Svc, p: P) -> KnowledgeDocOut:
    if is_suspicious(body.body) or is_suspicious(body.title):
        raise ProblemError(
            422,
            "knowledge.suspicious",
            "Instruction-like content",
            "The document contains text that looks like instructions to an AI model. Remove it before publishing.",
        )
    async with tenant_tx(services, p) as conn:
        row = (
            await conn.execute(
                text(
                    "INSERT INTO knowledge_docs (tenant_id, kind, title, body, published_by) "
                    "VALUES (app_tenant(), :k, :t, :b, :u) ON CONFLICT (tenant_id, title) DO UPDATE SET "
                    "body = EXCLUDED.body, kind = EXCLUDED.kind, version = knowledge_docs.version + 1, "
                    "published_by = EXCLUDED.published_by, updated_at = now() RETURNING id"
                ),
                {"k": body.kind, "t": body.title, "b": body.body, "u": p.user_id},
            )
        ).one()
        await index_doc(services, conn, row.id, body.title, body.body)
        await record(
            conn, p, "knowledge.publish", target_type="knowledge_doc", target_id=row.id, details={"title": body.title}
        )
        out = (
            await conn.execute(text(f"SELECT {_DOC_COLS} FROM knowledge_docs d WHERE d.id = :i"), {"i": row.id})  # nosec B608
        ).one()
    return KnowledgeDocOut(**out._mapping)


@router.delete("/docs/{doc_id}", status_code=status.HTTP_204_NO_CONTENT, **requires("knowledge:publish", step_up=True))
async def delete_doc(doc_id: UUID, services: Svc, p: P) -> Response:
    async with tenant_tx(services, p) as conn:
        row = (
            await conn.execute(text("DELETE FROM knowledge_docs WHERE id = :i RETURNING title"), {"i": doc_id})
        ).one_or_none()
        if row is None:
            raise not_found("Document")
        await record(
            conn, p, "knowledge.delete", target_type="knowledge_doc", target_id=doc_id, details={"title": row.title}
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/search", response_model=list[KnowledgeHit], **requires("knowledge:read"))
async def search(services: Svc, p: P, q: Annotated[str, Query(min_length=2, max_length=500)]) -> list[KnowledgeHit]:
    async with tenant_tx(services, p) as conn:
        hits = await retrieve(services, conn, q, k=5)
    return [
        KnowledgeHit(
            doc_id=h["id"],
            title=h["title"],
            kind=h["kind"],
            excerpt=h["text"][:300],
            score=round(1 - float(h["distance"]), 3),
        )
        for h in hits
    ]
