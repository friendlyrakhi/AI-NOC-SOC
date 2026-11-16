"""Deterministic local embeddings (feature hashing) for the knowledge base in dev.

Not semantic like a neural model, but stable, tenant-agnostic and offline: good enough to rank
runbooks by shared vocabulary. A neural embedding model (e.g. via Ollama) can replace it; the
dimension is part of the stored model name, so mixed vectors are never compared.
"""

from __future__ import annotations

import hashlib
import itertools
import math
import re

DIMENSIONS = 256
MODEL = "hash-256-v1"
_TOKEN = re.compile(r"[a-z0-9]+")
_STOP = frozenset(
    [
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "by",
        "for",
        "from",
        "has",
        "in",
        "is",
        "it",
        "of",
        "on",
        "or",
        "that",
        "the",
        "to",
        "was",
        "were",
        "with",
    ]
)


def _features(text: str) -> list[str]:
    words = [w for w in _TOKEN.findall(text.lower()) if w not in _STOP and len(w) > 1]
    return words + [f"{a}_{b}" for a, b in itertools.pairwise(words)]


def embed(text: str) -> list[float]:
    vec = [0.0] * DIMENSIONS
    for feature in _features(text):
        digest = hashlib.sha256(feature.encode()).digest()
        index = int.from_bytes(digest[:4], "big") % DIMENSIONS
        vec[index] += 1.0 if digest[4] & 1 else -1.0
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [round(v / norm, 6) for v in vec]
