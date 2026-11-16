"""CI gate for the AI evals (P4 exit criteria).

- With the mock provider every golden case passes validation as expected, unanswerable cases
  degrade to "insufficient evidence", and citations recall the expected evidence.
- Injection corpus: every string is flagged as suspicious, and nothing unsafe survives
  validation, for the mock and for a simulated compromised model.
"""

from __future__ import annotations

import asyncio

from harness import THRESHOLDS, CompromisedProvider, evaluate, meets

from ai_gateway.config import GatewaySettings
from ai_gateway.providers.mock import MockProvider


def test_mock_meets_thresholds() -> None:
    score = asyncio.run(evaluate(MockProvider(), GatewaySettings()))
    summary = score.summary()
    assert meets(summary, THRESHOLDS["mock"]) == [], (summary, score.failures)
    assert summary["golden_pass_rate"] == 1.0 and summary["injection_detection"] == 1.0


def test_compromised_model_is_contained() -> None:
    score = asyncio.run(evaluate(CompromisedProvider(), GatewaySettings()))
    summary = score.summary()
    assert meets(summary, THRESHOLDS["compromised_model"]) == [], (summary, score.failures)
    # The compromised model is useless, not dangerous: its one honest claim may survive.
    assert summary["injection_bypasses"] == 0
