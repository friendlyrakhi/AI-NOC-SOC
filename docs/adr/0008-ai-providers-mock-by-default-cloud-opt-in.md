# ADR-0008: AI providers: mock by default, cloud opt-in

- Status: accepted
- Date: 2026-11-16
- Decision ID: D8 (docs/10-decisions-for-approval.md)

## Context
Telemetry is sensitive (threat model LLM02). Model choice should not be locked in.

## Decision
The ai-gateway has provider adapters. `mock` is the default, Ollama is optional, and cloud providers (e.g. Anthropic, OpenAI or Azure OpenAI) require per-tenant opt-in plus redaction.

## Alternatives considered
Cloud-first.

## Consequences
Which cloud adapter to build first is still open (asked in docs/10).

## Implementation (P4, 2026-11-16)
- Adapters built: `mock` (default, deterministic, citation-aware), `ollama` (local, optional) and `anthropic` (cloud; official SDK, structured outputs, server-side refusal fallback). All non-mock providers are off unless configured.
- Cloud use needs three independent switches:
  1. The compose override `ai-egress.override.yml` gives the gateway network egress; the base `ai` network is internal-only.
  2. `NOCSOC_AI_CLOUD_EGRESS_ENABLED=true` plus an API key secret on the gateway.
  3. A tenant opt-in: provider `anthropic` with `allow_cloud`, set by an AI admin with step-up.
- Redaction: secrets always, for every provider. Personal data for every non-mock provider unless the tenant disables it.
- The open question in docs/10 (which cloud adapter first) defaulted to Anthropic. An OpenAI-compatible or Azure adapter fits the same `Provider` interface.
