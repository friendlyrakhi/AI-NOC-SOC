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
