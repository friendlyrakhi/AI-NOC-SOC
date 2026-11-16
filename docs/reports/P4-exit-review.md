# P4 Exit Review: AI intelligence engine

Date: 2026-11-16 · Status: **ready for your review**

The AI engine runs on the deterministic **mock** provider by default. No cloud model is enabled, and evidence cannot leave the PC unless you deliberately turn on three separate switches (below). The AI can only describe and suggest. It cannot change an alert, incident or anything else, and it has no tools.

## Exit criteria (docs/08-implementation-plan.md §P4)

| Criterion | Result | Evidence |
|-----------|--------|----------|
| With `mock`, every AI response passes the validator or degrades to "insufficient evidence" | **Pass** | Eval harness: 7 golden cases pass at 1.0, and 4 unanswerable cases degrade correctly at 1.0. Integration tests run every task on real pipeline incidents; each result is `grounded` or `insufficient_evidence`, and every claim cites supplied evidence. |
| Egress test: no outbound connections when cloud egress is off | **Pass** | `test_gateway.py`: a socket guard fails the test on any non-loopback connection or DNS lookup, for all 7 tasks. A cloud request with a key present but egress off returns `403 ai.egress_denied`, and the cloud client object is never constructed. Through the API, a tenant set to Anthropic gets `409 ai.egress_denied`. In compose, the gateway's only network is `internal: true`, which the policy check enforces. |
| Injection corpus: 0 policy bypasses or tool misuse; suspicious-evidence flag raised | **Pass** | 18 injection strings, including scenario 7, each tested in evidence and as the analyst's question (36 cases). Detection 1.0, bypasses 0, with the mock provider **and** with a simulated compromised model. Real pipeline: scenario 7 alerts are flagged, never echoed, and produce no suggested actions. E2E: an injected comment shows the warning banner and is not repeated back. |
| Architecture test: `ai` / `ai-gateway` cannot import or reach executors | **Pass** | import-linter: `ai_gateway` may not import `app`, the connectors, the runner or the workflow worker. `app.ai` may not import the integrations module, the connector catalog, the ingestion or worker code, the runner or the gateway. Compose policy: the gateway joins only the internal `ai` network, shared with the API alone, and holds only its own token. Six policy tests reject unsafe variants. |
| (If you enable a real provider) baseline recorded; thresholds set | **Thresholds set; no real baseline** | `ai-engine/evals/thresholds.json` defines the bar a real provider must meet. The mock baseline is in `ai-engine/evals/reports/mock-baseline.json`. No real provider is enabled, so no real baseline exists yet; see "Enabling a real model". |

## How it works

```
analyst → API (ai module) ──evidence (RLS, tenant-scoped)──► validator ◄── structured output
              │  assemble evidence: subject, alerts, timeline,        ▲
              │  services, runbooks (pgvector); flag injections       │
              └──── HTTP, token ────► ai-gateway: redact → template → provider (mock | ollama | anthropic)
```

- **Evidence.** The API assembles evidence inside the caller's tenant transaction, so RLS applies and no cross-tenant evidence is possible. Each item gets a ref (E1, E2, ...), its text is clipped, and items with instruction-like content are flagged `suspicious`.
- **Gateway.** The gateway is a separate service and the only holder of model keys. It always redacts secrets, and redacts personal data for every non-mock model. It wraps evidence as JSON between explicit "untrusted data" markers, applies a versioned template (`ai-engine/prompts/*.yaml`), and requests structured output. No provider is given tools.
- **Validator.** Nothing the model says is trusted. The API's validator:
  - drops claims with no citations or with refs that were not supplied;
  - drops claims with instruction-like text, links, HTML or markdown;
  - accepts suggested actions only from the task's allow-list, cited, and at most three;
  - sanitises suggested queries against allow-lists.

  Statuses are `grounded`, `partially_grounded` (confidence capped at 0.5), `insufficient_evidence` (confidence 0) or `rejected`.
- **Records.** Every run is stored with its evidence index, validated output, notes, token usage and citations, and is audited (`ai.run`). Runs are append-only. The raw prompt is not stored.
- **Budgets.** Each tenant has a daily token budget (`429 ai.budget_exhausted`). Per-task output caps, evidence limits (50 items, 1,500 characters each) and request timeouts also apply.
- **Knowledge base.** Runbooks are chunked and embedded through the gateway with deterministic local hash embeddings (`hash-256-v1`, 256 dimensions) and retrieved with pgvector inside the tenant transaction. Publishing needs `knowledge:publish` plus a step-up, and content that looks like instructions to a model is refused (LLM04).
- **UI.** The Copilot panel on real incidents offers Summarise, Suggest triage, Root-cause hypotheses, Draft PIR and Ask.
  - Each answer is labelled **AI-generated**, with its provider, model, template, validation status and confidence.
  - Every statement has citation chips linking to the evidence list. Answers render as plain text only.
  - Suspicious evidence produces a warning banner, and suggested actions are marked "not performed; each would need approval".
  - Also new: AI settings (admin), a knowledge base page, and an AI-suggested search on the search page that never runs on its own.

## Features delivered (docs/08 §P4)

| Feature | Endpoint / place |
|---------|------------------|
| Alert summary | `POST /ai/alerts/{id}/summary` |
| Incident summary, SOC triage suggestion, RCA hypotheses, PIR draft | `POST /ai/incidents/{id}/{summary\|triage\|rca\|pir-draft}` |
| Query assist (suggestion only) | `POST /ai/query-assist`; Search page |
| Scoped chat | `POST /ai/chat` (subject-scoped; JSON, not streamed) |
| Runs, feedback | `GET /ai/runs`, `GET /ai/runs/{id}`, `POST /ai/runs/{id}/feedback` |
| Settings, usage | `GET/PUT /ai/settings` (step-up), `GET /ai/usage`; Admin → AI settings |
| Knowledge base | `/knowledge/*`; Knowledge base page; 8 DEMO runbooks seeded per demo tenant |
| Eval harness | `ai-engine/evals/harness.py` (golden sets, unanswerable, injection corpus, compromised-model profile) |

## Test results (all green)

| Suite | Count | Notes |
|-------|-------|-------|
| AI gateway | 15 | auth, egress guard, redaction, templates, strict schema, embeddings, all tasks |
| AI evals (CI gate) | 2 | mock meets thresholds; compromised model contained |
| Backend unit | 58 | adds the validator, injection heuristics (including benign-text false-positive checks), the action allow-list compared with the manifests, and chunking |
| Backend integration | 153 | adds 10 AI tests on real pipeline data. The isolation suite now covers AI runs and knowledge docs, and the 6 new tables are classified FORCE RLS |
| Connectors, runner, compose policy | 35 + 71 + 16 + 18 | |
| Frontend unit | 50 | |
| Browser journeys | 30 | 4 new P4 journeys, with axe checks on the copilot, knowledge and AI settings pages |
| CI gates | 14/14 | includes import-linter (6 contracts), bandit, gitleaks and OpenAPI drift |

## Enabling a real model (not done; your decision, D8)

1. Put a key in `infrastructure/secrets/anthropic_api_key`. The file is git-ignored and never generated.
2. Start the stack with `infrastructure/compose/ai-egress.override.yml`. This gives the gateway egress and sets `NOCSOC_AI_CLOUD_EGRESS_ENABLED=true`.
3. Run `uv run python ai-engine/evals/harness.py --provider anthropic --write` and check the scores against `real_provider_minimum`.
4. As an AI admin, choose Anthropic and tick "Allow sending redacted evidence" (step-up required).

The adapter uses `claude-opus-5-5` by default, with server-side refusal fallback enabled. Ollama works the same way with `NOCSOC_AI_OLLAMA_URL`, using a local model and no internet.

## Residual risks and follow-ups

1. **Heuristic injection detection.** Detection is pattern-based. Novel phrasings can slip past the *flag*, but not past the structural defences: evidence is treated as data, the model has no tools, every claim must cite evidence, and actions are allow-listed suggestions that still need approval in P5.
2. **Lexical embeddings.** Hash embeddings rank by shared vocabulary, not meaning. A neural embedding model (for example via Ollama) needs its own vector column per model.
3. **No streaming.** Chat returns JSON. SSE streaming is deferred because it adds UI complexity without changing the safety properties.
4. **Abuse of non-mock models.** Budgets are per tenant per day, with no per-user rate limit yet.
5. **Not grounded in telemetry.** The mock is deterministic and grounded but simple. RCA quality on real data depends on the provider and on more evidence types (metrics windows, change records), which are planned with P6 analytics.

## Next: P5 (needs your go-ahead)

P5 covers workflow automation and human approval: Temporal, the policy engine, approval inbox, action requests (AI-originated requests always need a human), the kill switch, and simulated execution through the connector runner.
