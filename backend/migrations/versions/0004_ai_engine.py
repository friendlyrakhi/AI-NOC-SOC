"""P4: AI runs, citations, feedback, per-tenant AI settings, knowledge base (pgvector).

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-16

- Every table is tenant-scoped with FORCE RLS; vector search runs inside the tenant transaction,
  so retrieval can never return another tenant's chunks (threat model T11, LLM08).
- ai_runs and ai_citations are append-only for the application (no UPDATE/DELETE grants).
- Embeddings are 256-dimensional (local hash embeddings, model "hash-256-v1"). A different
  embedding model needs its own column or table; vectors of different models are never compared.
"""

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

SCHEMA = r"""
CREATE TABLE ai_settings (
  tenant_id          uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  provider           text NOT NULL DEFAULT 'mock' CHECK (provider IN ('mock', 'ollama', 'anthropic')),
  allow_cloud        boolean NOT NULL DEFAULT false,
  redact_pii         boolean NOT NULL DEFAULT true,
  daily_token_budget integer NOT NULL DEFAULT 200000 CHECK (daily_token_budget BETWEEN 0 AND 100000000),
  auto_summarize     boolean NOT NULL DEFAULT false,
  updated_by         uuid,
  updated_at         timestamptz NOT NULL DEFAULT now(),
  -- Cloud use requires the explicit opt-in flag.
  CHECK (provider <> 'anthropic' OR allow_cloud)
);

CREATE TABLE ai_runs (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  task              text NOT NULL CHECK (task IN ('alert_summary', 'incident_summary', 'triage', 'rca', 'pir_draft',
                                                  'query_assist', 'chat')),
  subject_type      text NOT NULL CHECK (subject_type IN ('alert', 'incident', 'none')),
  subject_id        uuid,
  provider          text NOT NULL,
  model             text NOT NULL,
  template          text NOT NULL,
  question          text,
  evidence          jsonb NOT NULL DEFAULT '[]'::jsonb,
  output            jsonb NOT NULL,
  validation_status text NOT NULL CHECK (validation_status IN ('grounded', 'partially_grounded',
                                                                'insufficient_evidence', 'rejected')),
  validation_notes  jsonb NOT NULL DEFAULT '[]'::jsonb,
  confidence        numeric(4, 3) NOT NULL DEFAULT 0,
  suspicious_count  integer NOT NULL DEFAULT 0,
  tokens_in         integer NOT NULL DEFAULT 0,
  tokens_out        integer NOT NULL DEFAULT 0,
  latency_ms        integer NOT NULL DEFAULT 0,
  redactions        integer NOT NULL DEFAULT 0,
  requested_by      uuid,
  created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ai_runs_subject_idx ON ai_runs (tenant_id, subject_type, subject_id, created_at DESC);
CREATE INDEX ai_runs_usage_idx ON ai_runs (tenant_id, created_at);

CREATE TABLE ai_citations (
  tenant_id     uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  ai_run_id     uuid NOT NULL REFERENCES ai_runs(id) ON DELETE CASCADE,
  claim_index   integer NOT NULL,
  evidence_ref  text NOT NULL,
  evidence_type text NOT NULL,
  evidence_id   text NOT NULL,
  PRIMARY KEY (ai_run_id, claim_index, evidence_ref)
);

CREATE TABLE ai_feedback (
  tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  ai_run_id  uuid NOT NULL REFERENCES ai_runs(id) ON DELETE CASCADE,
  user_id    uuid NOT NULL,
  rating     smallint NOT NULL CHECK (rating IN (-1, 1)),
  comment    text NOT NULL DEFAULT '' CHECK (length(comment) <= 2000),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (ai_run_id, user_id)
);

CREATE TABLE knowledge_docs (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  kind         text NOT NULL CHECK (kind IN ('runbook', 'kb', 'postmortem')),
  title        text NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
  body         text NOT NULL CHECK (length(body) BETWEEN 1 AND 100000),
  source       text NOT NULL DEFAULT 'manual',
  version      integer NOT NULL DEFAULT 1,
  published_by uuid,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, title)
);

CREATE TABLE knowledge_chunks (
  id              bigserial PRIMARY KEY,
  tenant_id       uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  doc_id          uuid NOT NULL REFERENCES knowledge_docs(id) ON DELETE CASCADE,
  ordinal         integer NOT NULL,
  text            text NOT NULL,
  embedding       vector(256) NOT NULL,
  embedding_model text NOT NULL
);
CREATE INDEX knowledge_chunks_doc_idx ON knowledge_chunks (doc_id, ordinal);
CREATE INDEX knowledge_chunks_embedding_idx ON knowledge_chunks USING hnsw (embedding vector_cosine_ops);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['ai_settings', 'ai_runs', 'ai_citations', 'ai_feedback', 'knowledge_docs',
                           'knowledge_chunks'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_rw ON %I FOR ALL USING (tenant_id = app_tenant()) WITH CHECK (tenant_id = app_tenant())', t);
  END LOOP;
END $$;

GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO nocsoc_app;
GRANT SELECT, INSERT, UPDATE ON ai_settings TO nocsoc_app;
GRANT SELECT, INSERT ON ai_runs, ai_citations TO nocsoc_app;
GRANT SELECT, INSERT, UPDATE ON ai_feedback TO nocsoc_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON knowledge_docs TO nocsoc_app;
GRANT SELECT, INSERT, DELETE ON knowledge_chunks TO nocsoc_app;
"""


def upgrade() -> None:
    op.get_bind().connection.driver_connection.execute(SCHEMA)


def downgrade() -> None:
    raise NotImplementedError("use scripts/dev reset in development")
