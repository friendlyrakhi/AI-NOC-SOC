import "server-only";

import { apiFetch, apiGetOptional, type Schemas } from "@/lib/server/api";

/**
 * Data that came through the real ingestion pipeline (sandbox connectors -> event bus ->
 * ingest worker). Every function returns null when the data is not available to this caller:
 * no permission, the read-only "All customers" view, or the stream profile not running (503).
 * Pages then fall back to their DEMO content and say why. Nothing here is invented.
 */
export type PipelineAlert = Schemas["AlertOut"];
export type AlertPage = Schemas["AlertPage"];
export type AlertSummary = Schemas["SummaryOut"];
export type VulnPage = Schemas["VulnPage"];
export type Definition = Schemas["DefinitionOut"];
export type Instance = Schemas["InstanceOut"];
export type Scenario = Schemas["ScenarioOut"];
export type Run = Schemas["RunOut"];
export type DeadLetter = Schemas["DeadLetterOut"];

async function optional<T>(path: string): Promise<T | null> {
  const r = await apiFetch<T>(path);
  if (r.ok) return r.data;
  if (r.status === 401) return apiGetOptional<T>(path); // reuses the sign-in redirect
  return null; // 403, 404, 409 (aggregate view), 503 (stream/analytics not running)
}

export function getAlerts(domain: "noc" | "soc", limit = 200): Promise<AlertPage | null> {
  return optional<AlertPage>(`/alerts?domain=${domain}&sort=severity&limit=${limit}`);
}

export function getAlertSummary(domain?: "noc" | "soc"): Promise<AlertSummary | null> {
  return optional<AlertSummary>(`/alerts/summary${domain ? `?domain=${domain}` : ""}`);
}

export function getVulns(limit = 200): Promise<VulnPage | null> {
  return optional<VulnPage>(`/vulnerabilities?status=open&limit=${limit}`);
}

export async function getConnectorState(): Promise<{
  definitions: Definition[];
  instances: Instance[];
  scenarios: Scenario[];
} | null> {
  const [definitions, instances, scenarios] = await Promise.all([
    optional<Definition[]>("/connectors/definitions"),
    optional<Instance[]>("/connectors/instances"),
    optional<Scenario[]>("/connectors/scenarios"),
  ]);
  if (!definitions || !instances || !scenarios) return null;
  return { definitions, instances, scenarios };
}

export async function getInstanceDetail(id: string): Promise<{
  instance: Instance;
  definition: Definition | undefined;
  runs: Run[];
  deadLetters: DeadLetter[];
} | null> {
  const instance = await optional<Instance>(`/connectors/instances/${encodeURIComponent(id)}`);
  if (!instance) return null;
  const [definitions, runs, deadLetters] = await Promise.all([
    optional<Definition[]>("/connectors/definitions"),
    optional<Run[]>(`/connectors/instances/${encodeURIComponent(id)}/runs?limit=50`),
    optional<DeadLetter[]>(`/connectors/dead-letters?instance_id=${encodeURIComponent(id)}&limit=50`),
  ]);
  return {
    instance,
    definition: definitions?.find((d) => d.id === instance.definition_id),
    runs: runs ?? [],
    deadLetters: deadLetters ?? [],
  };
}
