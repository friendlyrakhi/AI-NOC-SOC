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

// ---------------------------------------------------------------- P3: incidents and topology
export type IncidentOut = Schemas["IncidentOut"];
export type IncidentPage = Schemas["IncidentPage"];
export type IncidentMetrics = Schemas["MetricsOut"];
export type TimelineEntry = Schemas["TimelineOut"];
export type IncidentTask = Schemas["TaskOut"];
export type LinkedAlert = Schemas["LinkedAlert"];
export type ServiceOut = Schemas["ServiceOut"];
export type ServiceDetail = Schemas["ServiceDetail"];
export type MaintenanceWindow = Schemas["MaintenanceOut"];
export type SuppressionRule = Schemas["SuppressionOut"];
export type CorrelationRule = Schemas["RuleOut"];
export type SearchOut = Schemas["SearchOut"];

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isUuid(id: string): boolean {
  return UUID.test(id);
}

export function getIncidents(portal?: "noc" | "soc", limit = 200): Promise<IncidentPage | null> {
  return optional<IncidentPage>(`/incidents?limit=${limit}&sort=priority${portal ? `&portal=${portal}` : ""}`);
}

export function getIncidentMetrics(portal?: "noc" | "soc", days = 30): Promise<IncidentMetrics | null> {
  return optional<IncidentMetrics>(`/incidents/metrics?days=${days}${portal ? `&portal=${portal}` : ""}`);
}

export async function getIncidentDetail(id: string): Promise<{
  incident: IncidentOut;
  alerts: LinkedAlert[];
  timeline: TimelineEntry[];
  tasks: IncidentTask[];
} | null> {
  if (!isUuid(id)) return null;
  const incident = await optional<IncidentOut>(`/incidents/${id}`);
  if (!incident) return null;
  const [alerts, timeline, tasks] = await Promise.all([
    optional<LinkedAlert[]>(`/incidents/${id}/alerts`),
    optional<TimelineEntry[]>(`/incidents/${id}/timeline?limit=500`),
    optional<IncidentTask[]>(`/incidents/${id}/tasks`),
  ]);
  return { incident, alerts: alerts ?? [], timeline: timeline ?? [], tasks: tasks ?? [] };
}

export function getServices(): Promise<ServiceOut[] | null> {
  return optional<ServiceOut[]>("/services");
}

export function getService(id: string): Promise<ServiceDetail | null> {
  return isUuid(id) ? optional<ServiceDetail>(`/services/${id}`) : Promise.resolve(null);
}

export async function getOperationsControls(): Promise<{
  windows: MaintenanceWindow[] | null;
  rules: SuppressionRule[] | null;
  correlation: CorrelationRule[] | null;
}> {
  const [windows, rules, correlation] = await Promise.all([
    optional<MaintenanceWindow[]>("/maintenance-windows?include_past=true"),
    optional<SuppressionRule[]>("/suppression-rules"),
    optional<CorrelationRule[]>("/correlation-rules"),
  ]);
  return { windows, rules, correlation };
}

export function searchPipeline(q: string): Promise<SearchOut | null> {
  return q.trim().length >= 2 ? optional<SearchOut>(`/search?q=${encodeURIComponent(q.trim())}&limit=30`) : Promise.resolve(null);
}
