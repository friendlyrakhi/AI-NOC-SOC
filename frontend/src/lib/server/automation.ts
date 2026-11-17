import "server-only";

import { apiFetch, apiGetOptional, type Me, type Schemas } from "@/lib/server/api";

/**
 * Automation data from the API (P5). Each loader returns null when the caller cannot see it:
 * no permission, the read-only "All customers" view (409), or the workflow profile not
 * running (503). Pages then say so instead of inventing state.
 */
export type ActionRequest = Schemas["RequestOut"];
export type CatalogEntry = Schemas["CatalogEntry"];
export type Playbook = Schemas["PlaybookOut"];
export type PlaybookVersion = Schemas["VersionOut"];
export type WorkflowRun = Schemas["WorkflowRunOut"];
export type KillSwitch = Schemas["KillSwitchOut"];
export type StepState = { status: string; request_id: string | null; detail: string };

export interface StepDef {
  id: string;
  action: string;
  target: string;
  justification?: string;
  requires?: string[];
  on_failure?: "stop" | "continue";
  params?: Record<string, unknown>;
}

async function optional<T>(path: string): Promise<T | null> {
  const r = await apiFetch<T>(path);
  if (r.ok) return r.data;
  if (r.status === 401) return apiGetOptional<T>(path); // reuses the sign-in redirect
  return null;
}

export function getCatalog(): Promise<CatalogEntry[] | null> {
  return optional<CatalogEntry[]>("/actions/catalog");
}

export function getRequests(query: { incidentId?: string; status?: string; runId?: string; limit?: number } = {}): Promise<ActionRequest[] | null> {
  const q = new URLSearchParams();
  if (query.incidentId) q.set("incident_id", query.incidentId);
  if (query.status) q.set("status", query.status);
  if (query.runId) q.set("workflow_run_id", query.runId);
  q.set("limit", String(query.limit ?? 100));
  return optional<ActionRequest[]>(`/actions/requests?${q}`);
}

export function getRequest(id: string): Promise<ActionRequest | null> {
  return optional<ActionRequest>(`/actions/requests/${id}`);
}

export function getInbox(): Promise<ActionRequest[] | null> {
  return optional<ActionRequest[]>("/approvals/inbox");
}

export function getKillSwitch(): Promise<KillSwitch | null> {
  return optional<KillSwitch>("/killswitch");
}

export function getPlaybooks(): Promise<Playbook[] | null> {
  return optional<Playbook[]>("/playbooks");
}

export function getPlaybook(id: string): Promise<Playbook | null> {
  return optional<Playbook>(`/playbooks/${id}`);
}

export function getRuns(incidentId?: string): Promise<WorkflowRun[] | null> {
  return optional<WorkflowRun[]>(`/workflow-runs?limit=100${incidentId ? `&incident_id=${incidentId}` : ""}`);
}

export function getRun(id: string): Promise<WorkflowRun | null> {
  return optional<WorkflowRun>(`/workflow-runs/${id}`);
}

export function stepsOf(definition: unknown): StepDef[] {
  const steps = (definition as { steps?: StepDef[] } | null)?.steps;
  return Array.isArray(steps) ? steps : [];
}

export const TIER_HELP: Record<string, string> = {
  T0: "Read-only or annotation: runs automatically",
  T1: "Low impact: runs automatically, audited",
  T2: "Medium impact: one approver",
  T3: "High impact: two different approvers",
};

export interface IncidentAutomation {
  catalog: CatalogEntry[] | null;
  requests: ActionRequest[] | null;
  playbooks: Playbook[] | null;
  runs: WorkflowRun[] | null;
}

/** Everything the incident page shows about actions and playbooks, loaded in parallel. */
export async function getIncidentAutomation(me: Me, incidentId: string): Promise<IncidentAutomation> {
  const can = (p: string) => me.permissions.includes(p);
  const [catalog, requests, playbooks, runs] = await Promise.all([
    can("action:read") ? getCatalog() : null,
    can("action:read") ? getRequests({ incidentId }) : null,
    can("playbook:read") ? getPlaybooks() : null,
    can("playbook:read") ? getRuns(incidentId) : null,
  ]);
  return { catalog, requests, playbooks, runs };
}
