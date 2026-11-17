// NFR-1 API load test (P7): p95 < 300 ms for list/get at 100k alerts per tenant.
// Run through scripts/loadtest.py api (it seeds the SYNTHETIC tenant and passes a read-only API key).
import http from "k6/http";
import { check } from "k6";

const BASE = __ENV.API_URL || "http://api:8000";
const KEY = __ENV.API_KEY;
const VUS = Number(__ENV.VUS || 20);
const DURATION = __ENV.DURATION || "2m";

export const options = {
  scenarios: {
    reads: { executor: "constant-vus", vus: VUS, duration: DURATION },
  },
  thresholds: {
    "http_req_duration{kind:list}": ["p(95)<300"],
    "http_req_duration{kind:get}": ["p(95)<300"],
    http_req_failed: ["rate<0.01"],
    checks: ["rate>0.99"],
  },
  summaryTrendStats: ["avg", "med", "p(90)", "p(95)", "p(99)", "max"],
};

const params = (kind, name) => ({ headers: { Authorization: `Bearer ${KEY}` }, tags: { kind, name } });

export function setup() {
  const alerts = http.get(`${BASE}/api/v1/alerts?limit=200`, params("setup", "alerts")).json("items");
  const incidents = http.get(`${BASE}/api/v1/incidents?limit=200`, params("setup", "incidents")).json("items");
  if (!alerts || alerts.length === 0) throw new Error("no alerts: seed the load-test tenant first");
  return { alerts: alerts.map((a) => a.id), incidents: (incidents || []).map((i) => i.id) };
}

const pick = (xs) => xs[Math.floor(Math.random() * xs.length)];
const LISTS = [
  ["alerts", "/api/v1/alerts?limit=50"],
  ["alerts_noc_high", "/api/v1/alerts?domain=noc&severity=high&limit=50"],
  ["alerts_open_soc", "/api/v1/alerts?domain=soc&status=new&limit=50"],
  ["incidents", "/api/v1/incidents?limit=50"],
  ["incidents_open", "/api/v1/incidents?open_only=true&limit=50"],
  ["assets", "/api/v1/assets?limit=50"],
  ["search", "/api/v1/search?q=host-42"],
];

export default function (data) {
  const [name, path] = pick(LISTS);
  const r = http.get(`${BASE}${path}`, params("list", name));
  check(r, { "list 200": (x) => x.status === 200 });
  const a = http.get(`${BASE}/api/v1/alerts/${pick(data.alerts)}`, params("get", "alert"));
  check(a, { "alert 200": (x) => x.status === 200 });
  if (data.incidents.length) {
    const i = http.get(`${BASE}/api/v1/incidents/${pick(data.incidents)}`, params("get", "incident"));
    check(i, { "incident 200": (x) => x.status === 200 });
  }
}
