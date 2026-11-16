import { createHmac, randomBytes } from "node:crypto";

import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { signIn } from "./support";

/**
 * P3 journeys on the live dev stack (core + stream + analytics): correlation into incidents,
 * joint NOC/SOC visibility, the incident workflow, live updates and the new NOC pages.
 */
const INITECH_ADMIN = "admin@initech.example"; // has the ransomware-scenario connectors (EDR, Wazuh, Datadog)
const GLOBEX_ADMIN = "admin@globex.example"; // has ServiceNow (CMDB topology, ITSM) and the core-switch connectors
const API = process.env.E2E_API_URL ?? "http://127.0.0.1:8100";

async function expectA11yClean(page: Page, label: string) {
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  const serious = results.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
  expect(serious.map((v) => `${label}: ${v.id} (${v.nodes.length})`)).toEqual([]);
}

async function replay(page: Page, scenario: string) {
  await page.goto("/connectors");
  const item = page.getByRole("listitem").filter({ hasText: scenario });
  await item.getByRole("button", { name: "Replay" }).click();
  await expect(item.getByRole("status")).toContainText(/Published \d+ records/);
}

test.describe("P3 incidents", () => {
  test("ransomware precursor becomes one joint incident visible to both NOC and SOC", async ({ page }) => {
    test.setTimeout(90_000);
    await signIn(page, INITECH_ADMIN);
    await replay(page, "Ransomware precursor");
    const jointNumber = async (portal: "noc" | "soc") => {
      await page.goto(`/incidents?portal=${portal}`);
      const row = page.getByRole("table", { name: /^Incidents \(/ }).getByRole("row").filter({ hasText: "JOINT" }).first();
      return (await row.count()) ? ((await row.getByRole("cell").first().textContent()) ?? "").trim() : "";
    };
    await expect.poll(() => jointNumber("noc"), { timeout: 45_000, intervals: [2_000] }).toMatch(/^INC-\d{6}$/);
    const number = await jointNumber("noc");
    expect(await jointNumber("soc")).toBe(number);

    // Workflow on the real incident.
    await page.goto("/incidents?portal=soc");
    await page.getByRole("table", { name: /^Incidents \(/ }).getByRole("link", { name: number }).click();
    await expect(page.getByRole("heading", { level: 1, name: new RegExp(`^${number}`) })).toBeVisible();
    await expect(page.getByText("SANDBOX").first()).toBeVisible();
    await page.getByRole("tab", { name: /Alerts/ }).click();
    await expect(page.getByRole("table", { name: "Alerts in this incident" })).toContainText(/Same asset|Opened incident/);
    await page.getByRole("tab", { name: /Timeline/ }).click();
    await expect(page.getByRole("list", { name: "Incident timeline" })).toContainText(/JOINT/);

    const status = page.locator("form").filter({ has: page.getByRole("button", { name: "Update status" }) });
    if (await status.count()) {
      await status.getByLabel("Reason (optional)").fill("E2E triage");
      await status.getByRole("button", { name: "Update status" }).click();
      await expect(status.getByRole("status")).toContainText("Status is now");
    }
    const comment = page.locator("form").filter({ has: page.getByRole("button", { name: "Comment" }) });
    await comment.getByLabel("Comment").fill("<b>E2E</b> note stays text");
    await comment.getByRole("button", { name: "Comment" }).click();
    await expect(comment.getByRole("status")).toContainText("Comment added");
    await expect(page.getByRole("list", { name: "Incident timeline" })).toContainText("<b>E2E</b> note stays text");
    await expectA11yClean(page, "incident detail");
  });

  test("an ingested alert reaches an open page in under 5 seconds (live updates)", async ({ page, browser }) => {
    test.setTimeout(90_000);
    await signIn(page, GLOBEX_ADMIN);
    // A generic webhook integration gives this test a signing secret it controls.
    await page.goto("/connectors");
    const add = page.locator("form").filter({ has: page.getByRole("button", { name: "Add in sandbox mode" }) });
    await add.getByLabel("Connector").selectOption("generic.webhook");
    await add.getByLabel("Name").fill(`E2E latency ${Date.now()}`);
    await add.getByRole("button", { name: "Add in sandbox mode" }).click();
    const shown = (await page.getByText(/Webhook secret: whs_/).textContent()) ?? "";
    const secret = /Webhook secret: (whs_\S+)/.exec(shown)?.[1] ?? "";
    const ingress = /\/api\/v1\/ingest\/webhooks\/([0-9a-f-]{36})/.exec(shown)?.[1] ?? "";
    expect(secret && ingress).toBeTruthy();

    await page.goto("/noc/alerts");
    await expect(page.getByRole("status").filter({ hasText: "Live" })).toBeVisible({ timeout: 15_000 });
    const tab = page.getByRole("tab", { name: /Sandbox pipeline/ });
    const count = async () => Number(/(\d+)/.exec((await tab.textContent()) ?? "")?.[1] ?? "0");
    const before = await count();

    const body = JSON.stringify({ id: `e2e-${randomBytes(6).toString("hex")}`, title: "E2E latency probe", severity: "high", host: "e2e-probe-host", domain: "noc" });
    const ts = Math.floor(Date.now() / 1000);
    const nonce = randomBytes(12).toString("hex");
    const signature = "v1=" + createHmac("sha256", secret).update(`${ts}.${nonce}.${body}`).digest("hex");
    const started = Date.now();
    const context = await browser.newContext();
    const r = await context.request.post(`${API}/api/v1/ingest/webhooks/${ingress}`, {
      data: body,
      headers: { "content-type": "application/json", "x-nocsoc-timestamp": String(ts), "x-nocsoc-nonce": nonce, "x-nocsoc-signature": signature },
    });
    expect(r.status()).toBe(202);
    await expect.poll(count, { timeout: 5_000, intervals: [100] }).toBeGreaterThan(before);
    const latency = Date.now() - started;
    test.info().annotations.push({ type: "alert-to-UI latency (ms)", description: String(latency) });
    expect(latency).toBeLessThan(5_000);
    await context.close();
  });

  test("ServiceNow ticket links to an incident through the sandbox connector", async ({ page }) => {
    await signIn(page, GLOBEX_ADMIN);
    await page.goto("/incidents");
    const declare = page.locator("form").filter({ has: page.getByRole("button", { name: "Declare incident" }) });
    await declare.getByLabel("Title").fill(`E2E ITSM ${Date.now()}`);
    await declare.getByRole("button", { name: "Declare incident" }).click();
    await expect(page.getByRole("heading", { level: 1, name: /^INC-\d{6} · E2E ITSM/ })).toBeVisible();
    const sn = page.locator("form").filter({ has: page.getByRole("button", { name: "Open ServiceNow ticket" }) });
    await sn.getByRole("button", { name: "Open ServiceNow ticket" }).click();
    // On success the page refreshes: the form gives way to the linked ticket.
    await expect(page.getByText("In sync (sandbox)")).toBeVisible();
    await expect(page.getByRole("list", { name: "Incident timeline" })).toContainText(/ServiceNow INC\d{7} ← platform: new \(simulated\)/);
  });

  test("topology and maintenance pages render real services and controls", async ({ page }) => {
    await signIn(page, GLOBEX_ADMIN);
    await page.goto("/noc/topology");
    await expect(page.getByRole("heading", { level: 1, name: "Services & topology" })).toBeVisible();
    const services = page.getByRole("table", { name: "Business services" });
    await expect.poll(async () => (await page.reload(), services.getByRole("row").count()), { timeout: 30_000, intervals: [3_000] }).toBeGreaterThan(5);
    await services.getByRole("link", { name: "Payments" }).click();
    await expect(page.getByRole("table", { name: "Assets of Payments" })).toContainText("Runs the service");
    await expectA11yClean(page, "service detail");

    await page.goto("/noc/maintenance");
    await expect(page.getByRole("heading", { level: 1, name: "Maintenance & noise control" })).toBeVisible();
    await expect(page.getByText("Service topology")).toBeVisible();
    await expectA11yClean(page, "maintenance");
    await page.goto("/noc/topology");
    await expectA11yClean(page, "topology");
    await page.goto("/incidents");
    await expectA11yClean(page, "incidents");
  });
});
