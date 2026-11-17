import { readFileSync } from "node:fs";

import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { signIn } from "./support";

/**
 * P6 journeys on the live stack (all default profiles, including search): the Command Center
 * shows real KPIs that drill to their records, the AI briefing is cited, reports export as CSV and
 * PDF, hunts run in the background, Investigate pivots on facets, and the MSP view compares
 * customers. Data comes from sandbox scenario replays.
 */
const ADMIN = "admin@initech.example";
const EXEC = "msp.exec@acme.example";

async function expectA11yClean(page: Page, label: string) {
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  const serious = results.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
  expect(serious.map((v) => `${label}: ${v.id} (${v.nodes.length})`)).toEqual([]);
}

/** Replays the ransomware scenario and waits until the projector has turned it into KPIs. */
async function ensureData(page: Page) {
  await page.goto("/command?period=24h");
  const tile = page.getByRole("link", { name: /^Incidents opened/ }).first();
  const value = async () => Number(((await tile.locator("p").nth(1).textContent()) ?? "0").replace(/\D/g, "") || "0");
  if ((await tile.count()) && (await value()) > 0) return;
  await page.goto("/connectors");
  const item = page.getByRole("listitem").filter({ hasText: "Ransomware precursor" });
  await item.getByRole("button", { name: "Replay" }).click();
  await expect(item.getByRole("status")).toContainText(/Published \d+ records/);
  await expect
    .poll(async () => (await page.goto("/command?period=24h"), (await tile.count()) ? value() : 0), { timeout: 60_000, intervals: [3_000] })
    .toBeGreaterThan(0);
}

test.describe("P6 command center, reports, hunting and investigate", () => {
  test("command center KPIs are real and drill to their records", async ({ page }) => {
    test.setTimeout(120_000);
    await signIn(page, ADMIN);
    await ensureData(page);
    await page.goto("/command?period=7d");
    await expect(page.getByRole("heading", { level: 1, name: "Executive Command Center" })).toBeVisible();
    await expect(page.getByText("Generated demonstration data")).toHaveCount(0);
    const tile = page.getByRole("link", { name: /^Incidents opened/ }).first();
    const shown = ((await tile.locator("p").nth(1).textContent()) ?? "").replace(/\D/g, "");
    await expectA11yClean(page, "command center");
    await tile.click();
    await expect(page).toHaveURL(/\/command\/kpi\/incidents_opened\?domain=all&period=7d/);
    await expect(page.getByRole("table", { name: new RegExp(`^${shown} incidents behind Incidents opened`) })).toBeVisible();
    await expectA11yClean(page, "KPI records");
    await page.goto("/command/kpi/resolve_sla?domain=all&period=7d");
    await expect(page.getByRole("columnheader", { name: /Resolved in time/ })).toBeVisible();
  });

  test("the daily briefing is AI-labelled and cites KPIs", async ({ page }) => {
    test.setTimeout(90_000);
    await signIn(page, ADMIN);
    await page.goto("/command?period=24h");
    const form = page.locator("form").filter({ has: page.getByRole("button", { name: /Generate (a fresh )?briefing/ }) });
    await form.getByRole("button", { name: /Generate (a fresh )?briefing/ }).click();
    await expect(form.getByRole("status")).toContainText("Briefing generated", { timeout: 30_000 });
    const card = page.getByRole("article", { name: "Daily briefing (AI-generated)" });
    await expect(card.getByText("AI-generated", { exact: true })).toBeVisible();
    await card.getByText(/^Evidence \(\d+\)$/).click();
    await expect(card.getByRole("link", { name: /\(last 24 h\)$/ }).first()).toBeVisible();
  });

  test("a saved report downloads as CSV and PDF", async ({ page }) => {
    await signIn(page, ADMIN);
    await page.goto("/reports");
    const name = `E2E KPIs ${Date.now()}`;
    const form = page.locator("form").filter({ has: page.getByRole("button", { name: "Save report" }) });
    await form.getByLabel("Name").fill(name);
    await form.getByRole("button", { name: "Save report" }).click();
    await expect(form.getByRole("status")).toContainText("Report saved");
    const card = page.getByRole("listitem").filter({ hasText: name });
    const [csv] = await Promise.all([page.waitForEvent("download"), card.getByRole("link", { name: "Download CSV" }).click()]);
    expect(csv.suggestedFilename()).toMatch(/\.csv$/);
    expect(readFileSync(await csv.path(), "utf-8")).toContain("Incidents opened");
    const [pdf] = await Promise.all([page.waitForEvent("download"), card.getByRole("link", { name: "Download PDF" }).click()]);
    expect(readFileSync(await pdf.path()).subarray(0, 8).toString()).toBe("%PDF-1.4");
    await expectA11yClean(page, "reports");
  });

  test("a hunt runs in the background and shows results", async ({ page }) => {
    test.setTimeout(90_000);
    await signIn(page, ADMIN);
    await page.goto("/soc/hunting");
    const run = page.locator("form").filter({ has: page.getByRole("button", { name: "Run hunt", exact: true }) }).last();
    await run.getByLabel("Domain").selectOption("soc");
    await run.getByLabel("Time window").selectOption("720");
    await run.getByRole("button", { name: "Run hunt", exact: true }).click();
    await expect(page).toHaveURL(/\/soc\/hunting\?run=/, { timeout: 20_000 });
    await expect(page.getByRole("table", { name: "Hunt results" })).toBeVisible({ timeout: 30_000 });
    await expect(page.getByText(/\d+ matching events?/)).toBeVisible();
    await expectA11yClean(page, "hunting");
  });

  test("investigate searches events and pivots on a facet", async ({ page }) => {
    await signIn(page, ADMIN);
    await page.goto("/soc/investigations?hours=720");
    await expect(page.getByRole("heading", { level: 1, name: "Investigate" })).toBeVisible();
    await expect(page.getByRole("table", { name: "Matching events" })).toBeVisible();
    const facet = page.getByRole("complementary", { name: "Facets" }).getByRole("link").first();
    await facet.click();
    await expect(page).toHaveURL(/\/soc\/investigations\?(severity|asset|actor_user|connector)=/);
    await expect(page.getByText(/\d+ matching events?/)).toBeVisible();
    await expectA11yClean(page, "investigate");
  });

  test("the MSP view compares real customer KPIs", async ({ page }) => {
    await signIn(page, EXEC);
    await page.getByLabel("Tenant").selectOption({ label: "Acme Managed Services: All customers (read-only)" });
    await expect(page.getByText("All customers · read-only")).toBeVisible();
    await page.goto("/command/customers");
    await expect(page.getByRole("table", { name: "Customer KPI comparison" })).toBeVisible();
    await expect(page.getByRole("table", { name: "Customer KPI comparison" })).toContainText("Initech");
    await expectA11yClean(page, "customer comparison");
  });
});
