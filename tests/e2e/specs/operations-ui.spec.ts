import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { signIn } from "./support";

const NOC_ENGINEER = "noc@globex.example"; // noc_engineer: NOC portal, assets, incidents, playbooks, reports
const SOC_RESPONDER = "soc@initech.example"; // soc_analyst_l2: SOC portal, hunting, vulnerabilities
const TENANT_ADMIN = "admin@initech.example"; // tenant_admin: everything, MFA

async function expectA11yClean(page: Page, label: string) {
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  const serious = results.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
  expect(serious.map((v) => `${label}: ${v.id} (${v.nodes.length})`)).toEqual([]);
}

test.describe("NOC portal", () => {
  test("role-based menu, every NOC screen renders with DEMO labels", async ({ page }) => {
    await signIn(page, NOC_ENGINEER);
    const portals = page.getByRole("navigation", { name: "Portals" });
    await expect(portals.getByRole("link", { name: "AI NOC" })).toBeVisible();
    await expect(portals.getByRole("link", { name: "AI SOC" })).toHaveCount(0);

    const section = page.getByRole("navigation", { name: "Section" });
    for (const [label, heading] of [
      ["Overview", "AI NOC"],
      ["Alerts & correlation", "Alerts & correlation"],
      ["Root cause analysis", "Root cause analysis"],
      ["SLA reporting", "SLA reporting"],
      ["Servers", "Server monitoring"],
      ["Network", "Network monitoring"],
      ["Cloud operations", "Cloud operations"],
      ["Applications (APM)", "Application performance"],
      ["Databases", "Databases"],
    ] as const) {
      await section.getByRole("link", { name: label, exact: true }).click();
      await expect(page.getByRole("heading", { level: 1, name: heading, exact: true })).toBeVisible();
      await expect(page.getByText("DEMO").first()).toBeVisible();
    }
    // No security-only areas for a NOC engineer.
    await expect(section.getByRole("link", { name: "Connectors" })).toHaveCount(0);
  });

  test("drill down from inventory to an asset", async ({ page }) => {
    await signIn(page, NOC_ENGINEER);
    await page.goto("/noc/servers");
    const first = page.getByRole("table", { name: "Server monitoring inventory" }).getByRole("link").first();
    const name = (await first.textContent())?.trim() ?? "";
    await first.click();
    await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
    await expect(page.getByRole("img", { name: /over the last 48 hours/ }).first()).toBeVisible();
  });

  test("tables filter, sort and paginate", async ({ page }) => {
    await signIn(page, NOC_ENGINEER);
    await page.goto("/noc/alerts");
    const status = page.getByRole("status").filter({ hasText: "records" }).first();
    const before = await status.textContent();
    await page.getByRole("combobox", { name: "Severity" }).first().selectOption("critical");
    await expect(status).not.toHaveText(before ?? "");
    const header = page.getByRole("columnheader", { name: /Raised/ }).first();
    await header.getByRole("button").click();
    await expect(header).toHaveAttribute("aria-sort", "ascending");
    await page.getByRole("tab", { name: /Correlated groups/ }).click();
    await expect(page.getByRole("tabpanel")).toContainText(/confidence/);
  });

  test("incident drill-down shows timeline, cited AI RCA and simulated response", async ({ page }) => {
    await signIn(page, NOC_ENGINEER);
    await page.goto("/incidents");
    await page.getByRole("table", { name: "Incidents" }).getByRole("link").first().click();
    await expect(page.getByRole("tab", { name: /Timeline/ })).toHaveAttribute("aria-selected", "true");
    await page.getByRole("tab", { name: "Root cause (AI)" }).click();
    await expect(page.getByText("AI draft (demo) · not confirmed")).toBeVisible();
    await expect(page.getByText("Cited evidence", { exact: true }).first()).toBeVisible();
    await page.getByRole("tab", { name: /Response workflow/ }).click();
    await expect(page.getByText(/All execution is/)).toContainText("simulated");
  });

  test("security screens are closed to a NOC role", async ({ page }) => {
    await signIn(page, NOC_ENGINEER);
    await page.goto("/soc/hunting");
    await expect(page.getByText(/Your role does not include this area/)).toBeVisible();
  });

  test("NOC screens meet WCAG 2.1 AA (no serious or critical axe findings)", async ({ page }) => {
    await signIn(page, NOC_ENGINEER);
    for (const path of ["/noc", "/noc/servers", "/noc/alerts", "/noc/sla", "/incidents", "/reports", "/automation"]) {
      await page.goto(path);
      await expectA11yClean(page, path);
    }
  });
});

test.describe("SOC portal", () => {
  test("every SOC screen renders", async ({ page }) => {
    await signIn(page, SOC_RESPONDER);
    for (const [path, heading] of [
      ["/soc", "AI SOC"],
      ["/soc/investigations", "Investigations"],
      ["/soc/siem", "SIEM events"],
      ["/soc/edr", "EDR / XDR"],
      ["/soc/threat-intel", "Threat intelligence"],
      ["/soc/hunting", "AI threat hunting"],
      ["/soc/mitre", "MITRE ATT&CK"],
      ["/soc/vulnerabilities", "Vulnerability management"],
      ["/soc/vapt", "VAPT"],
    ] as const) {
      await page.goto(path);
      await expect(page.getByRole("heading", { level: 1, name: heading, exact: true })).toBeVisible();
    }
  });

  test("EDR detection drill-down shows the process tree", async ({ page }) => {
    await signIn(page, SOC_RESPONDER);
    await page.goto("/soc/edr");
    await page.getByRole("table", { name: /EDR detections/ }).locator("tbody").getByRole("button").first().click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toContainText("Process tree");
    await expect(dialog).toContainText("powershell.exe");
    await dialog.getByRole("button", { name: "Close details" }).click();
    await expect(dialog).toBeHidden();
  });

  test("threat data never looks like real-world identifiers", async ({ page }) => {
    await signIn(page, SOC_RESPONDER);
    await page.goto("/soc/vulnerabilities");
    await expect(page.getByRole("table", { name: "Vulnerability findings" })).toContainText("CVE-DEMO-");
    await page.goto("/soc/threat-intel");
    await expect(page.getByText("Ember Lynx (demo)").first()).toBeVisible();
  });

  test("SOC screens meet WCAG 2.1 AA (no serious or critical axe findings)", async ({ page }) => {
    await signIn(page, SOC_RESPONDER);
    for (const path of ["/soc", "/soc/siem", "/soc/mitre", "/soc/vulnerabilities", "/soc/hunting"]) {
      await page.goto(path);
      await expectA11yClean(page, path);
    }
  });
});

test.describe("Administration and shared areas", () => {
  test("connectors show honest status, never a fake connection", async ({ page }) => {
    await signIn(page, TENANT_ADMIN);
    await page.goto("/connectors");
    const table = page.getByRole("table", { name: "Connector catalog" });
    await expect(table.getByRole("row")).toHaveCount(17); // header + 16 connectors
    await expect(table).not.toContainText(/Connected|Healthy|Online/);
    const statuses = await table.locator("tbody tr td:nth-child(5)").allTextContents();
    expect(new Set(statuses)).toEqual(new Set(["Not configured"]));
  });

  test("command center, global search and real tenant admin coexist", async ({ page }) => {
    await signIn(page, TENANT_ADMIN);
    await page.goto("/command");
    await expect(page.getByRole("heading", { level: 1, name: "Executive Command Center" })).toBeVisible();
    await expect(page.getByRole("img", { name: /alert volume/i }).first()).toBeVisible();
    await page.getByRole("searchbox", { name: /Search incidents/ }).fill("payments");
    await page.getByRole("searchbox", { name: /Search incidents/ }).press("Enter");
    await expect(page.getByRole("status").filter({ hasText: /results? for/ })).toBeVisible();
    await page.goto("/admin/users");
    await expect(page.getByRole("table")).toContainText("@initech.example"); // real API data, not demo
  });

  test("mobile navigation opens as a dialog", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await signIn(page, NOC_ENGINEER);
    await page.goto("/noc");
    await page.getByRole("button", { name: /Menu/ }).click();
    const nav = page.getByRole("dialog", { name: "Navigation" });
    await nav.getByRole("link", { name: "Servers" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Server monitoring" })).toBeVisible();
    await expect(nav).toBeHidden();
  });
});

test.describe("Dark theme", () => {
  test.use({ colorScheme: "dark" });

  test("key screens meet WCAG 2.1 AA in dark mode", async ({ page }) => {
    await signIn(page, TENANT_ADMIN);
    for (const path of ["/command", "/noc", "/noc/servers", "/soc", "/soc/mitre", "/soc/edr", "/incidents", "/connectors", "/automation", "/admin/users"]) {
      await page.goto(path);
      await expectA11yClean(page, `${path} (dark)`);
    }
  });
});
