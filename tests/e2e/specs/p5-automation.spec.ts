import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Browser, type Page } from "@playwright/test";

import { devUser, resetTotpReplay, signIn, stagePrimaryAsset, totp } from "./support";

/**
 * P5 journeys on the live stack (core + stream + ai + workflow profiles): a T3 action needs two
 * different approvers with step-up and runs simulated; a playbook dry run completes; the kill
 * switch engages and releases. Every execution is simulated or a dry-run preview.
 */
const ADMIN = "admin@initech.example";
const APPROVER_ONE = "approver.one@initech.example";
const APPROVER_TWO = "approver.two@initech.example";

async function expectA11yClean(page: Page, label: string) {
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  const serious = results.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
  expect(serious.map((v) => `${label}: ${v.id} (${v.nodes.length})`)).toEqual([]);
}

/** A fresh authenticator code for a step-up (clears the replay marker on the dev database first). */
function stepUpCode(email: string): string {
  resetTotpReplay(email);
  return totp(devUser(email).totp_secret ?? "");
}

async function openRealIncident(page: Page) {
  await page.goto("/incidents?portal=soc");
  const table = page.getByRole("table", { name: /^Incidents \(/ });
  let link = table.getByRole("link", { name: /^INC-\d{6}$/ }).first();
  if (!(await link.count())) {
    await page.goto("/connectors");
    const item = page.getByRole("listitem").filter({ hasText: "Ransomware precursor" });
    await item.getByRole("button", { name: "Replay" }).click();
    await expect
      .poll(async () => (await page.goto("/incidents?portal=soc"), table.getByRole("link", { name: /^INC-\d{6}$/ }).count()), {
        timeout: 45_000,
        intervals: [2_000],
      })
      .toBeGreaterThan(0);
    link = table.getByRole("link", { name: /^INC-\d{6}$/ }).first();
  }
  await link.click();
  await page.getByRole("tab", { name: /^Actions/ }).click();
}

async function approveAs(browser: Browser, email: string, url: string, decisions: number) {
  const page = await (await browser.newContext()).newPage();
  await signIn(page, email);
  await page.goto(url);
  const form = page.locator("form").filter({ has: page.getByRole("button", { name: "Approve", exact: true }) });
  await form.getByLabel("Comment (optional)").fill("Checked the evidence (E2E).");
  await form.locator('input[name="mfa_code"]').fill(stepUpCode(email));
  await form.getByRole("button", { name: "Approve", exact: true }).click();
  // The page re-renders without the form once this approver has decided.
  await expect(page.getByRole("button", { name: "Approve", exact: true })).toHaveCount(0, { timeout: 15_000 });
  await expect(page.getByRole("list", { name: "Decisions" }).getByRole("listitem")).toHaveCount(decisions);
  return page;
}

test.describe("P5 automation and approvals", () => {
  test("a T3 action needs two different approvers, then runs simulated", async ({ page, browser }) => {
    test.setTimeout(150_000);
    await signIn(page, ADMIN);
    await openRealIncident(page);
    // A fresh primary asset per run, so reruns do not trip the loop guard on the same host.
    const heading = (await page.getByRole("heading", { level: 1 }).textContent()) ?? "";
    stagePrimaryAsset("initech", heading.split(" ")[0]);
    await page.reload();
    await page.getByRole("tab", { name: /^Actions/ }).click();
    const form = page.locator("form").filter({ has: page.getByRole("button", { name: "Request action", exact: true }) });
    await form.getByLabel("Action").selectOption("edr.isolate_host");
    await form.getByLabel("Mode").selectOption("simulate");
    await form.getByLabel("Justification").fill("Contain the host while we investigate (E2E).");
    await form.getByRole("button", { name: "Request action", exact: true }).click();
    await expect(form.getByRole("status")).toContainText("Waiting for 2 approvals from different people");

    await page.reload();
    await page.getByRole("tab", { name: /^Actions/ }).click();
    await page.getByRole("table", { name: /Action requests for this incident/ }).getByRole("link", { name: "edr.isolate_host" }).first().click();
    await expect(page).toHaveURL(/\/automation\/requests\//);
    const url = page.url();
    await expect(page.getByText("You requested this, so someone else must approve it.")).toBeVisible();
    await expect(page.getByRole("button", { name: "Approve", exact: true })).toHaveCount(0);
    await expectA11yClean(page, "action request");

    const one = await approveAs(browser, APPROVER_ONE, url, 1);
    await expect(one.getByText(/You already decided\. A different approver must approve too\./)).toBeVisible();
    await approveAs(browser, APPROVER_TWO, url, 2);

    await expect
      .poll(async () => (await page.goto(url), page.getByRole("main").getByText("succeeded", { exact: true }).count()), {
        timeout: 45_000,
        intervals: [2_000],
      })
      .toBeGreaterThan(0);
    await expect(page.getByText("Simulated result (no real system was changed)")).toBeVisible();
  });

  test("approvers land on their inbox, which is accessible", async ({ page }) => {
    await signIn(page, APPROVER_ONE);
    await page.goto("/");
    await expect(page).toHaveURL(/\/automation\/approvals$/);
    await expect(page.getByRole("heading", { level: 1, name: "Approvals inbox" })).toBeVisible();
    await expectA11yClean(page, "approvals inbox");
  });

  test("the automation center is accessible and says live execution is off", async ({ page }) => {
    await signIn(page, ADMIN);
    await page.goto("/automation");
    await expect(page.getByRole("heading", { level: 1, name: "Automation center" })).toBeVisible();
    await expect(page.getByText(/Live execution is disabled in\s+this build/)).toBeVisible();
    await expectA11yClean(page, "automation center");
  });

  test("a playbook dry run completes and previews every step", async ({ page }) => {
    test.setTimeout(120_000);
    await signIn(page, ADMIN);
    await openRealIncident(page);
    await page.goto("/automation");
    await page.getByRole("link", { name: "Enrich & ticket (DEMO)" }).click();
    const run = page.locator("form").filter({ has: page.getByRole("button", { name: "Start run" }) });
    await run.getByLabel("Mode").selectOption("dry_run");
    await run.getByRole("button", { name: "Start run" }).click();
    await expect(page).toHaveURL(/\/automation\/runs\//, { timeout: 20_000 });
    await expect(page.getByRole("heading", { level: 2, name: "Steps" })).toBeVisible();
    await expect(page.getByText("Every step succeeded or was skipped.")).toBeVisible({ timeout: 60_000 });
    await expectA11yClean(page, "playbook run");
  });

  test("the kill switch engages and releases with step-up", async ({ page }) => {
    await signIn(page, ADMIN);
    await page.goto("/automation");
    const card = page.locator("section").filter({ has: page.getByRole("heading", { name: "Kill switch" }) });
    const engage = card.locator("form");
    await engage.getByLabel("Reason (audited)").fill("E2E drill");
    await engage.locator('input[name="mfa_code"]').fill(stepUpCode(ADMIN));
    await engage.getByRole("button", { name: "Engage kill switch" }).click();
    await expect(engage.getByRole("status").last()).toContainText("Kill switch engaged");
    await page.reload();
    await expect(card.getByText("Engaged: automation is halted")).toBeVisible();
    const release = card.locator("form");
    await release.getByLabel("Reason (audited)").fill("E2E drill over");
    await release.locator('input[name="mfa_code"]').fill(stepUpCode(ADMIN));
    await release.getByRole("button", { name: "Release kill switch" }).click();
    await expect(release.getByRole("status").last()).toContainText("Kill switch released");
    await page.reload();
    await expect(card.getByText("Released: automation may run")).toBeVisible();
  });
});
