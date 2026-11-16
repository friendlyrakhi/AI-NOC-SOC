import { expect, test } from "@playwright/test";

import { devUser, signIn } from "./support";

test("unauthenticated visitors are sent to sign-in", async ({ page }) => {
  await page.goto("/noc");
  await expect(page).toHaveURL(/\/login\?next=%2Fnoc/);
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await expect(page.getByText("SANDBOX: development build")).toBeVisible();
});

test("wrong password shows an error and no session", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel("Email").fill("noc@globex.example");
  await page.getByLabel("Password").fill("definitely-not-it");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("Email or password is incorrect.")).toBeVisible();
  const cookies = await page.context().cookies();
  expect(cookies.find((c) => c.name === "nocsoc_session")).toBeUndefined();
});

test("session cookie is HttpOnly and SameSite=Strict", async ({ page }) => {
  await signIn(page, "noc@globex.example");
  const cookie = (await page.context().cookies()).find((c) => c.name === "nocsoc_session");
  expect(cookie?.httpOnly).toBe(true);
  expect(cookie?.sameSite).toBe("Strict");
  expect(await page.evaluate(() => document.cookie)).not.toContain("nocsoc_session");
});

test("MSP analyst sees only delegated customers and the read-only All customers view", async ({ page }) => {
  await signIn(page, "msp.noc@acme.example");
  await expect(page).toHaveURL(/\/noc$/);
  await expect(page.getByRole("link", { name: "AI SOC" })).toHaveCount(0);

  const switcher = page.getByLabel("Tenant");
  const options = await switcher.locator("option").allTextContents();
  expect(options).toContain("Globex Corporation (via MSP)");
  expect(options.join(" ")).not.toContain("Initech");

  await switcher.selectOption({ label: "Acme Managed Services: All customers (read-only)" });
  await expect(page.getByText("All customers · read-only")).toBeVisible();
  const customers = page.locator("section", { hasText: "Customers (" });
  await expect(customers.getByRole("cell", { name: /Globex Corporation/ })).toBeVisible();
  await expect(customers.getByText("Initech")).toHaveCount(0);

  await switcher.selectOption({ label: "Globex Corporation (via MSP)" });
  await expect(page.getByText("Delegated access")).toBeVisible();
});

test("customer admin signs in with MFA and administers only their tenant", async ({ page }) => {
  await signIn(page, "admin@globex.example");
  await page.getByRole("link", { name: "Administration" }).click();
  await expect(page.getByRole("heading", { name: "Tenant" })).toBeVisible();
  await expect(page.locator("dd", { hasText: "Globex Corporation" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Customers" })).toHaveCount(0);

  await page.getByRole("link", { name: "Members" }).click();
  const rows = page.locator("tbody tr");
  await expect(rows.first()).toBeVisible();
  for (const email of await page.locator("tbody td.font-mono").allTextContents()) {
    expect(email).toMatch(/@globex\.example$/);
  }

  await page.getByRole("link", { name: "Delegations" }).click();
  await expect(page.getByRole("heading", { name: "MSP access" })).toBeVisible();
  await expect(page.getByRole("cell", { name: "Acme Managed Services" }).first()).toBeVisible();

  await page.getByRole("link", { name: "Audit log" }).click();
  await expect(page.getByText(/verified · \d+ entries/)).toBeVisible();
});

test("sensitive changes require the authenticator code", async ({ page }) => {
  await signIn(page, "admin@initech.example");
  await page.goto("/admin/roles");
  const form = page.locator("section", { hasText: "Create a custom role" });
  await form.locator('input[name="key"]').fill(`e2e_${Date.now() % 100000}`);
  await form.locator('input[name="name"]').fill("E2E role");
  await form.getByRole("button", { name: "Create role" }).click();
  await expect(form.getByText(/authenticator code\./)).toBeVisible();

  await form.locator('input[name="mfa_code"]').fill("000000");
  await form.getByRole("button", { name: "Create role" }).click();
  await expect(form.getByText("The authentication code is not valid.")).toBeVisible();

  expect(devUser("admin@initech.example").totp_secret).toBeTruthy();
});
