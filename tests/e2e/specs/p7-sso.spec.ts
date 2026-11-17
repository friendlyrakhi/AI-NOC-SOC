import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

import { expect, test } from "@playwright/test";

import { totp } from "./support";

/**
 * P7 optional single sign-on through the DEMO Keycloak (`sso` profile). Skipped when the API reports
 * SSO as disabled. The realm forces an authenticator on first sign-in; the test enrols one and keeps
 * its secret in a git-ignored file so later runs can answer the OTP prompt.
 */
const API = process.env.NOCSOC_API_URL ?? "http://127.0.0.1:8100";
const ROOT = path.resolve(__dirname, "..", "..", "..");
const USER = "soc@initech.example";
const OTP_FILE = path.join(__dirname, "..", ".auth", "sso-otp.json");

async function ssoEnabled(): Promise<boolean> {
  try {
    const r = await fetch(`${API}/api/v1/auth/oidc/config`);
    return r.ok && ((await r.json()) as { enabled: boolean }).enabled;
  } catch {
    return false;
  }
}

test.describe("P7 single sign-on", () => {
  test("a Keycloak user signs in through OIDC and lands in the platform", async ({ page }) => {
    test.skip(!(await ssoEnabled()), "sso profile not running");
    test.setTimeout(90_000);
    const password = readFileSync(path.join(ROOT, "infrastructure", "secrets", "sso_demo_password"), "utf8").trim();

    await page.goto("/login");
    await page.getByRole("link", { name: /Sign in with Keycloak/ }).click();
    await expect(page).toHaveURL(/127\.0\.0\.1:8180\/realms\/nocsoc\//);
    await page.locator("#username").fill(USER);
    await page.locator("#password").fill(password);
    await page.locator("#kc-login").click();

    const setup = page.locator("#kc-totp-secret-key");
    const prompt = page.locator("#otp");
    await expect(setup.or(page.locator("#mode-manual")).or(prompt)).toBeVisible();
    const enrolling = !(await prompt.isVisible());
    if (enrolling && (await page.locator("#mode-manual").isVisible())) await page.locator("#mode-manual").click();
    if (enrolling) {
      await expect(setup).toBeVisible();
      const secret = ((await setup.textContent()) ?? "").replace(/\s+/g, "");
      mkdirSync(path.dirname(OTP_FILE), { recursive: true });
      writeFileSync(OTP_FILE, JSON.stringify({ [USER]: secret }));
      await page.locator("#totp").fill(totp(secret));
      await page.locator("#saveTOTPBtn").click();
    } else {
      test.skip(!existsSync(OTP_FILE), "authenticator enrolled in an earlier run without a saved secret");
      const secret = (JSON.parse(readFileSync(OTP_FILE, "utf8")) as Record<string, string>)[USER];
      // Codes are single use: wait for a fresh 30-second window in case an earlier run used this one.
      await page.waitForTimeout(31_000 - (Date.now() % 30_000));
      await prompt.fill(totp(secret));
      await page.locator("#kc-login").click();
    }

    // Back in the platform with a session: no sign-in page, and the user is shown.
    await expect(page).toHaveURL(/127\.0\.0\.1:3000\/(?!login)/);
    await expect(page.getByText(USER).first()).toBeAttached();
  });
});
