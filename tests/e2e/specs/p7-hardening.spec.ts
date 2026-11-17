import { expect, test } from "@playwright/test";

import { signIn } from "./support";

/**
 * P7 browser checks: the nonce-based Content-Security-Policy (SEC-WEB-01, found missing by the DAST
 * baseline) is sent on every page and does not break the app, and the session cookie is HttpOnly
 * and SameSite=Strict.
 */
const ADMIN = "admin@globex.example";

function directives(header: string | undefined): Map<string, string> {
  const out = new Map<string, string>();
  for (const part of (header ?? "").split(";")) {
    const [name, ...rest] = part.trim().split(/\s+/);
    if (name) out.set(name, rest.join(" "));
  }
  return out;
}

test.describe("P7 hardening", () => {
  test("pages carry a nonce-based CSP and still work under it", async ({ page }) => {
    const violations: string[] = [];
    page.on("console", (m) => {
      if (/Content Security Policy|Refused to (execute|load)/i.test(m.text())) violations.push(m.text());
    });
    const login = await page.goto("/login");
    const csp = directives(login?.headers()["content-security-policy"]);
    expect(csp.get("default-src")).toBe("'self'");
    expect(csp.get("script-src")).toMatch(/'nonce-[A-Za-z0-9+/=]+' 'strict-dynamic'/);
    expect(csp.get("script-src")).not.toContain("'unsafe-inline'");
    expect(csp.get("object-src")).toBe("'none'");
    expect(csp.get("frame-ancestors")).toBe("'none'");

    const second = directives((await page.goto("/login"))?.headers()["content-security-policy"]);
    expect(second.get("script-src")).not.toBe(csp.get("script-src")); // a fresh nonce per response

    await signIn(page, ADMIN);
    await page.goto("/incidents");
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    // Client-side navigation and hydrated components work under the policy.
    await page.getByRole("link", { name: "NOC" }).first().click();
    await expect(page).toHaveURL(/\/noc/);
    expect(violations).toEqual([]);
  });

  test("session cookie is HttpOnly and SameSite=Strict", async ({ page, context }) => {
    await signIn(page, ADMIN);
    const cookie = (await context.cookies()).find((c) => c.name === "nocsoc_session");
    expect(cookie?.httpOnly).toBe(true);
    expect(cookie?.sameSite).toBe("Strict");
  });
});
