import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { expect, type Page } from "@playwright/test";

interface DevUser {
  email: string;
  password: string;
  totp_secret: string | null;
}

const DEV_USERS = resolve(__dirname, "../../../infrastructure/secrets/dev-users.json");

export function devUser(email: string): DevUser {
  const users: DevUser[] = JSON.parse(readFileSync(DEV_USERS, "utf-8")).users;
  const user = users.find((u) => u.email === email);
  if (!user) throw new Error(`${email} not in dev-users.json; run scripts/dev seed`);
  return user;
}

function base32Decode(input: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of input.replace(/=+$/, "").toUpperCase()) bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  const bytes = bits.match(/.{8}/g) ?? [];
  return Buffer.from(bytes.map((b) => parseInt(b, 2)));
}

/** RFC 6238 TOTP (SHA-1, 6 digits, 30 s), matching the API. `offset` selects a later time step. */
export function totp(secret: string, offset = 0): string {
  const counter = Math.floor(Date.now() / 1000 / 30) + offset;
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const hmac = createHmac("sha1", base32Decode(secret)).update(msg).digest();
  const o = hmac[hmac.length - 1] & 0xf;
  const code = (hmac.readUInt32BE(o) & 0x7fffffff) % 1_000_000;
  return code.toString().padStart(6, "0");
}

export async function signIn(page: Page, email: string): Promise<void> {
  const user = devUser(email);
  await page.goto("/login");
  await page.getByLabel("Email").fill(user.email);
  await page.getByLabel("Password").fill(user.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  if (user.totp_secret) {
    await expect(page).toHaveURL(/\/login\/mfa/);
    // The next time step is also accepted, and avoids replaying a code used moments ago.
    await page.getByLabel("Code").fill(totp(user.totp_secret, 1));
    await page.getByRole("button", { name: "Verify" }).click();
  }
  await expect(page).not.toHaveURL(/\/login/);
}
