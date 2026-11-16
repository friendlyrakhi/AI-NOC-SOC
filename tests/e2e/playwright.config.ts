import { defineConfig } from "@playwright/test";

/**
 * Browser journeys against the running dev stack (scripts/dev up + scripts/dev seed).
 * Locally this uses the installed Microsoft Edge, so no browser download is needed.
 */
export default defineConfig({
  testDir: "./specs",
  timeout: 30_000,
  fullyParallel: false,
  workers: 1,
  reporter: [["list"]],
  use: {
    baseURL: process.env.NOCSOC_WEB_URL ?? "http://127.0.0.1:3000",
    trace: "retain-on-failure",
    channel: process.env.CI ? undefined : "msedge",
  },
});
