import path from "node:path";
import type { NextConfig } from "next";

const securityHeaders = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
  // The nonce-based Content-Security-Policy is set per request in src/proxy.ts (P7).
];

const nextConfig: NextConfig = {
  output: "standalone",
  // pnpm workspace root, so standalone tracing includes hoisted deps.
  outputFileTracingRoot: path.join(__dirname, ".."),
  poweredByHeader: false,
  // Every page is authenticated and per-user, so pages render dynamically (ADR-0017).
  turbopack: {
    root: path.join(__dirname, ".."),
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default nextConfig;
