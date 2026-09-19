import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.toml" },
      miniflare: {
        // The R2 binding is commented out in wrangler.toml so the Worker can
        // be deployed before the bucket exists. Tests bind it here so the
        // attachment paths stay covered; the unbound case is covered
        // separately in test/attachments.test.ts.
        r2Buckets: ["ATTACHMENTS"],
        bindings: {
          // Test-only VAPID key pair (generated with the one-liner in README.md).
          VAPID_PUBLIC_KEY: "BJTWg67IHOcOJxa-RwzlsxXlJBGJMW5scarb2O9YOzd_N_xxTg9ploDkd6FI3OYRt0KKTvhwzrHEoRgY-dlGTsQ",
          VAPID_PRIVATE_KEY: "28TCKBOdPAgjONCTVPKW_pYMsVAg3S8g5ifba0vv5Jw",
          VAPID_SUBJECT: "mailto:test@example.com",
          BOOTSTRAP_INVITE: "bootstrap-test-code",
        },
      },
    }),
  ],
  test: {
    include: ["test/**/*.test.ts"],
    testTimeout: 20000,
    hookTimeout: 20000,
  },
});
