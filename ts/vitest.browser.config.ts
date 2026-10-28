// Headless Chrome run of the browser entry (npm run test:browser).
import { playwright } from "@vitest/browser-playwright";
import { defineConfig } from "vitest/config";

export default defineConfig({
  // The conformance vectors live beside ts/, in the repository root.
  server: { fs: { allow: [".."] } },
  test: {
    include: ["test/browser/**/*.browser-test.ts"],
    browser: {
      enabled: true,
      headless: true,
      provider: playwright(),
      instances: [{ browser: "chromium" }],
    },
  },
});
