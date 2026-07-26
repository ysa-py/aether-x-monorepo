import { defineConfig, devices } from "@playwright/test";

/**
 * E2E config for the Aether-X NOC dashboard. Headless Chromium + Firefox.
 *
 * The test server is the production Next.js standalone artifact, not `next
 * start`: standalone output is what the dashboard container executes. All
 * backend calls are mocked in the specs (hermetic — no Go control plane
 * required), which keeps the suite fast and flake-free.
 */
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 1,  // absorb residual sandbox load transients
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.CI ? "line" : "list",
  timeout: 45_000,
  expect: { timeout: 10_000 },
  use: {
    baseURL: "http://localhost:3100",
    headless: true,
    trace: "on-first-retry",
  },
  // Keep this list aligned with CI's explicit browser installation. A declared
  // project without its browser binary turns every E2E case into a false fail.
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
  ],
  webServer: {
    command: "npm run build && node scripts/serve-e2e.mjs",
    port: 3100,
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
  },
});
