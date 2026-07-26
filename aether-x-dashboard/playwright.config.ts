import { defineConfig, devices } from "@playwright/test";

/**
 * E2E config for the Aether-X NOC dashboard. Headless Chromium + Firefox.
 * The dev server is auto-started on :3100; all backend calls are mocked in the
 * specs (hermetic — no Go control plane required), which keeps the suite fast
 * and flake-free.
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
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
  ],
  webServer: {
    command: "npx next build && npx next start -p 3100",
    port: 3100,
    reuseExistingServer: true,
    timeout: 180_000,
  },
});
