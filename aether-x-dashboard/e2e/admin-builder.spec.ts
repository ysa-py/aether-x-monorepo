import { expect, test } from "@playwright/test";
import { collectPageErrors, mockBuildConfig, mockTransports } from "./mocks";

/**
 * Admin Config Builder — Transport Network E2E suite.
 *
 * Verifies the admin panel (at /admin/builder) renders the RGB builder, loads
 * the transport catalog, and that selecting ANY transport (tcp, kcp, ws, h2,
 * grpc, httpupgrade, xhttp, quic) flows through to a correctly-typed generated
 * config. Hermetic — the Go control plane is fully mocked.
 */

const ALL_TRANSPORTS = ["xhttp", "httpupgrade", "grpc", "h2", "ws", "kcp", "tcp", "quic"];

// The fallback catalog has 4 entries; the live /v1/transports catalog has 8.
// Waiting for >4 options proves the catalog fetch resolved before we assert —
// this kills the engine-dependent race where Chromium/WebKit read the dropdown
// before the async fetch completed.
async function waitForCatalog(page: import("@playwright/test").Page) {
  const select = page.getByTestId("transport-select");
  await expect
    .poll(async () => await select.locator("option").count(), { timeout: 7_000 })
    .toBeGreaterThan(4);
}

test.describe("Admin Config Builder", () => {
  test.beforeEach(async ({ page, context }) => {
    for (const perms of [["clipboard-read", "clipboard-write"], ["clipboard-read"], [] as string[]]) {
      try {
        if (perms.length) await context.grantPermissions(perms, { origin: "http://localhost:3100" });
        break;
      } catch {
        // degrade gracefully across engines
      }
    }
    await mockTransports(page);
    await mockBuildConfig(page);
  });

  test("loads catalog, renders RGB cards, and builds an xhttp config", async ({ page }) => {
    const errors = collectPageErrors(page);
    await page.goto("/admin/builder");

    // Header + RGB cards render.
    await expect(page.getByText("Config Builder")).toBeVisible();
    await expect(page.getByTestId("rgb-card").first()).toBeVisible();

    // Wait for the catalog to load (deterministic across engines).
    const transportSelect = page.getByTestId("transport-select");
    await waitForCatalog(page);

    const options = await transportSelect.locator("option").allTextContents();
    const joined = options.join(" ");
    for (const tr of ALL_TRANSPORTS) {
      expect(joined, `dropdown should list ${tr}`).toContain(tr);
    }

    // xhttp is selected by default → description shows "Newest".
    await expect(page.getByTestId("transport-desc")).toContainText(/Newest|جدیدترین/);

    // Build with the default (xhttp).
    await page.getByTestId("build-btn").click();

    // Result appears with the share link reflecting type=xhttp.
    const output = page.getByTestId("config-output");
    await expect(output).toBeVisible();
    await expect(output).toContainText("type=xhttp");
    await expect(page.getByTestId("transport-badge")).toContainText("xhttp");

    // No runtime errors.
    expect(errors, `uncaught page errors: ${errors.join("\n")}`).toHaveLength(0);
  });

  // Parameterized across every transport — proves the full registry round-trips.
  for (const tr of ALL_TRANSPORTS) {
    test(`builds a valid config for transport: ${tr}`, async ({ page }) => {
      await page.goto("/admin/builder");
      const transportSelect = page.getByTestId("transport-select");
      await waitForCatalog(page);

      await transportSelect.selectOption(tr);
      await page.getByTestId("build-btn").click();

      const output = page.getByTestId("config-output");
      await expect(output).toBeVisible();
      // The reflected share link must carry the selected transport type.
      await expect(output).toContainText(`type=${tr}`);
      await expect(page.getByTestId("transport-badge")).toContainText(tr);

      // Each format tab produces non-empty output.
      for (const tab of ["clash", "singbox", "base64"] as const) {
        await page.getByTestId(`tab-${tab}`).click();
        await expect(output).not.toBeEmpty();
      }
    });
  }

  test("copies the generated share link with a confirmation", async ({ page }) => {
    await page.goto("/admin/builder");
    await waitForCatalog(page);
    await page.getByTestId("build-btn").click();
    await expect(page.getByTestId("config-output")).toContainText("type=xhttp");

    await page.getByTestId("copy-share").click();
    // Button flips to "Copied" confirmation text.
    await expect(page.getByTestId("copy-share")).toContainText(/کپی شد|Copied/);
  });
});
