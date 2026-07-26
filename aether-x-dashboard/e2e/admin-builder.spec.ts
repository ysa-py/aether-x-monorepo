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

// The fallback catalog has 5 transports; the live /v1/transports catalog has 8.
// Waiting for >5 options proves the catalog fetch resolved before we assert —
// this kills the engine-dependent race where Chromium/Firefox read the dropdown
// before the async fetch completed.
async function waitForCatalog(page: import("@playwright/test").Page) {
  const select = page.getByTestId("transport-select");
  await expect
    .poll(async () => await select.locator("option").count(), { timeout: 7_000 })
    .toBeGreaterThan(5);
}

async function fillReviewedEndpoint(page: import("@playwright/test").Page) {
  await page.getByTestId("address-input").fill("198.51.100.42");
  const uuid = page.getByTestId("uuid-input");
  if (await uuid.count()) await uuid.fill("0d1f2e3a-4b5c-6d7e-8f90-12345678abcd");
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

  test("requires reviewed endpoint material instead of a fictional default", async ({ page }) => {
    await page.goto("/admin/builder");
    await waitForCatalog(page);
    await expect(page.getByTestId("build-btn")).toBeDisabled();

    await fillReviewedEndpoint(page);
    await expect(page.getByTestId("build-btn")).toBeEnabled();
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

    // Build with an explicit reviewed test endpoint, never a UI placeholder.
    await fillReviewedEndpoint(page);
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
      await fillReviewedEndpoint(page);
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
    await fillReviewedEndpoint(page);
    await page.getByTestId("build-btn").click();
    await expect(page.getByTestId("config-output")).toContainText("type=xhttp");

    await page.getByTestId("copy-share").click();
    // Button flips to "Copied" confirmation text.
    await expect(page.getByTestId("copy-share")).toContainText(/کپی شد|Copied/);
  });

  test("builds native Hysteria2 and TUIC profiles without a custom client", async ({ page }) => {
  await page.goto("/admin/builder");
  await waitForCatalog(page);

  const protocolSelect = page.getByTestId("protocol-select");
  const transportSelect = page.getByTestId("transport-select");

  await protocolSelect.selectOption("hysteria2");
  await expect(transportSelect).toHaveValue("quic");
  await fillReviewedEndpoint(page);
  await page.getByTestId("password-input").fill("hy2-test-password");
  await page.getByTestId("build-btn").click();
  await expect(page.getByTestId("config-output")).toContainText("hysteria2://");

  await protocolSelect.selectOption("tuic");
  await expect(transportSelect).toHaveValue("quic");
  await page.getByTestId("uuid-input").fill("tuic-test-uuid");
  await page.getByTestId("password-input").fill("tuic-test-password");
  await page.getByTestId("build-btn").click();
  await expect(page.getByTestId("config-output")).toContainText("tuic://");
  });
});
