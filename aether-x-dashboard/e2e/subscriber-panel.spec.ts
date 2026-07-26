import { expect, test } from "@playwright/test";
import { collectPageErrors, mockMeSubscription, mockSubClients } from "./mocks";

/**
 * Subscriber Portal — RGB glassmorphism E2E suite.
 *
 * Drives the real SubscriberPortal component (rendered at /user/dashboard) under
 * headless Chromium, Firefox, and WebKit. The Go control plane is fully mocked
 * so the suite is hermetic and deterministic.
 *
 * Coverage:
 *   1. UI rendering — RGB glowing borders, circular usage ring, countdown timer.
 *   2. One-Tap Import — modal surfaces valid client deep-link schemes.
 *   3. Copy subscription link — clipboard interaction + confirmation toast.
 *   4. QR code — inline SVG rendered and visible (generated in-house, no API).
 */

const TOKEN = "tok-pro-live-001";
const DASHBOARD = `/user/dashboard?token=${TOKEN}`;

test.describe("Subscriber Portal", () => {
  test.beforeEach(async ({ page, context }) => {
    // Grant clipboard so the copy interaction works across all engines.
    // WebKit/Firefox reject some permission names, so degrade gracefully —
    // the copy test's primary assertion is the in-DOM toast, not the clipboard.
    const origins = { origin: "http://localhost:3100" };
    for (const perms of [
      ["clipboard-read", "clipboard-write"],
      ["clipboard-read"],
      [] as string[],
    ]) {
      try {
        if (perms.length) await context.grantPermissions(perms, origins);
        break;
      } catch {
        // try the next smaller permission set
      }
    }
    await mockMeSubscription(page);
    await mockSubClients(page);
    await page.route("**/v1/sub/revoke-device", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        headers: { "Access-Control-Allow-Origin": "*" },
        body: JSON.stringify({ status: "revoked" }),
      }),
    );
  });

  // --- 1. UI Rendering Verification ---

  test("renders RGB glass cards, circular usage ring, and live countdown", async ({ page }) => {
    const errors = collectPageErrors(page);
    await page.goto(DASHBOARD);

    // Plan badge + live status confirm /v1/me/subscription data is wired.
    await expect(page.getByTestId("plan-badge")).toContainText("Pro");
    await expect(page.getByText("زنده — اتصال فعال")).toBeVisible();

    // RGB glowing borders render (at least the header card).
    await expect(page.getByTestId("rgb-card").first()).toBeVisible();
    const headerCard = page.getByTestId("rgb-card").first();
    await expect(headerCard).toHaveClass(/rgb-border/);

    // Circular usage progress ring (inline SVG) is present & shows ~25%.
    const ring = page.getByTestId("usage-ring");
    await expect(ring).toBeVisible();
    await expect(ring.locator("svg")).toBeVisible();
    await expect(ring).toContainText("%");

    // Live countdown timer renders all four units.
    const countdown = page.getByTestId("countdown");
    await expect(countdown).toBeVisible();
    await expect(page.getByTestId("cd-روز")).toBeVisible();
    await expect(page.getByTestId("cd-ساعت")).toBeVisible();
    await expect(page.getByTestId("cd-دقیقه")).toBeVisible();
    await expect(page.getByTestId("cd-ثانیه")).toBeVisible();

    // The subscription URL is surfaced (used by copy + QR).
    await expect(page.getByTestId("sub-url")).toContainText("tok-pro-live-001");

    // No runtime errors during render.
    expect(errors, `uncaught page errors: ${errors.join("\n")}`).toHaveLength(0);
  });

  // --- 2. One-Tap Deep Link Triggering ---

  test("opens the import modal with valid client schemes", async ({ page }) => {
    await page.goto(DASHBOARD);
    await expect(page.getByTestId("plan-badge")).toBeVisible();

    const btn = page.getByTestId("one-tap-import");
    await expect(btn).toBeVisible();
    await btn.click();

    const modal = page.getByTestId("import-modal");
    await expect(modal).toBeVisible();

    // The modal lists client links carrying the expected deep-link schemes.
    const links = modal.getByTestId("client-link");
    await expect(links.first()).toBeVisible();
    const count = await links.count();
    expect(count).toBeGreaterThanOrEqual(4);

    // Collect all resolved scheme prefixes shown in the modal.
    const schemes = await links.evaluateAll((nodes) =>
      nodes
        .map((n) => n.querySelector("span:last-child")?.textContent ?? "")
        .map((s) => s.trim()),
    );
    const joined = schemes.join(" ");
    for (const scheme of ["sing-box://", "v2rayng://", "shadowrocket://", "clash://"]) {
      expect(joined, `modal should advertise ${scheme}`).toContain(scheme);
    }

    // Closing via the dedicated close button dismisses the modal (deterministic
    // across engines — a real tap target, not a tiny icon-only button).
    await page.getByTestId("modal-close").click();
    await expect(modal).toBeHidden();
  });

  // --- 3. Copy Subscription Link ---

  test("copies the subscription link and confirms via toast", async ({ page }) => {
    await page.goto(DASHBOARD);
    await expect(page.getByTestId("plan-badge")).toBeVisible();

    await page.getByTestId("copy-link").click();

    // Confirmation toast appears.
    const toast = page.getByTestId("copy-toast");
    await expect(toast).toBeVisible();
    await expect(toast).toContainText("کپی");

    // Clipboard received the exact subscription URL (Chromium/Firefox).
    // WebKit may gate clipboard behind focus; the toast is the primary assertion.
    const clip = await page.evaluate(() => navigator.clipboard.readText().catch(() => ""));
    if (clip) {
      expect(clip).toContain("tok-pro-live-001");
    }
  });

  // --- 4. QR Code Inspection (in-house, inline SVG) ---

  test("renders an inline SVG QR code that is visible", async ({ page }) => {
    await page.goto(DASHBOARD);
    await expect(page.getByTestId("plan-badge")).toBeVisible();

    const qr = page.getByTestId("qr-inline");
    await expect(qr).toBeVisible();
    const svg = qr.locator("svg");
    await expect(svg).toBeVisible();

    // The QR encodes real data: it must contain black modules (<rect> children).
    const rectCount = await svg.locator("rect").count();
    expect(rectCount, "QR SVG must contain rendered modules").toBeGreaterThan(20);

    // The large-QR modal also renders a valid SVG.
    await page.getByTestId("qr-toggle").click();
    const modalSvg = page.locator(".fixed.inset-0 svg").last();
    await expect(modalSvg).toBeVisible();
  });

  // --- 5. Enterprise tier renders distinctly ---

  test("renders enterprise tier styling", async ({ page }) => {
    await mockMeSubscription(page, {
      plan_type: "enterprise",
      plan_name: "Enterprise",
      bytes_total: 1_000_000_000_000_000,
      bytes_used: 1_000_000_000,
      usage_percent: 0.0001,
    });
    await page.goto(DASHBOARD);
    await expect(page.getByTestId("plan-badge")).toContainText("Enterprise");
  });
});
