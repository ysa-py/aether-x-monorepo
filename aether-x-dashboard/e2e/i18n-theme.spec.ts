import { expect, test } from "@playwright/test";
import { collectPageErrors, mockAuditRoot, mockCores, mockTelemetryStream } from "./mocks";

test.describe("i18n RTL/LTR switcher", () => {
  test("toggles to Persian RTL and back to English LTR with no errors", async ({ page }) => {
    const errors = collectPageErrors(page);
    await mockCores(page);
    // Mock every endpoint the main page polls so the suite is hermetic on all
    // engines (WebKit surfaces unmocked cross-origin fetches as page errors).
    await mockAuditRoot(page, 7);
    await mockTelemetryStream(page);

    await page.goto("/");

    // Default is English / LTR.
    await expect(page.locator("html")).toHaveAttribute("dir", "ltr");

    const toggle = page.getByRole("button", { name: /toggle language/i });
    await expect(toggle).toBeVisible();

    // Switch to Persian -> RTL.
    await toggle.click();
    await expect(page.locator("html")).toHaveAttribute("dir", "rtl");
    // A Persian label is rendered (title).
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();

    // Switch back to English -> LTR.
    await toggle.click();
    await expect(page.locator("html")).toHaveAttribute("dir", "ltr");

    expect(errors).toEqual([]);
  });
});
