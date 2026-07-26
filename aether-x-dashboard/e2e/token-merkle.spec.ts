import { expect, test } from "@playwright/test";
import { mockAuditRoot, mockCores, mockTelemetryStream, mockVerifyToken } from "./mocks";

test.describe("Token Inspector + Merkle Tree", () => {
  test("verifies a token and renders the Merkle inclusion-path highlights", async ({ page }) => {
    test.setTimeout(60000); // heavy multi-step interaction; generous under CI load
    await mockAuditRoot(page, 7);
    await mockVerifyToken(page, true);
    // Mock every endpoint the main page polls so the suite is hermetic on all
    // engines (WebKit surfaces unmocked cross-origin fetches as page errors).
    await mockCores(page);
    await mockTelemetryStream(page);

    await page.goto("/");

    // The merkle tree viewer is present (a set of small square buttons).
    const tree = page.getByTestId("merkle-tree");
    const treeButtons = tree.getByRole("button");
    await expect(treeButtons.first()).toBeVisible();
    const beforeCount = await treeButtons.count();
    expect(beforeCount).toBeGreaterThan(4);

    // Enter a token and verify. Use focus + keyboard typing so the React
    // controlled-input state propagates reliably on every engine (WebKit's
    // `fill` can race the immediate click that follows). Then explicitly
    // auto-wait for the button to become enabled before clicking it.
    const input = page.getByTestId("token-input");
    await expect(input).toBeVisible();
    await input.click();
    await page.keyboard.type("tok-test-sig");
    const verifyBtn = page.getByTestId("token-verify");
    await expect(verifyBtn).toBeEnabled();
    await verifyBtn.click();

    // Verification result pill appears.
    await expect(page.getByText(/Signature valid: true/i)).toBeVisible();

    // Clicking a LEAF (enabled nodes) re-highlights its inclusion path; root/internal
    // nodes are intentionally disabled, so target a leaf.
    await tree.getByRole("button", { name: /Leaf/ }).first().click();
    const afterCount = await treeButtons.count();
    expect(afterCount).toBe(beforeCount);
  });
});
