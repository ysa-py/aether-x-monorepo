import { expect, test } from "@playwright/test";
import { collectPageErrors, mockClientDraftWorkflow } from "./mocks";

/**
 * Admin Client-Registry AI Draft — Part 2 §6 E2E suite.
 *
 * Verifies the human-gated workflow: paste a docs URL → AI drafts a pending
 * entry → it is NOT served until the admin confirms. Hermetic across engines.
 */
test.describe("Admin Client Draft", () => {
  test.beforeEach(async ({ page }) => {
    mockClientDraftWorkflow(page);
  });

  test("drafts a client from a URL and gates it behind confirm", async ({ page }) => {
    const errors = collectPageErrors(page);
    await page.goto("/admin/clients");

    await expect(page.getByText("Client Registry · AI Draft")).toBeVisible();

    // Draft from a docs URL. Use click + keyboard.type (not fill) so React's
    // controlled-input state settles before the click — the proven WebKit
    // synchronization fix that avoids the load-induced race.
    const urlInput = page.getByTestId("docs-url-input");
    await urlInput.click();
    await page.keyboard.type("https://github.com/acme/NovaVPN");
    const draftBtn = page.getByTestId("draft-btn");
    await expect(draftBtn).toBeEnabled();
    await draftBtn.click();

    // Confirmation flash + the pending draft row appears.
    await expect(page.getByTestId("draft-flash")).toContainText(/NovaVPN.*review|drafted/i);
    await expect(page.getByTestId("draft-row-NovaVPN")).toBeVisible();
    await expect(page.getByTestId("draft-row-NovaVPN")).toContainText("ai-drafted-pending-review");

    // Confirm the draft → status flips to "confirmed" and the confirm button disappears.
    await page.getByTestId("confirm-btn-NovaVPN").click();
    await expect(page.getByTestId("draft-row-NovaVPN")).toContainText("confirmed");
    await expect(page.getByTestId("confirm-btn-NovaVPN")).toHaveCount(0);

    expect(errors, `uncaught page errors: ${errors.join("\n")}`).toHaveLength(0);
  });

  test("renders the empty state before any draft is made", async ({ page }) => {
    await page.goto("/admin/clients");
    await expect(page.getByTestId("empty-drafts")).toBeVisible();
  });

  test("rejects an empty draft (button disabled)", async ({ page }) => {
    await page.goto("/admin/clients");
    await expect(page.getByTestId("draft-btn")).toBeDisabled();
  });
});
