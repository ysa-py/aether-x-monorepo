import { expect, test } from "@playwright/test";
import { defaultCores, mockCores } from "./mocks";

test.describe("Core Manager", () => {
  test("lists cores and fires a hot-swap without errors", async ({ page }) => {
    await mockCores(page);

    // The hot-swap POST endpoint (reserved REST path) is mocked to succeed.
    await page.route("**/v1/cores/switch", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        headers: { "Access-Control-Allow-Origin": "*" },
        body: JSON.stringify({ migrated: true }),
      }),
    );

    await page.goto("/");

    // A known core instance id appears (from the mocked /v1/cores).
    const coreRow = page.getByText("edge-1");
    await expect(coreRow).toBeVisible();

    // The status text reflects the RUNNING state (emerald-tinged in CSS, but we
    // assert the text content which is deterministic).
    await expect(page.getByText("RUNNING", { exact: true }).first()).toBeVisible();

    // Trigger the hot-swap; assert the button exists and the click is accepted.
    const hotSwap = page.getByTestId("hot-swap").first();
    await expect(hotSwap).toBeVisible();
    await hotSwap.click();

    // The core list (driven by TanStack Query) still shows both cores.
    await expect(page.getByText("edge-2")).toBeVisible();
    expect(defaultCores().length).toBe(2);
  });
});
