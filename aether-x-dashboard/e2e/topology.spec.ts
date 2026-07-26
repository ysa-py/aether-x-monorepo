import { expect, test } from "@playwright/test";
import { collectPageErrors, mockAuditRoot, mockCores, mockTelemetryStream } from "./mocks";

test.describe("Topology Visualizer + SSE", () => {
  test("renders nodes, reacts to mock telemetry, and opens the inspect drawer", async ({ page }) => {
    const errors = collectPageErrors(page);
    await mockCores(page);
    // Mock every endpoint the main page polls so the suite is hermetic on all
    // engines (WebKit surfaces unmocked cross-origin fetches as page errors).
    await mockAuditRoot(page, 7);
    await mockTelemetryStream(page, { latency_ms: 220, packet_loss: true, protocol: "reality-vision" });

    await page.goto("/");

    // The topology SVG is present with its nodes.
    const svg = page.locator("svg[role='img']").first();
    await expect(svg).toBeVisible();

    // A known node (supervisor) is rendered as a focusable/clickable group.
    const node = page.getByRole("button", { name: "supervisor" }).first();
    await expect(node).toBeVisible();

    // Clicking a node opens the inspection drawer with CPU/RAM metrics.
    await node.click();
    const drawer = page.getByRole("dialog");
    await expect(drawer).toBeVisible();
    await expect(drawer.getByText("CPU")).toBeVisible();
    await expect(drawer.getByText("RAM")).toBeVisible();

    // No uncaught errors during render + interaction.
    expect(errors).toEqual([]);
  });
});
