#!/usr/bin/env node
/**
 * Serve the production Next.js standalone artifact for Playwright.
 *
 * `next start` is intentionally incompatible with `output: "standalone"`.
 * This launcher exercises the same server artifact used by the container image,
 * and stages the static and public assets Next intentionally leaves outside the
 * traced standalone directory.
 */

import { spawn } from "node:child_process";
import { cp, stat } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const dashboardDirectory = resolve(scriptDirectory, "..");
const nextDirectory = join(dashboardDirectory, ".next");
const standaloneDirectory = join(nextDirectory, "standalone");
const serverPath = join(standaloneDirectory, "server.js");

async function requireDirectory(path, description) {
  try {
    const details = await stat(path);
    if (!details.isDirectory()) {
      throw new Error(`${description} is not a directory: ${path}`);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`${description} is missing. Run \"npm run build\" first. (${message})`);
  }
}

async function stageAssets() {
  await requireDirectory(standaloneDirectory, "Next.js standalone output");
  await requireDirectory(join(nextDirectory, "static"), "Next.js static output");

  await cp(join(nextDirectory, "static"), join(standaloneDirectory, ".next", "static"), {
    recursive: true,
    force: true,
  });

  // `public/` is optional in Next.js projects. Copy it when present so the
  // production artifact and the browser test server have the same asset set.
  try {
    const publicDirectory = join(dashboardDirectory, "public");
    const details = await stat(publicDirectory);
    if (details.isDirectory()) {
      await cp(publicDirectory, join(standaloneDirectory, "public"), {
        recursive: true,
        force: true,
      });
    }
  } catch (error) {
    if (!(error instanceof Error) || !("code" in error) || error.code !== "ENOENT") {
      throw error;
    }
  }
}

await stageAssets();

const child = spawn(process.execPath, [serverPath], {
  cwd: standaloneDirectory,
  env: {
    ...process.env,
    HOSTNAME: process.env.HOSTNAME || "127.0.0.1",
    PORT: process.env.PORT || "3100",
  },
  stdio: "inherit",
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => child.kill(signal));
}

child.on("error", (error) => {
  console.error(`Unable to start the standalone dashboard server: ${error.message}`);
  process.exitCode = 1;
});

child.on("exit", (code, signal) => {
  if (signal) {
    process.exitCode = 1;
    return;
  }
  process.exitCode = code ?? 1;
});
