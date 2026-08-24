import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { defineConfig, devices } from '@playwright/test';

const adminUiRoot = path.dirname(fileURLToPath(import.meta.url));
const liveServer = path.join(
  adminUiRoot,
  'tests',
  'fixtures',
  'issue-240-live-server.mjs',
);
const fixtureCommand = `"${process.execPath}" "${liveServer}"`;
const viteEnvironment = stringEnvironment({
  ...process.env,
  GREENGATEWAY_BACKEND_URL: 'http://127.0.0.1:43202',
});

export default defineConfig({
  testDir: 'tests',
  testMatch: 'issue-240-live.spec.ts',
  fullyParallel: false,
  workers: 1,
  timeout: 90_000,
  expect: {
    timeout: 10_000,
  },
  use: {
    baseURL: 'http://127.0.0.1:43203',
    trace: 'off',
    viewport: { width: 1440, height: 1000 },
  },
  webServer: [
    {
      name: 'issue-240-real-gateway',
      command: fixtureCommand,
      cwd: adminUiRoot,
      url: 'http://127.0.0.1:43202/readyz',
      reuseExistingServer: false,
      timeout: 300_000,
      stdout: 'pipe',
      stderr: 'pipe',
    },
    {
      name: 'issue-240-admin-ui',
      command:
        'npm run dev -- --host 127.0.0.1 --port 43203 --strictPort',
      cwd: adminUiRoot,
      env: viteEnvironment,
      url: 'http://127.0.0.1:43203/admin/',
      reuseExistingServer: false,
      timeout: 120_000,
      stdout: 'pipe',
      stderr: 'pipe',
    },
  ],
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});

function stringEnvironment(
  source: NodeJS.ProcessEnv,
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(source).filter(
      (entry): entry is [string, string] => entry[1] !== undefined,
    ),
  );
}
