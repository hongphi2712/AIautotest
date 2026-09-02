import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests/e2e',
  timeout: 30000,
  expect: { timeout: 5000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [
    ['list'],
    ['html', { open: 'never' }],
    ['json', { outputFile: 'output/playwright-report.json' }],
  ],
  use: {
    baseURL: 'http://127.0.0.1:8888',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    ignoreHTTPSErrors: true,
    extraHTTPHeaders: { 'X-Test-Source': 'playwright-direct' },
  },
  // crAPI + AnToanAI already running externally (docker compose + cargo run)
  // No webServer needed
});
