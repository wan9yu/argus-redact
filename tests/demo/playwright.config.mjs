import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  timeout: 30000,
  use: { baseURL: 'http://127.0.0.1:8848', headless: true },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'python3 -m http.server 8848 --bind 127.0.0.1 --directory ../../demo',
    url: 'http://127.0.0.1:8848/index.html',
    reuseExistingServer: !process.env.CI,
    timeout: 30000,
  },
});
