import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  use: {
    baseURL: 'http://localhost:3000'
  },
  webServer: {
    command: 'bun build/index.js',
    url: 'http://localhost:3000',
    reuseExistingServer: false,
    timeout: 120_000
  }
});
