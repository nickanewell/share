// This maintained harness is mounted read-only, outside the candidate source.
module.exports = {
  testDir: '/tmp/test',
  testMatch: '**/*.spec.{js,ts}',
  outputDir: '/tmp/gate-results',
  reporter: [['json', { outputFile: '/tmp/gate-results/report.json' }]],
  workers: 2,
  retries: 0,
  timeout: 30_000,
  use: { baseURL: 'http://127.0.0.1:8000', actionTimeout: 30_000 },
  projects: [
    { name: 'chrome', use: { browserName: 'chromium' } },
    { name: 'firefox', use: { browserName: 'firefox' } },
    { name: 'safari', use: { browserName: 'webkit' } },
  ],
}
