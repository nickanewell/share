import path from 'node:path'
import config from '../playwright.config'

process.env.CRYPTGEON_TEST_SERVER = 'http://127.0.0.1:13000'

export default {
  ...config,
  testDir: path.resolve(__dirname, '../test'),
  outputDir: path.resolve(__dirname, '../test-results/staging'),
  use: { ...config.use, baseURL: 'http://127.0.0.1:13000' },
  // Start only the isolated Compose project explicitly, never dev/production.
  webServer: undefined,
}
