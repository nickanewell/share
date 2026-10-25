const { test, expect } = require('@playwright/test')
const assert = require('node:assert/strict')
const { randomBytes, webcrypto } = require('node:crypto')
const { readFile } = require('node:fs/promises')
const cli = require('../../../packages/cli/dist/index.cjs')
let server
// A generated one-page PDF keeps these checks independent of Git LFS fixtures.
const bytes = Buffer.from('JVBERi0xLjQKJeLjz9MKMSAwIG9iago8PCAvVHlwZSAvQ2F0YWxvZyAvUGFnZXMgMiAwIFIgPj4KZW5kb2JqCjIgMCBvYmoKPDwgL1R5cGUgL1BhZ2VzIC9LaWRzIFszIDAgUl0gL0NvdW50IDEgPj4KZW5kb2JqCjMgMCBvYmoKPDwgL1R5cGUgL1BhZ2UgL1BhcmVudCAyIDAgUiAvTWVkaWFCb3ggWzAgMCAzMDAgMTUwXSAvUmVzb3VyY2VzIDw8IC9Gb250IDw8IC9GMSA0IDAgUiA+PiA+PiAvQ29udGVudHMgNSAwIFIgPj4KZW5kb2JqCjQgMCBvYmoKPDwgL1R5cGUgL0ZvbnQgL1N1YnR5cGUgL1R5cGUxIC9CYXNlRm9udCAvSGVsdmV0aWNhID4+CmVuZG9iago1IDAgb2JqCjw8IC9MZW5ndGggNjAgPj4Kc3RyZWFtCkJUIC9GMSAxNCBUZiAyMCA4MCBUZCAoTG9jYWwgaW50ZWdyYXRpb24gUERGIGZpeHR1cmUpIFRqIEVUCmVuZHN0cmVhbQplbmRvYmoKeHJlZgowIDYKMDAwMDAwMDAwMCA2NTUzNSBmIAowMDAwMDAwMDE1IDAwMDAwIG4gCjAwMDAwMDAwNjQgMDAwMDAgbiAKMDAwMDAwMDEyMSAwMDAwMCBuIAowMDAwMDAwMjQ3IDAwMDAwIG4gCjAwMDAwMDAzMTcgMDAwMDAgbiAKdHJhaWxlcgo8PCAvU2l6ZSA2IC9Sb290IDEgMCBSID4+CnN0YXJ0eHJlZgo0MjYKJSVFT0YK', 'base64')

function localURL(input) {
  const url = new URL(typeof input === 'string' ? input : input.url ?? input)
  assert.equal(url.origin, server, 'All integration requests must stay local')
  return url
}

test.beforeEach(async ({ context, baseURL }) => {
  assert(baseURL, 'Security integration tests require a local baseURL')
  const target = new URL(baseURL)
  assert(['http:', 'https:'].includes(target.protocol), 'HTTP or HTTPS baseURL required')
  assert(['localhost', '127.0.0.1', '[::1]'].includes(target.hostname),
    'Security integration tests must never target a remote service')
  assert(!target.username && !target.password, 'Credentials are not accepted in the test baseURL')
  server = target.origin
  await context.route('**/*', route => {
    const url = new URL(route.request().url())
    if (url.origin === server || url.protocol === 'data:') return route.continue()
    return route.abort('blockedbyclient')
  })
})

async function aesSeal(data, key) {
  const iv = randomBytes(12)
  const imported = await webcrypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt'])
  const encrypted = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, imported, data)
  return ['QUVTLUdDTQ==', iv.toString('base64'), Buffer.from(encrypted).toString('base64')].join('--')
}

async function v2Seal(name, key) {
  const encoder = new TextEncoder()
  const imported = await webcrypto.subtle.importKey('raw', key, 'HKDF', false, ['deriveBits'])
  const derived = await webcrypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256',
    salt: encoder.encode('cryptgeon-files'), info: encoder.encode('cryptgeon-files/v2') }, imported, 256)
  const manifest = Buffer.from(JSON.stringify({ format: 'cryptgeon-files', version: 2,
    files: [{ name, type: 'application/pdf', size: bytes.length }] }))
  const length = Buffer.alloc(4)
  length.writeUInt32BE(manifest.length)
  const ciphertext = await aesSeal(Buffer.concat([length, manifest, bytes]), derived)
  return JSON.stringify({ format: 'cryptgeon-files', version: 2, ciphertext })
}

async function createNote(contents, type, key) {
  const endpoint = `${server}/api/notes/`
  localURL(endpoint)
  const response = await fetch(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ contents, meta: JSON.stringify({ type }), views: 1 }) })
  assert.equal(response.status, 200)
  const { id } = await response.json()
  return `${server}/note/${id}#${Buffer.from(key).toString('hex')}`
}

async function show(page, link) {
  localURL(link)
  await page.goto(link)
  await page.getByTestId('show-note-button').click()
}

async function downloadBytes(page, name) {
  const [download] = await Promise.all([page.waitForEvent('download'),
    page.getByTestId('result').getByRole('button', { name: `↓ ${name}` }).click()])
  expect(download.suggestedFilename()).toBe(name)
  const path = await download.path()
  expect(path).toBeTruthy()
  expect(await readFile(path)).toEqual(bytes)
}

test('backend advertises authenticated file format v2', async () => {
  const endpoint = `${server}/api/status/`
  localURL(endpoint)
  const response = await fetch(endpoint)
  expect(response.status).toBe(200)
  const status = await response.json()
  expect(status.file_format_version).toBe(2)
})

test('legacy file remains byte-exact and shows metadata warning', async ({ page }) => {
  const key = randomBytes(32)
  const name = 'legacy-integration.pdf'
  const contents = JSON.stringify([{ name, size: 999999, type: 'application/pdf', contents: await aesSeal(bytes, key) }])
  await show(page, await createNote(contents, 'file', key))
  await expect(page.getByTestId('legacy-file-warning')).toContainText('does not verify file names or types')
  await downloadBytes(page, name)
})

test('independent authenticated v2 file downloads without legacy warning', async ({ page }) => {
  const key = randomBytes(32)
  const name = 'authenticated-integration.pdf'
  const contents = await v2Seal(name, key)
  expect(contents).not.toContain(name)
  expect(contents).not.toContain('application/pdf')
  await show(page, await createNote(contents, 'file', key))
  await expect(page.getByTestId('result')).toBeVisible()
  await expect(page.getByTestId('legacy-file-warning')).toHaveCount(0)
  await downloadBytes(page, name)
})

test('older or ambiguous readers cannot consume a new one-view file', async ({ page }) => {
  const key = randomBytes(32)
  const name = 'preserved-for-updated-reader.pdf'
  const original = await v2Seal(name, key)
  // JSON.parse uses last-value semantics; the Rust gate must not let an
  // otherwise valid new envelope bypass preservation through duplicate fields.
  const variants = [original, original.replace('"format":', '"format":"ignored","format":'),
    original.replace('"version":', '"version":1,"version":')]
  for (const contents of variants) {
    const link = await createNote(contents, 'file', key)
    const endpoint = `${server}/api/notes/${new URL(link).pathname.split('/')[2]}`
    localURL(endpoint)
    for (const value of [undefined, '1', '3', '2, 2', 'invalid']) {
      const headers = value === undefined ? {} : { 'X-Cryptgeon-File-Format': value }
      expect((await fetch(endpoint, { method: 'DELETE', headers })).status).toBe(426)
      expect((await fetch(endpoint)).status).toBe(200)
    }
    await show(page, link)
    await downloadBytes(page, name)
    expect((await fetch(endpoint)).status).toBe(404)
  }
})

test('tampered authenticated v2 file is rejected without exposing a download', async ({ page }) => {
  const key = randomBytes(32)
  const envelope = JSON.parse(await v2Seal('tampered.pdf', key))
  const parts = envelope.ciphertext.split('--')
  const encrypted = Buffer.from(parts[2], 'base64')
  encrypted[0] ^= 1
  parts[2] = encrypted.toString('base64')
  envelope.ciphertext = parts.join('--')
  const link = await createNote(JSON.stringify(envelope), 'file', key)
  await show(page, link)
  await expect(page.locator('main')).toContainText('could not decipher')
  await expect(page.getByTestId('result')).toHaveCount(0)
  const endpoint = `${server}/api/notes/${new URL(link).pathname.split('/')[2]}`
  localURL(endpoint)
  expect((await fetch(endpoint)).status).toBe(404)
})

test('independent old text ciphertext remains readable unchanged', async ({ page }) => {
  const key = randomBytes(32)
  const text = 'Legacy text unchanged: 日本語, spaces, and 0123456789.'
  await show(page, await createNote(await aesSeal(Buffer.from(text), key), 'text', key))
  await expect(page.getByTestId('result').locator('.note')).toHaveText(text)
  await expect(page.getByTestId('legacy-file-warning')).toHaveCount(0)
})

test('browser file upload refuses missing server capability before posting a note', async ({ page }) => {
  let posts = 0
  page.on('request', request => {
    localURL(request.url())
    if (request.method() === 'POST' && new URL(request.url()).pathname.startsWith('/api/notes')) posts++
  })
  await page.route(/\/api\/status\/?$/, async route => {
    localURL(route.request().url())
    // Keep JSON rewriting independent of the browser's advertised compression.
    const response = await route.fetch({ headers: { ...route.request().headers(), 'accept-encoding': 'identity' } })
    const status = await response.json()
    delete status.file_format_version
    await route.fulfill({ json: status })
  })
  await page.goto('/')
  await page.getByTestId('switch-file').click()
  await page.getByTestId('file-upload').setInputFiles({ name: 'integration.pdf', mimeType: 'application/pdf', buffer: bytes })
  await expect(page.locator('.pasted-files-preview .file-name')).toHaveText('integration.pdf')
  await page.locator('button:has-text("create")').click()
  await expect(page.locator('._toastContainer')).toContainText('needs an update before it can share files securely')
  await expect(page.getByTestId('share-link')).toHaveCount(0)
  expect(posts).toBe(0)
})

test('CLI file upload refuses missing server capability before posting a note', async () => {
  const originalFetch = globalThis.fetch
  let posts = 0
  cli.API.setOptions({ server })
  globalThis.fetch = async (input, init) => {
    const url = localURL(input)
    if (init?.method?.toLowerCase() === 'post') posts++
    const response = await originalFetch(input, init)
    if (/\/api\/status\/?$/.test(url.pathname)) {
      const status = await response.json()
      delete status.file_format_version
      return new Response(JSON.stringify(status), { status: 200, headers: { 'Content-Type': 'application/json' } })
    }
    return response
  }
  try {
    await assert.rejects(cli.upload(['.security-test-must-not-read-before-capability-check.pdf'], { views: 1 }), /Update this server/)
    expect(posts).toBe(0)
  } finally { globalThis.fetch = originalFetch }
})

test('oversized authenticated file is rejected without creating a share', async ({ page, request }) => {
  test.setTimeout(60_000)
  await page.goto('/')
  await page.getByTestId('switch-file').click()
  await page.getByTestId('file-upload').setInputFiles({ name: 'oversized-local-only.bin',
    mimeType: 'application/octet-stream', buffer: Buffer.alloc(9 * 1024 * 1024, 165) })
  await expect(page.locator('.pasted-files-preview .file-name')).toHaveText('oversized-local-only.bin')
  await page.evaluate(() => {
    const originalFetch = window.fetch
    window.fetch = function (input, init) {
      if (typeof input === 'string' && input.endsWith('/api/notes/')
        && init?.method?.toUpperCase() === 'POST' && typeof init.body === 'string') {
        window.__cryptgeonTestUploadBody = init.body
      }
      return originalFetch.call(this, input, init)
    }
  })
  const posted = page.waitForRequest(upload => new URL(upload.url()).origin === server
    && new URL(upload.url()).pathname.startsWith('/api/notes') && upload.method() === 'POST')
  await page.locator('button:has-text("create")').click()
  const upload = await posted
  const endpoint = localURL(upload.url()).href
  const body = await page.evaluate(() => window.__cryptgeonTestUploadBody)
  expect(typeof body).toBe('string')
  expect(body.length).toBeGreaterThan(0)
  const observedBody = upload.postData()
  if (observedBody !== null) expect(observedBody === body).toBe(true)
  // WebKit can lose an early 413 to a broken-pipe upload error. Replay the exact
  // browser ciphertext to verify the server limit independently of that transport.
  const response = await request.post(endpoint, {
    data: body,
    headers: { 'Content-Type': upload.headers()['content-type'] ?? 'application/json' },
    timeout: 20_000,
  })
  expect(response.status()).toBe(413)
  await expect(page.locator('._toastContainer')).toContainText('could not create note')
  await expect(page.getByTestId('share-link')).toHaveCount(0)
})
