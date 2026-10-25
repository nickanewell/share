import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomBytes, webcrypto } from 'node:crypto'
import fs from 'node:fs'
import { createRequire } from 'node:module'
import os from 'node:os'
import path from 'node:path'
import test, { after } from 'node:test'
import { fileURLToPath } from 'node:url'

const require = createRequire(import.meta.url)
const cliRequire = createRequire(new URL('../../packages/cli/package.json', import.meta.url))
const { buildSync } = createRequire(cliRequire.resolve('tsup'))('esbuild')
const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'cryptgeon-files-security-'))
const bundle = path.join(directory, 'adapters.cjs')
const source = fileURLToPath(new URL('../../packages/cli/src/shared/adapters.ts', import.meta.url))
buildSync({ entryPoints: [source], outfile: bundle, bundle: true, platform: 'node', format: 'cjs', logLevel: 'silent' })
const { Adapters } = require(bundle)
after(() => fs.rmSync(directory, { recursive: true, force: true }))

const FORMAT = 'cryptgeon-files'
const encoder = new TextEncoder()
const key = randomBytes(32)
const file = (name = 'private 日本語.txt', contents = Buffer.from('private file bytes'), type = 'text/plain') => ({
  name, contents, type, size: contents.byteLength,
})
const assertFiles = (actual, expected) => {
  assert.equal(actual.length, expected.length)
  actual.forEach((entry, index) => {
    assert.equal(entry.name, expected[index].name)
    assert.equal(entry.type, expected[index].type)
    const view = expected[index].contents
    const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength)
    assert.deepEqual(Buffer.from(entry.contents), Buffer.from(bytes))
    assert.equal(entry.size, bytes.byteLength)
  })
}

// Independent WebCrypto fixtures reproduce the old wire format and adversarial
// authenticated frames instead of using the new encoder to generate its tests.
async function encryptRaw(bytes, rawKey) {
  const iv = randomBytes(12)
  const imported = await webcrypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt'])
  const encrypted = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, imported, bytes)
  return ['QUVTLUdDTQ==', iv.toString('base64'), Buffer.from(encrypted).toString('base64')].join('--')
}

async function fileKey(rawKey) {
  const imported = await webcrypto.subtle.importKey('raw', rawKey, 'HKDF', false, ['deriveBits'])
  return new Uint8Array(await webcrypto.subtle.deriveBits({
    name: 'HKDF', hash: 'SHA-256', salt: encoder.encode(FORMAT), info: encoder.encode(FORMAT + '/v2'),
  }, imported, 256))
}

function frame(manifest, contents = Buffer.alloc(0)) {
  const json = Buffer.from(JSON.stringify(manifest))
  const header = Buffer.alloc(4)
  header.writeUInt32BE(json.byteLength)
  return Buffer.concat([header, json, contents])
}

async function seal(bytes, rawKey = key) {
  return JSON.stringify({ format: FORMAT, version: 2, ciphertext: await encryptRaw(bytes, await fileKey(rawKey)) })
}

async function legacy(files, rawKey = key) {
  return JSON.stringify(await Promise.all(files.map(async ({ name, size, type, contents }) => ({
    name, size, type, contents: await encryptRaw(contents, rawKey),
  }))))
}

test('authenticated files preserve Unicode, multiple/empty/binary files and exact byte views', async () => {
  const storage = new Uint16Array([0x1234, 0x5678, 0xabcd, 0xef01])
  const files = [file(), file('empty', new Uint8Array(), ''),
    file('duplicate.bin', new Uint8Array([0, 255, 1, 128]), 'application/octet-stream'),
    file('duplicate.bin', storage.subarray(1, 3), 'application/octet-stream')]
  // Declared sizes are not trusted; the encrypted manifest uses actual bytes.
  files[0].size = 999999
  const ciphertext = await Adapters.Files.encrypt(files, key)
  const decoded = await Adapters.Files.decryptWithInfo(ciphertext, key)
  assert.equal(decoded.metadataAuthenticated, true)
  assertFiles(decoded.files, files)
  assertFiles(await Adapters.Files.decrypt(ciphertext, key), files)
  const decrypt = Adapters.Files.decrypt
  assertFiles(await decrypt(ciphertext, key), files)
})

test('password-derived keys and repeated randomized file cases round trip', async () => {
  const material = await webcrypto.subtle.importKey('raw', encoder.encode('test password'), 'PBKDF2', false, ['deriveBits'])
  const passwordKey = new Uint8Array(await webcrypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-512',
    salt: Buffer.from('independent fixture salt'), iterations: 100000 }, material, 256))
  for (let round = 0; round < 20; round++) {
    const files = [file('round-' + round, randomBytes(round * 97), ''), file('second', randomBytes(31 + round))]
    const encrypted = await Adapters.Files.encrypt(files, passwordKey)
    assertFiles((await Adapters.Files.decryptWithInfo(encrypted, passwordKey)).files, files)
  }
})

test('one MiB binary keeps single-base64 overhead and leaks no filename or MIME', async () => {
  const files = [file('SECRET-custom-client-name.dat', randomBytes(1024 * 1024), 'application/x-private-client')]
  const encrypted = await Adapters.Files.encrypt(files, key)
  assert.equal(encrypted.includes(files[0].name), false)
  assert.equal(encrypted.includes(files[0].type), false)
  assert.ok(Buffer.byteLength(encrypted) < files[0].size * 1.35)
  assertFiles(await Adapters.Files.decrypt(encrypted, key), files)
})

test('repeated encryptions use fresh IVs and do not reuse ciphertext', async () => {
  const results = new Set()
  for (let round = 0; round < 10; round++) results.add(await Adapters.Files.encrypt([file()], key))
  assert.equal(results.size, 10)
})

test('new writes reject missing files, non-byte payloads and non-256-bit keys', async () => {
  for (const files of [[], null, [null], [{ ...file(), name: 1 }], [{ ...file(), type: null }],
    [{ ...file(), contents: [1, 2, 3] }]]) {
    await assert.rejects(Adapters.Files.encrypt(files, key))
  }
  for (const length of [0, 16, 24, 31, 33]) await assert.rejects(Adapters.Files.encrypt([file()], randomBytes(length)))
})

test('wrong keys, byte tampering and truncated authentication tags are rejected', async () => {
  const original = JSON.parse(await Adapters.Files.encrypt([file()], key))
  await assert.rejects(Adapters.Files.decrypt(JSON.stringify(original), randomBytes(32)))
  const segments = original.ciphertext.split('--')
  for (const segment of [1, 2]) {
    const changed = [...segments]
    const bytes = Buffer.from(changed[segment], 'base64')
    bytes[Math.floor(bytes.length / 2)] ^= 1
    changed[segment] = bytes.toString('base64')
    await assert.rejects(Adapters.Files.decrypt(JSON.stringify({ ...original, ciphertext: changed.join('--') }), key))
  }
  await assert.rejects(Adapters.Files.decrypt(JSON.stringify({ ...original,
    ciphertext: segments.slice(0, 2).concat(Buffer.alloc(15).toString('base64')).join('--') }), key))
})

test('unknown versions, extra fields and malformed objects never fall back to legacy', async () => {
  const original = JSON.parse(await Adapters.Files.encrypt([file()], key))
  for (const data of [null, {}, { ...original, format: 'other' }, { ...original, version: 1 },
    { ...original, version: 3 }, { ...original, version: '2' }, { ...original, name: 'forged.txt' },
    { ...original, ciphertext: 12 }, { ...original, ciphertext: '' }]) {
    await assert.rejects(Adapters.Files.decrypt(JSON.stringify(data), key))
  }
  await assert.rejects(Adapters.Files.decrypt('not JSON', key))
})

test('strict v2 AES framing rejects extra segments and noncanonical base64', async () => {
  const original = JSON.parse(await Adapters.Files.encrypt([file()], key))
  const parts = original.ciphertext.split('--')
  const variants = [original.ciphertext + '--AAAA', original.ciphertext + '--',
    ['QUVTLUdDTQ', ...parts.slice(1)].join('--'), ['AAAA', ...parts.slice(1)].join('--'),
    [parts[0], parts[1].slice(1), parts[2]].join('--'),
    [parts[0], parts[1] + '\n', parts[2]].join('--'),
    [parts[0], parts[1], parts[2].replace(/[+/]/, '_') + ' '].join('--')]
  for (const ciphertext of variants) await assert.rejects(Adapters.Files.decrypt(JSON.stringify({ ...original, ciphertext }), key))
})

test('nonzero base64 padding bits are rejected even when they decode to identical bytes', async () => {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  for (let length = 0; length < 3; length++) {
    const original = JSON.parse(await Adapters.Files.encrypt([file('padding', Buffer.alloc(length))], key))
    const parts = original.ciphertext.split('--')
    const encoded = parts[2]
    if (!encoded.endsWith('=')) continue
    const padding = encoded.endsWith('==') ? 2 : 1
    const position = encoded.length - padding - 1
    const changed = encoded.slice(0, position) + alphabet[alphabet.indexOf(encoded[position]) | 1] + encoded.slice(position + 1)
    assert.deepEqual(Buffer.from(changed, 'base64'), Buffer.from(encoded, 'base64'))
    parts[2] = changed
    await assert.rejects(Adapters.Files.decrypt(JSON.stringify({ ...original, ciphertext: parts.join('--') }), key))
  }
})

test('manifest allocation limits reject excessive attacker-controlled metadata', async () => {
  await assert.rejects(Adapters.Files.encrypt([file('x'.repeat(16 * 1024 * 1024), Buffer.alloc(0))], key))
  const prefix = Buffer.alloc(4)
  prefix.writeUInt32BE(16 * 1024 * 1024 + 1)
  await assert.rejects(Adapters.Files.decrypt(await seal(prefix), key))
})

test('v2 key separation blocks raw-key decryption and wrapping ciphertext as legacy', async () => {
  const original = JSON.parse(await Adapters.Files.encrypt([file()], key))
  const [, iv, encrypted] = original.ciphertext.split('--')
  const rawKey = await webcrypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt'])
  await assert.rejects(webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: Buffer.from(iv, 'base64') }, rawKey, Buffer.from(encrypted, 'base64')))
  const wrapped = JSON.stringify([{ name: 'chosen.txt', type: 'text/plain', size: 1, contents: original.ciphertext }])
  await assert.rejects(Adapters.Files.decrypt(wrapped, key))
  // Relabeling an old raw-key ciphertext as new must also fail authentication.
  const old = JSON.parse(await legacy([file()]))[0].contents
  await assert.rejects(Adapters.Files.decrypt(JSON.stringify({ ...original, ciphertext: old }), key))
})

test('independently produced valid v2 frames decrypt', async () => {
  const expected = file('independent.bin', Buffer.from([0, 1, 2, 255]), '')
  const manifest = { format: FORMAT, version: 2, files: [{ name: expected.name, type: '', size: 4 }] }
  assertFiles(await Adapters.Files.decrypt(await seal(frame(manifest, expected.contents)), key), [expected])
})

test('authenticated malformed frame lengths, UTF-8 and JSON are rejected', async () => {
  const variants = [Buffer.alloc(0), Buffer.from([0, 0, 0]), Buffer.from([255, 255, 255, 255]),
    Buffer.from([0, 0, 0, 1, 255]), Buffer.from([0, 0, 0, 1, 123]), Buffer.from([0, 0, 0, 0])]
  for (const bytes of variants) await assert.rejects(Adapters.Files.decrypt(await seal(bytes), key))
})

test('authenticated malformed manifests and unsafe sizes are rejected', async () => {
  const meta = { name: 'file', type: '', size: 1 }
  const original = { format: FORMAT, version: 2, files: [meta] }
  const variants = [null, [], {}, { ...original, format: 'other' }, { ...original, version: 3 },
    { ...original, files: [] }, { ...original, files: {} }, { ...original, extra: true },
    ...[null, {}, { ...meta, name: 1 }, { ...meta, type: null }, { ...meta, extra: true },
      ...[-1, 0.5, Number.MAX_SAFE_INTEGER + 1, '1', null].map(size => ({ ...meta, size }))]
      .map(entry => ({ ...original, files: [entry] }))]
  for (const manifest of variants) await assert.rejects(Adapters.Files.decrypt(await seal(frame(manifest, Buffer.from([1]))), key))
})

test('authenticated sizes must exactly partition raw bytes without trailing data', async () => {
  for (const [sizes, bytes] of [[[0], [1]], [[2], [1]], [[1, 1], [1]], [[1], [1, 2]], [[2 ** 32], []]]) {
    const manifest = { format: FORMAT, version: 2, files: sizes.map(size => ({ name: 'file', type: '', size })) }
    await assert.rejects(Adapters.Files.decrypt(await seal(frame(manifest, Buffer.from(bytes))), key))
  }
})

test('legacy shares still open with an explicit unauthenticated metadata result', async () => {
  const files = [file(), file('empty', new Uint8Array(), ''), file('binary', Buffer.from([0, 255, 128]), '')]
  for (const length of [16, 24, 32]) {
    const oldKey = randomBytes(length)
    const original = await legacy(files, oldKey)
    const result = await Adapters.Files.decryptWithInfo(original, oldKey)
    assert.equal(result.metadataAuthenticated, false)
    assertFiles(result.files, files)
    const tampered = JSON.parse(original)
    tampered[0].name = 'server-changed-name.txt'
    tampered[0].size = 999999
    const changed = await Adapters.Files.decryptWithInfo(JSON.stringify(tampered), oldKey)
    assert.equal(changed.metadataAuthenticated, false)
    assert.equal(changed.files[0].name, tampered[0].name)
    assert.equal(changed.files[0].size, files[0].contents.byteLength)
  }
})

test('legacy arbitrary binary content is preserved, including v2-looking plaintext', async () => {
  const files = [file('looks-new.json', Buffer.from('{"format":"cryptgeon-files","version":2}'), 'application/json')]
  assertFiles(await Adapters.Files.decrypt(await legacy(files), key), files)
})

test('Node crypto fallback works when the global WebCrypto object is absent', () => {
  const program = `Object.defineProperty(globalThis,'crypto',{value:undefined,configurable:true});
    const {Adapters}=require(${JSON.stringify(bundle)}); const key=Buffer.alloc(32,7);
    (async()=>{const data=[{name:'fallback',type:'',size:3,contents:Buffer.from([1,2,3])}];
      const encrypted=await Adapters.Files.encrypt(data,key);
      const result=await Adapters.Files.decryptWithInfo(encrypted,key);
      require('node:assert/strict').equal(result.metadataAuthenticated,true);
      require('node:assert/strict').deepEqual(Buffer.from(result.files[0].contents),Buffer.from([1,2,3]));
    })().catch(e=>{console.error(e);process.exitCode=1})`
  execFileSync(process.execPath, ['-e', program], { timeout: 15000, stdio: 'pipe' })
})
