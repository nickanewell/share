import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import fs from 'node:fs'
import { createRequire } from 'node:module'
import os from 'node:os'
import path from 'node:path'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

import {
  captureDownloadDirectory,
  saveDownloadFiles,
  validateDownloadFilename,
} from '../../packages/cli/src/utils/download-files.ts'

const execute = promisify(execFile)
const helperUrl = new URL('../../packages/cli/src/utils/download-files.ts', import.meta.url).href
const file = (name, contents = name) => {
  const bytes = Buffer.from(contents)
  return { name, contents: bytes, size: bytes.byteLength, type: 'application/octet-stream' }
}

async function inDownloadDirectory(run) {
  const previous = process.cwd()
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'cryptgeon-download-test-'))
  const output = path.join(root, 'downloads')
  fs.mkdirSync(output)
  process.chdir(output)
  try {
    return await run({ root, output, directory: captureDownloadDirectory() })
  } finally {
    process.chdir(previous)
    // rm removes symlinks themselves; it must never follow the test's outside links.
    fs.rmSync(root, { recursive: true, force: true })
  }
}

test('rejects traversal, absolute, Windows, device, dot, NUL and ambiguous filenames', () => {
  for (const name of [
    '', '.', '..', '../outside', 'sub/file', './file', '/absolute', '//server/share',
    'C:\\outside.txt', 'C:outside.txt', '\\outside', '\\\\server\\share',
    'sub\\file', 'file\0.txt', 'file\n.txt', 'file\x1b.txt', 'file:stream',
    'CON', 'con.txt', 'NUL.tar.gz', 'AUX', 'PRN', 'COM1', 'LPT9.log',
    'COM¹.txt', 'LPT³', 'CON .txt', 'CONIN$', 'CONOUT$.txt',
    'file.', 'file ', 'file?.txt', 'file*.txt', 'file|other', 'file<other',
    null, undefined, 42, {},
  ]) {
    assert.throws(() => validateDownloadFilename(name), /Unsafe download filename/, JSON.stringify(name))
  }
  for (const name of ['hello.txt', 'archive.tar.gz', '.env', '..notes', 'my report (final).pdf', 'Grüße 日本語.txt']) {
    assert.doesNotThrow(() => validateDownloadFilename(name))
  }
})

test('validates the complete selection before writing and never escapes its directory', async () => {
  await inDownloadDirectory(({ root, output, directory }) => {
    const outside = path.join(root, 'outside.txt')
    fs.writeFileSync(outside, 'keep')
    for (const name of ['../outside.txt', outside, 'C:outside.txt', '..\\outside.txt']) {
      assert.throws(() => saveDownloadFiles([file('valid.txt'), file(name, 'replace')], directory), /Unsafe/)
      assert.deepEqual(fs.readdirSync(output), [])
      assert.equal(fs.readFileSync(outside, 'utf8'), 'keep')
    }
  })
})

test('preserves names, extensions and sliced bytes; duplicate names get distinct files', async () => {
  await inDownloadDirectory(({ directory }) => {
    const bytes = Uint8Array.of(99, 11, 12, 13, 88)
    const names = saveDownloadFiles([
      { name: 'report.tar.gz', contents: bytes.subarray(1, 4) },
      file('report.tar.gz', 'second'),
      file('report.tar.gz', 'third'),
      file('.env', 'first hidden'),
      file('.env', 'second hidden'),
      file('Grüße 日本語.txt', 'unicode'),
    ], directory)
    assert.deepEqual(names, ['report.tar.gz', 'report.tar (1).gz', 'report.tar (2).gz', '.env', '.env (1)', 'Grüße 日本語.txt'])
    assert.deepEqual([...fs.readFileSync(names[0])], [11, 12, 13])
    assert.equal(fs.readFileSync(names[1], 'utf8'), 'second')
    assert.equal(fs.readFileSync(names[2], 'utf8'), 'third')
    if (process.platform !== 'win32') assert.equal(fs.statSync(names[0]).mode & 0o777, 0o600)
  })
})

test('never overwrites unreadable existing files, directories or existing collision suffixes', async () => {
  await inDownloadDirectory(({ directory }) => {
    fs.writeFileSync('report.txt', 'original', { mode: 0o000 })
    fs.writeFileSync('report (1).txt', 'also original')
    fs.mkdirSync('folder.txt')
    const names = saveDownloadFiles([file('report.txt', 'new'), file('folder.txt', 'data')], directory)
    assert.deepEqual(names, ['report (2).txt', 'folder (1).txt'])
    fs.chmodSync('report.txt', 0o600)
    assert.equal(fs.readFileSync('report.txt', 'utf8'), 'original')
    assert.equal(fs.readFileSync('report (1).txt', 'utf8'), 'also original')
    assert.ok(fs.statSync('folder.txt').isDirectory())
  })
})

test('existing and dangling symlinks are collisions, never followed', { skip: process.platform === 'win32' }, async () => {
  await inDownloadDirectory(({ root, directory }) => {
    const outside = path.join(root, 'outside.txt')
    const absent = path.join(root, 'must-not-be-created.txt')
    fs.writeFileSync(outside, 'keep')
    fs.symlinkSync(outside, 'linked.txt')
    fs.symlinkSync(absent, 'dangling.txt')
    assert.deepEqual(saveDownloadFiles([file('linked.txt', 'new'), file('dangling.txt', 'new')], directory), ['linked (1).txt', 'dangling (1).txt'])
    assert.equal(fs.readFileSync(outside, 'utf8'), 'keep')
    assert.equal(fs.existsSync(absent), false)
    assert.ok(fs.lstatSync('linked.txt').isSymbolicLink())
    assert.ok(fs.lstatSync('dangling.txt').isSymbolicLink())
  })
})

test('retains the original kernel cwd after its path is replaced by an outside symlink', { skip: process.platform === 'win32' }, async () => {
  await inDownloadDirectory(({ root, output, directory }) => {
    const renamed = path.join(root, 'original-directory')
    const outside = path.join(root, 'outside-directory')
    fs.mkdirSync(outside)
    fs.renameSync(output, renamed)
    fs.symlinkSync(outside, output, 'dir')
    assert.deepEqual(saveDownloadFiles([file('safe.txt', 'saved')], directory), ['safe.txt'])
    assert.equal(fs.readFileSync(path.join(renamed, 'safe.txt'), 'utf8'), 'saved')
    assert.deepEqual(fs.readdirSync(outside), [])
  })
})

test('refuses an explicitly different directory or a cwd changed after capture', async () => {
  await inDownloadDirectory(({ root, directory }) => {
    const other = path.join(root, 'other')
    fs.mkdirSync(other)
    assert.throws(() => captureDownloadDirectory(other), /current working directory/)
    process.chdir(other)
    assert.throws(() => saveDownloadFiles([file('safe.txt')], directory), /working directory changed/)
    assert.deepEqual(fs.readdirSync(other), [])
  })
})

test('parallel processes atomically choose distinct collision names without losing content', async () => {
  await inDownloadDirectory(async ({ output }) => {
    const results = await Promise.allSettled(Array.from({ length: 8 }, (_, index) => execute(process.execPath, [
      '--input-type=module', '--eval',
      `import {captureDownloadDirectory,saveDownloadFiles} from ${JSON.stringify(helperUrl)};
       console.log(JSON.stringify(saveDownloadFiles([{name:'parallel.txt',contents:Buffer.from('payload-${index}')}],captureDownloadDirectory())));`,
    ], { cwd: output })))
    for (const result of results) {
      if (result.status === 'rejected') throw result.reason
    }
    const names = results.flatMap(result => JSON.parse(result.value.stdout))
    assert.equal(new Set(names).size, 8)
    assert.deepEqual(new Set(names.map(name => fs.readFileSync(name, 'utf8'))), new Set(Array.from({ length: 8 }, (_, index) => `payload-${index}`)))
  })
})

test('failed writes clean only the new file and close its descriptor', async (t) => {
  await inDownloadDirectory(({ directory }) => {
    fs.writeFileSync('report.txt', 'keep')
    let opened
    t.mock.method(fs, 'writeFileSync', (descriptor) => {
      opened = descriptor
      fs.writeSync(descriptor, Buffer.from('partial'))
      throw new Error('simulated disk failure')
    })
    assert.throws(() => saveDownloadFiles([file('report.txt', 'new')], directory), /simulated disk failure/)
    assert.equal(fs.readFileSync('report.txt', 'utf8'), 'keep')
    assert.equal(fs.existsSync('report (1).txt'), false)
    assert.throws(() => fs.fstatSync(opened), { code: 'EBADF' })
  })
})

test('failed-write cleanup does not unlink a replacement symlink or touch its target', { skip: process.platform === 'win32' }, async (t) => {
  await inDownloadDirectory(({ root, directory }) => {
    const outside = path.join(root, 'outside.txt')
    fs.writeFileSync(outside, 'keep')
    t.mock.method(fs, 'writeFileSync', () => {
      fs.unlinkSync('new.txt')
      fs.symlinkSync(outside, 'new.txt')
      throw new Error('simulated file replacement')
    })
    assert.throws(() => saveDownloadFiles([file('new.txt')], directory), /simulated file replacement/)
    assert.ok(fs.lstatSync('new.txt').isSymbolicLink())
    assert.equal(fs.readFileSync(outside, 'utf8'), 'keep')
  })
})

test('failed-write cleanup preserves an ordinary replacement with a different inode', async (t) => {
  await inDownloadDirectory(({ directory }) => {
    fs.writeFileSync('replacement.txt', 'keep replacement')
    t.mock.method(fs, 'writeFileSync', () => {
      fs.renameSync('replacement.txt', 'new.txt')
      throw new Error('simulated file replacement')
    })
    assert.throws(() => saveDownloadFiles([file('new.txt')], directory), /simulated file replacement/)
    assert.equal(fs.readFileSync('new.txt', 'utf8'), 'keep replacement')
  })
})

let downloadAction
async function loadDownloadAction() {
  if (downloadAction) return downloadAction
  const require = createRequire(new URL('../../packages/cli/package.json', import.meta.url))
  const { build } = createRequire(require.resolve('tsup'))('esbuild')
  const result = await build({
    entryPoints: [fileURLToPath(new URL('../../packages/cli/src/actions/download.ts', import.meta.url))],
    bundle: true,
    write: false,
    platform: 'node',
    format: 'esm',
    target: 'node24',
    plugins: [{
      name: 'offline-download-fixtures',
      setup(build) {
        build.onResolve({ filter: /^(inquirer|\.\.\/shared\/(api|adapters)\.js)$/ }, ({ path }) => ({ path, namespace: 'fixture' }))
        build.onLoad({ filter: /.*/, namespace: 'fixture' }, ({ path }) => ({ contents:
          path === 'inquirer' ? 'export default {prompt: (...args) => globalThis.__downloadFixture.prompt(...args)}' :
          path.includes('adapters') ? 'export const Adapters = {Files: {decryptWithInfo: (...args) => globalThis.__downloadFixture.decrypt(...args)}}' :
          'export const API = {setOptions: (...args) => globalThis.__downloadFixture.setOptions(...args), info: (...args) => globalThis.__downloadFixture.info(...args), get: (...args) => globalThis.__downloadFixture.get(...args)}',
        }))
      },
    }],
  })
  const source = `${result.outputFiles[0].text}\n//# sourceURL=cryptgeon-download-fixture.mjs`
  downloadAction = (await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`)).download
  return downloadAction
}

async function withDownloadFixture(t, files, run, metadataAuthenticated = true) {
  const calls = []
  const logs = []
  const warnings = []
  globalThis.__downloadFixture = {
    setOptions: value => calls.push(['options', value]),
    info: async id => { calls.push(['info', id]); return { meta: { type: 'file' } } },
    get: async id => { calls.push(['get', id]); return { meta: { type: 'file' }, contents: 'fixture-ciphertext' } },
    decrypt: async () => ({ files, metadataAuthenticated }),
    prompt: async ([question]) => ({ indices: [question.choices[1].value] }),
  }
  t.mock.method(console, 'log', value => logs.push(value))
  t.mock.method(console, 'warn', value => warnings.push(value))
  try {
    const download = await loadDownloadAction()
    await run(download, { calls, logs, warnings })
  } finally {
    delete globalThis.__downloadFixture
  }
}

test('actual download action saves duplicate files safely and warns once for legacy metadata', async (t) => {
  await inDownloadDirectory(async () => {
    await withDownloadFixture(t, [file('same.txt', 'first'), file('same.txt', 'second')], async (download, { calls, logs, warnings }) => {
      await download(new URL(`https://example.invalid/note/fixture#${'00'.repeat(32)}`), true)
      assert.equal(fs.readFileSync('same.txt', 'utf8'), 'first')
      assert.equal(fs.readFileSync('same (1).txt', 'utf8'), 'second')
      assert.deepEqual(logs, ['Saved: same.txt', 'Saved: same (1).txt'])
      assert.deepEqual(warnings, ['Warning: this older share does not authenticate file names or types. Verify them before opening.'])
      assert.deepEqual(calls, [['options', { server: 'https://example.invalid' }], ['info', 'fixture'], ['get', 'fixture']])
    }, false)
  })
})

test('actual download selection identifies duplicate names by index and new metadata has no warning', async (t) => {
  await inDownloadDirectory(async () => {
    await withDownloadFixture(t, [file('same.txt', 'first'), file('same.txt', 'second')], async (download, { warnings }) => {
      await download(new URL(`https://example.invalid/note/fixture#${'00'.repeat(32)}`), false)
      assert.deepEqual(fs.readdirSync('.'), ['same.txt'])
      assert.equal(fs.readFileSync('same.txt', 'utf8'), 'second')
      assert.deepEqual(warnings, [])
    })
  })
})

test('actual download action rejects malicious names before saving any selection', async (t) => {
  await inDownloadDirectory(async ({ output }) => {
    await withDownloadFixture(t, [file('safe.txt'), file('../outside.txt')], async download => {
      await assert.rejects(download(new URL(`https://example.invalid/note/fixture#${'00'.repeat(32)}`), true), /Unsafe download filename/)
      assert.deepEqual(fs.readdirSync(output), [])
    })
  })
})
