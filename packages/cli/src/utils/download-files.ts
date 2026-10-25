import fs, { type BigIntStats } from 'node:fs'
import { extname, resolve } from 'node:path'

export type DownloadDirectory = {
  readonly path: string
  readonly device: bigint
  readonly inode: bigint
}

type DownloadFile = {
  name: string
  contents: ArrayBufferView
}

function matchesDirectory(stats: BigIntStats, directory: DownloadDirectory) {
  return stats.isDirectory() && stats.dev === directory.device && stats.ino === directory.inode
}

export function captureDownloadDirectory(path = process.cwd()): DownloadDirectory {
  const resolved = resolve(path)
  const stats = fs.statSync(resolved, { bigint: true })
  const directory = { path: resolved, device: stats.dev, inode: stats.ino }
  if (!matchesDirectory(fs.statSync('.', { bigint: true }), directory)) {
    throw new Error('The download directory must be the current working directory')
  }
  return directory
}

export function validateDownloadFilename(name: unknown): asserts name is string {
  if (
    typeof name !== 'string' ||
    !name ||
    name === '.' ||
    name === '..' ||
    /[<>:"/\\|?*\u0000-\u001f\u007f]/u.test(name) ||
    /[. ]$/u.test(name) ||
    /^(con|prn|aux|nul|com[1-9¹²³]|lpt[1-9¹²³]|conin\$|conout\$|clock\$)(?: *\.| *$)/iu.test(name)
  ) {
    throw new Error(`Unsafe download filename ${JSON.stringify(name)}: expected a portable basename`)
  }
}

/**
 * Save only in the captured cwd. Relative basenames keep filesystem operations
 * anchored to the kernel's cwd even if an ancestor path is renamed or replaced.
 * The CLI must not change its process cwd during this synchronous operation.
 * A hostile process with write access to the destination is outside this boundary.
 */
export function saveDownloadFiles(files: readonly DownloadFile[], directory: DownloadDirectory): string[] {
  // Reject the entire selection before creating any files.
  for (const file of files) {
    validateDownloadFilename(file.name)
    if (!ArrayBuffer.isView(file.contents)) throw new Error('Invalid downloaded file contents')
  }

  return files.map((file) => {
    const extension = extname(file.name)
    const stem = file.name.slice(0, file.name.length - extension.length)

    for (let collision = 0; collision < 10_000; collision++) {
      if (!matchesDirectory(fs.statSync('.', { bigint: true }), directory)) {
        throw new Error('The current working directory changed during the download')
      }
      const filename = collision === 0 ? file.name : `${stem} (${collision})${extension}`
      let descriptor: number
      try {
        // O_EXCL atomically reserves the name and also rejects existing symlinks.
        descriptor = fs.openSync(filename, 'wx', 0o600)
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'EEXIST') continue
        throw error
      }

      try {
        const created = fs.fstatSync(descriptor, { bigint: true })
        try {
          const bytes = new Uint8Array(file.contents.buffer, file.contents.byteOffset, file.contents.byteLength)
          fs.writeFileSync(descriptor, bytes)
        } catch (error) {
          // Only remove this attempt's newly created file, never a replacement.
          try {
            const current = fs.lstatSync(filename, { bigint: true })
            if (current.isFile() && current.dev === created.dev && current.ino === created.ino) {
              fs.unlinkSync(filename)
            }
          } catch {}
          throw error
        }
      } finally {
        fs.closeSync(descriptor)
      }
      return filename
    }
    throw new Error(`Could not find an unused download filename for ${JSON.stringify(file.name)}`)
  })
}
