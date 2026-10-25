import { AES, type TypedArray } from 'occulto'
import type { FileDTO } from './api.js'

export const FILE_FORMAT = 'cryptgeon-files'
export const FILE_FORMAT_VERSION = 2

// Bound allocations independently of server configuration or an untrusted size.
export const MAX_FILE_FRAME_BYTES = 512 * 1024 * 1024
export const MAX_FILE_MANIFEST_BYTES = 16 * 1024 * 1024

const encoder = new TextEncoder()
const decoder = new TextDecoder('utf-8', { fatal: true })
const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
const salt = encoder.encode(FILE_FORMAT)
const info = encoder.encode(`${FILE_FORMAT}/v${FILE_FORMAT_VERSION}`)

export type DecryptedFiles = {
  files: FileDTO[]
  metadataAuthenticated: boolean
}

type FileMetadata = Pick<FileDTO, 'name' | 'type' | 'size'>

function invalid(): never {
  throw new Error('Invalid encrypted file bundle')
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function keys(value: Record<string, unknown>, expected: string[]): boolean {
  const actual = Object.keys(value)
  return actual.length === expected.length && expected.every((key) => Object.hasOwn(value, key))
}

function ownedBytes(view: ArrayBufferView): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(view.byteLength)
  bytes.set(new Uint8Array(view.buffer, view.byteOffset, view.byteLength))
  return bytes
}

function metadata(value: unknown, exact: boolean): value is FileMetadata {
  return record(value)
    && (!exact || keys(value, ['name', 'type', 'size']))
    && typeof value.name === 'string'
    && typeof value.type === 'string'
    && typeof value.size === 'number'
    && Number.isSafeInteger(value.size)
    && value.size >= 0
}

async function fileKey(key: TypedArray): Promise<Uint8Array<ArrayBuffer>> {
  if (!ArrayBuffer.isView(key) || key.byteLength !== 32) invalid()
  const master = ownedBytes(key)
  // Node 18 exposes WebCrypto through node:crypto even without a global crypto.
  const subtle = globalThis.crypto?.subtle ?? (await import('node:crypto')).webcrypto.subtle
  const imported = await subtle.importKey('raw', master.buffer, 'HKDF', false, ['deriveBits'])
  const derived = await subtle.deriveBits({
    name: 'HKDF', hash: 'SHA-256', salt: salt.buffer, info: info.buffer,
  }, imported, 256)
  return new Uint8Array(derived)
}

// The old library accepts extra AES segments and noncanonical Base64. Do not
// accept those alternate representations in the versioned authenticated format.
function base64Size(value: string): number {
  if (!value.length || value.length % 4 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) invalid()
  const padding = value.endsWith('==') ? 2 : value.endsWith('=') ? 1 : 0
  if (padding === 2 && (alphabet.indexOf(value[value.length - 3]!) & 15)) invalid()
  if (padding === 1 && (alphabet.indexOf(value[value.length - 2]!) & 3)) invalid()
  return value.length / 4 * 3 - padding
}

function validateCiphertext(ciphertext: unknown): asserts ciphertext is string {
  if (typeof ciphertext !== 'string') invalid()
  const parts = ciphertext.split('--')
  if (parts.length !== 3 || parts[0] !== 'QUVTLUdDTQ==') invalid()
  if (base64Size(parts[1]!) !== 12) invalid()
  const bytes = base64Size(parts[2]!)
  if (bytes < 16 || bytes > MAX_FILE_FRAME_BYTES + 16) invalid()
}

export async function encryptFiles(files: FileDTO[], key: TypedArray): Promise<string> {
  if (!Array.isArray(files) || !files.length) invalid()
  let dataLength = 0
  const data: Uint8Array<ArrayBuffer>[] = []
  const descriptions = files.map((file) => {
    if (!record(file) || typeof file.name !== 'string' || typeof file.type !== 'string'
      || !ArrayBuffer.isView(file.contents)) invalid()
    if (file.contents.byteLength > MAX_FILE_FRAME_BYTES - dataLength) invalid()
    const bytes = ownedBytes(file.contents)
    data.push(bytes)
    dataLength += bytes.byteLength
    return { name: file.name, type: file.type, size: bytes.byteLength }
  })
  const manifest = encoder.encode(JSON.stringify({
    format: FILE_FORMAT, version: FILE_FORMAT_VERSION, files: descriptions,
  }))
  if (manifest.byteLength > MAX_FILE_MANIFEST_BYTES) invalid()
  const total = 4 + manifest.byteLength + dataLength
  if (total > MAX_FILE_FRAME_BYTES) invalid()
  const frame = new Uint8Array(total)
  new DataView(frame.buffer).setUint32(0, manifest.byteLength, false)
  frame.set(manifest, 4)
  let offset = 4 + manifest.byteLength
  for (const bytes of data) {
    frame.set(bytes, offset)
    offset += bytes.byteLength
  }
  const ciphertext = await AES.encrypt(frame, await fileKey(key))
  return JSON.stringify({ format: FILE_FORMAT, version: FILE_FORMAT_VERSION, ciphertext })
}

function decodeFrame(frame: Uint8Array): FileDTO[] {
  if (frame.byteLength < 4 || frame.byteLength > MAX_FILE_FRAME_BYTES) invalid()
  const length = new DataView(frame.buffer, frame.byteOffset, frame.byteLength).getUint32(0, false)
  if (!length || length > MAX_FILE_MANIFEST_BYTES || length > frame.byteLength - 4) invalid()
  const manifest: unknown = JSON.parse(decoder.decode(frame.subarray(4, 4 + length)))
  if (!record(manifest) || !keys(manifest, ['format', 'version', 'files'])
    || manifest.format !== FILE_FORMAT || manifest.version !== FILE_FORMAT_VERSION
    || !Array.isArray(manifest.files) || !manifest.files.length) invalid()
  let offset = 4 + length
  const files: FileDTO[] = []
  for (const description of manifest.files) {
    if (!metadata(description, true) || description.size > frame.byteLength - offset) invalid()
    files.push({
      name: description.name, type: description.type, size: description.size,
      contents: frame.slice(offset, offset + description.size),
    })
    offset += description.size
  }
  if (offset !== frame.byteLength) invalid()
  return files
}

async function legacyFiles(value: unknown[], key: TypedArray): Promise<FileDTO[]> {
  if (!value.length) invalid()
  return Promise.all(value.map(async (file) => {
    if (!metadata(file, false) || typeof (file as Record<string, unknown>).contents !== 'string') invalid()
    // Historical files used the original master key and permissive AES codec.
    const contents = ownedBytes(await AES.decrypt((file as Record<string, unknown>).contents as string, key))
    return { name: file.name, type: file.type, size: contents.byteLength, contents }
  }))
}

export async function decryptFilesWithInfo(ciphertext: string, key: TypedArray): Promise<DecryptedFiles> {
  const envelope: unknown = JSON.parse(ciphertext)
  if (Array.isArray(envelope)) {
    return { files: await legacyFiles(envelope, key), metadataAuthenticated: false }
  }
  if (!record(envelope) || !keys(envelope, ['format', 'version', 'ciphertext'])
    || envelope.format !== FILE_FORMAT || envelope.version !== FILE_FORMAT_VERSION) invalid()
  validateCiphertext(envelope.ciphertext)
  const frame = ownedBytes(await AES.decrypt(envelope.ciphertext, await fileKey(key)))
  return { files: decodeFrame(frame), metadataAuthenticated: true }
}
