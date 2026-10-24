import { AES, Bytes, type TypedArray } from 'occulto'
import type { FileDTO } from './api'
import { decryptFilesWithInfo, encryptFiles } from './files.js'

abstract class CryptAdapter<T> {
  abstract encrypt(plaintext: T, key: TypedArray): Promise<string>
  abstract decrypt(ciphertext: string, key: TypedArray): Promise<T>
}

class CryptTextAdapter implements CryptAdapter<string> {
  async encrypt(plaintext: string, key: TypedArray) {
    return await AES.encrypt(Bytes.encode(plaintext), key)
  }
  async decrypt(ciphertext: string, key: TypedArray) {
    return Bytes.decode(await AES.decrypt(ciphertext, key))
  }
}

class CryptBlobAdapter implements CryptAdapter<TypedArray> {
  async encrypt(plaintext: TypedArray, key: TypedArray) {
    return await AES.encrypt(plaintext, key)
  }

  async decrypt(ciphertext: string, key: TypedArray) {
    return await AES.decrypt(ciphertext, key)
    // const plaintext = await AES.decrypt(ciphertext, key)
    // return new Blob([plaintext], { type: 'application/octet-stream' })
  }
}

class CryptFilesAdapter implements CryptAdapter<FileDTO[]> {
  async encrypt(plaintext: FileDTO[], key: TypedArray) {
    return encryptFiles(plaintext, key)
  }

  async decrypt(ciphertext: string, key: TypedArray) {
    return (await decryptFilesWithInfo(ciphertext, key)).files
  }

  async decryptWithInfo(ciphertext: string, key: TypedArray) {
    return decryptFilesWithInfo(ciphertext, key)
  }
}

export const Adapters = {
  Text: new CryptTextAdapter(),
  Blob: new CryptBlobAdapter(),
  Files: new CryptFilesAdapter(),
}
