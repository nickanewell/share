import inquirer from 'inquirer'
import { AES, Hex } from 'occulto'
import pretty from 'pretty-bytes'
import { Adapters } from '../shared/adapters.js'
import { API } from '../shared/api.js'
import { captureDownloadDirectory, saveDownloadFiles, validateDownloadFilename } from '../utils/download-files.js'

export async function download(url: URL, all: boolean, suggestedPassword?: string) {
  const downloadDirectory = captureDownloadDirectory()
  API.setOptions({ server: url.origin })
  const id = url.pathname.split('/')[2]
  const preview = await API.info(id).catch(() => {
    throw new Error('Note does not exist or is expired')
  })

  // Password
  let password: string
  const derivation = preview?.meta.derivation
  if (derivation) {
    if (suggestedPassword) {
      password = suggestedPassword
    } else {
      const response = await inquirer.prompt([
        {
          type: 'password',
          message: 'Note password',
          name: 'password',
        },
      ])
      password = response.password
    }
  } else {
    password = url.hash.slice(1)
  }

  const key = derivation ? (await AES.derive(password, derivation))[0] : Hex.decode(password)
  const note = await API.get(id)

  const couldNotDecrypt = new Error('Could not decrypt note. Probably an invalid password')
  switch (note.meta.type) {
    case 'file':
      const decrypted = await Adapters.Files.decryptWithInfo(note.contents, key).catch(() => {
        throw couldNotDecrypt
      })
      const files = decrypted.files
      if (!files) {
        throw new Error('No files found in note')
      }
      if (decrypted.metadataAuthenticated === false) {
        console.warn('Warning: this older share does not authenticate file names or types. Verify them before opening.')
      }
      for (const file of files) validateDownloadFilename(file.name)

      let selected: typeof files
      if (all) {
        selected = files
      } else {
        const { indices } = await inquirer.prompt([
          {
            type: 'checkbox',
            message: 'What files should be saved?',
            name: 'indices',
            choices: files.map((file, index) => ({
              value: index,
              name: `${file.name} - ${file.type} - ${pretty(file.size, { binary: true })}`,
              checked: true,
            })),
          },
        ])
        selected = files.filter((file, index) => indices.includes(index))
      }

      if (!selected.length) throw new Error('No files selected')
      for (const filename of saveDownloadFiles(selected, downloadDirectory)) {
        console.log(`Saved: ${filename}`)
      }

      break
    case 'text':
      const plaintext = await Adapters.Text.decrypt(note.contents, key).catch(() => {
        throw couldNotDecrypt
      })
      console.log(plaintext)
      break
  }
}
