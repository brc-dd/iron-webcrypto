import assert from 'node:assert'
import fs from 'node:fs/promises'
import path from 'node:path'

const file = path.resolve(process.argv[2])
const data = await fs.readFile(file, 'utf8')
const sarif = JSON.parse(data)

function traverse(obj) {
  for (const key in obj) {
    if (key === 'uri') {
      assert(typeof obj[key] === 'string')
      obj[key] = 'src/' + obj[key]
    } else if (key === 'uriBaseId') {
      delete obj[key]
    } else if (typeof obj[key] === 'object') {
      traverse(obj[key])
    }
  }
}

traverse(sarif)

if (sarif.version === '2.1.0') {
  sarif.$schema = 'https://json.schemastore.org/sarif-2.1.0.json'
}

await fs.writeFile(file + '.tmp', JSON.stringify(sarif, null, 2) + '\n')
await fs.rename(file + '.tmp', file)
