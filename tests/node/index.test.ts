import assert from 'assert'
import crypto from 'crypto'
import test from 'test'
import { tests } from '../index.js'

tests({
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
  crypto: globalThis.crypto ?? crypto.webcrypto,
  createHmac: crypto.createHmac,
  describe: test.describe,
  it: test.it,
  deepEqual: assert.deepStrictEqual,
  rejects: assert.rejects,
})
