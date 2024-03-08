/* eslint-disable */

import assert from 'node:assert'
import crypto from 'node:crypto'
import test from 'node:test'
import { tests } from '../index.js'

tests({
  crypto: globalThis.crypto ?? crypto.webcrypto,
  createHmac: crypto.createHmac,
  describe: test.describe,
  it: test.it,
  deepEqual: assert.deepStrictEqual,
  rejects: assert.rejects
})
