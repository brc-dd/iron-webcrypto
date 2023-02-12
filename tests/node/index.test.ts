/* eslint @typescript-eslint/ban-ts-comment: off */
import { Crypto } from '@peculiar/webcrypto'
import assert from 'assert'
import crypto from 'crypto'
import { satisfies } from 'semver'
import test from 'test'
import { tests } from '../index.js'

tests({
  // @ts-expect-error
  // eslint-disable-next-line no-nested-ternary
  crypto: satisfies(process.version, '>=19.0.0')
    ? globalThis.crypto
    : satisfies(process.version, '>=16.0.0')
    ? crypto.webcrypto
    : new Crypto(),
  createHmac: crypto.createHmac,
  describe: test.describe,
  it: test.it,
  deepEqual: assert.deepStrictEqual,
  rejects: assert.rejects,
})
