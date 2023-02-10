/* eslint @typescript-eslint/ban-ts-comment: off */
import assert from 'node:assert/strict'
import { webcrypto } from 'node:crypto'
import { describe, it } from 'node:test'
import { satisfies } from 'semver'
import { tests } from '.'

tests({
  // @ts-expect-error
  crypto: satisfies(process.version, '>=19.0.0') ? crypto : webcrypto,
  describe,
  it,
  deepEqual(actual, expected) {
    assert.deepEqual(actual, expected)
  },
  async rejects(fn, re) {
    return assert.rejects(fn, re)
  },
})
