/* eslint @typescript-eslint/ban-ts-comment: off */
import { Crypto } from '@peculiar/webcrypto'
import crypto from 'node:crypto'
import { satisfies } from 'semver'
import { describe, expect, it } from 'vitest'
import { tests } from '.'

tests({
  // @ts-expect-error
  // eslint-disable-next-line no-nested-ternary
  crypto: satisfies(process.version, '>=19.0.0')
    ? globalThis.crypto
    : satisfies(process.version, '>=16.0.0')
    ? crypto.webcrypto
    : Crypto,
  describe,
  it,
  deepEqual(actual, expected) {
    expect(actual).toStrictEqual(expected)
  },
  async rejects(fn, re) {
    return expect(fn).rejects.toThrow(re)
  },
})
