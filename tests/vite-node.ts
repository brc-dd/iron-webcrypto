/* eslint @typescript-eslint/ban-ts-comment: off */
import { webcrypto } from 'crypto'
import { satisfies } from 'semver'
import { describe, expect, it } from 'vitest'
import { tests } from '.'

tests({
  // @ts-expect-error
  crypto: satisfies(process.version, '>=19.0.0') ? crypto : webcrypto,
  describe,
  it,
  deepEqual(actual, expected) {
    expect(actual).toStrictEqual(expected)
  },
  async rejects(fn, re) {
    return expect(fn).rejects.toThrow(re)
  },
})
