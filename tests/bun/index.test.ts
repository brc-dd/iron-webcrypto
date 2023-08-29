/// <reference types="bun-types" />
import assert, { AssertionError } from 'assert'
import { describe, it } from 'bun:test'
import { createHmac } from 'crypto'
import { tests } from '../index.js'

async function rejects(fn: Promise<unknown>, re: RegExp): Promise<void> {
  let doesThrow = false
  let isPromiseReturned = false
  const msgToAppendToError = `: ${re.toString()}`
  try {
    const possiblePromise = fn
    if (typeof possiblePromise === 'object' && typeof possiblePromise.then === 'function') {
      isPromiseReturned = true
      await possiblePromise
    }
  } catch (error) {
    if (!isPromiseReturned)
      throw new AssertionError({
        message: `Function throws when expected to reject${msgToAppendToError}`
      })
    if (!(error instanceof Error))
      throw new AssertionError({ message: 'A non-Error object was rejected.' })
    if (!re.test(error.message))
      throw new AssertionError({
        message: `Expected error message to include "${re.toString()}", but got "${error.message}"`
      })
    doesThrow = true
  }

  if (!doesThrow)
    throw new AssertionError({ message: `Expected function to reject${msgToAppendToError}` })
}

tests({ crypto, createHmac, describe, it, deepEqual: assert.deepStrictEqual, rejects })
