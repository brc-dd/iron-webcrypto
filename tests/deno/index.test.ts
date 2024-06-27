import { AssertionError, assertEquals } from 'jsr:@std/assert'
import { stripAnsiCode } from 'jsr:@std/fmt/colors'
import { describe, it } from 'jsr:@std/testing/bdd'
import { tests } from '../index.ts'

async function rejects(fn: Promise<unknown>, re: RegExp): Promise<void> {
  let doesThrow = false
  let isPromiseReturned = false
  const msgToAppendToError = re ? `: ${re}` : '.'
  try {
    const possiblePromise = fn
    if (
      possiblePromise &&
      typeof possiblePromise === 'object' &&
      typeof possiblePromise.then === 'function'
    ) {
      isPromiseReturned = true
      await possiblePromise
    }
  } catch (error) {
    if (!isPromiseReturned)
      throw new AssertionError(`Function throws when expected to reject${msgToAppendToError}`)
    if (error instanceof Error === false)
      throw new AssertionError('A non-Error object was rejected.')
    if (!re.test(stripAnsiCode(error.message)))
      throw new AssertionError(
        `Expected error message to include "${re}", but got "${error.message}"`
      )
    doesThrow = true
  }

  if (!doesThrow) throw new AssertionError(`Expected function to reject${msgToAppendToError}`)
}

tests({ crypto, describe, it, deepEqual: assertEquals, rejects })
