import { assertEquals, AssertionError } from 'https://deno.land/std@0.219.1/assert/mod.ts'
import { stripAnsiCode } from 'https://deno.land/std@0.219.1/fmt/colors.ts'
import { describe, it } from 'https://deno.land/std@0.219.1/testing/bdd.ts'
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
