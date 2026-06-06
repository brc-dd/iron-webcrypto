import { AssertionError } from '@std/assert'

export {
  assert,
  assertEquals,
  assertExists,
  assertFalse,
  assertMatch,
  assertNotEquals,
  assertNotMatch,
  assertThrows,
} from '@std/assert'

/**
 * Asserts that a promise rejects with an `Error`. When `expectedMessage` is provided, the
 * error's message must include it — or, when an array is given, any one of the entries
 * (handy for messages that differ across runtimes). Returns the rejected error so callers
 * can make further assertions on it.
 */
export async function assertRejects(promise: Promise<unknown>, expectedMessage?: string | string[]): Promise<Error> {
  let error = undefined
  try {
    await promise
  } catch (err) {
    error = err
  }
  if (!error) throw new AssertionError('Promise did not reject')
  if (!(error instanceof Error)) throw new AssertionError('Rejected value is not an Error')
  if (expectedMessage !== undefined) {
    if (typeof expectedMessage === 'string') expectedMessage = [expectedMessage]
    const matches = expectedMessage.some((msg) => error.message.includes(msg))
    if (!matches) {
      throw new AssertionError(
        `Error message "${error.message}" does not include any of expected messages: ${expectedMessage.join(', ')}`,
      )
    }
  }
  return error
}
