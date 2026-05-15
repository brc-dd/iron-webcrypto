// deno-lint-ignore-file ban-ts-comment

import { assertEquals, AssertionError } from '@std/assert'
import { describe, it } from 'cross-bdd'
import * as Iron from 'iron-webcrypto'
import { randomBits } from '../src/keys.ts'

describe('Iron', () => {
  const obj = { a: 1, b: 2, c: [3, 4, 5], d: { e: 'f' } }
  const password = 'some_not_random_password_that_is_also_long_enough'

  it('turns object into a ticket then parses the ticket successfully', async () => {
    const sealed = await Iron.seal(obj, password, Iron.defaults)
    const unsealed = await Iron.unseal(sealed, { default: password }, Iron.defaults)
    assertEquals(unsealed, obj)
  })

  it('seals and unseals an object with expiration', async () => {
    const options = Iron.clone(Iron.defaults)
    options.ttl = 200
    const sealed = await Iron.seal(obj, password, options)
    const unsealed = await Iron.unseal(sealed, { default: password }, Iron.defaults)
    assertEquals(unsealed, obj)
  })

  it('seals and unseals an object with expiration and time offset', async () => {
    const options = Iron.clone(Iron.defaults)
    options.ttl = 200
    options.localtimeOffsetMsec = -100_000
    const sealed = await Iron.seal(obj, password, options)
    const options2 = Iron.clone(Iron.defaults)
    options2.localtimeOffsetMsec = -100_000
    const unsealed = await Iron.unseal(sealed, { default: password }, options2)
    assertEquals(unsealed, obj)
  })

  it('seals and unseals an object with expiration but no time offset', async () => {
    const options = Iron.clone(Iron.defaults)
    options.ttl = 200
    // @ts-expect-error
    delete options.localtimeOffsetMsec
    const sealed = await Iron.seal(obj, password, options)
    const options2 = Iron.clone(Iron.defaults)
    // @ts-expect-error
    delete options2.localtimeOffsetMsec
    const unsealed = await Iron.unseal(sealed, { default: password }, options2)
    assertEquals(unsealed, obj)
  })

  it('turns object into a ticket then parses the ticket successfully (password buffer)', async () => {
    const key = randomBits(256)
    const sealed = await Iron.seal(obj, key, Iron.defaults)
    const unsealed = await Iron.unseal(sealed, key, Iron.defaults)
    assertEquals(unsealed, obj)
  })

  it('turns object into a ticket then parses the ticket successfully (password buffer in object)', async () => {
    const key = randomBits(256)
    const sealed = await Iron.seal(obj, key, Iron.defaults)
    const unsealed = await Iron.unseal(sealed, { default: key }, Iron.defaults)
    assertEquals(unsealed, obj)
  })

  it('fails to turn object into a ticket (password buffer too short)', async () => {
    const key = randomBits(128)
    await assertRejects(Iron.seal(obj, key, Iron.defaults), 'Key buffer (password) too small')
  })

  it('fails to turn object into a ticket (failed to stringify object)', async () => {
    const cyclic: unknown[] = []
    cyclic[0] = cyclic
    const key = randomBits(128)
    await assertRejects(Iron.seal(cyclic, key, Iron.defaults), 'Data is not JSON serializable')
  })

  it('turns object into a ticket then parses the ticket successfully (password object)', async () => {
    const sealed = await Iron.seal(obj, { id: '1', secret: password }, Iron.defaults)
    const unsealed = await Iron.unseal(sealed, { '1': password }, Iron.defaults)
    assertEquals(unsealed, obj)
  })

  it('handles separate password buffers (password object)', async () => {
    const key = { id: '1', encryption: randomBits(256), integrity: randomBits(256) }
    const sealed = await Iron.seal(obj, key, Iron.defaults)
    const unsealed = await Iron.unseal(sealed, { '1': key }, Iron.defaults)
    assertEquals(unsealed, obj)
  })

  it('handles a common password buffer (password object)', async () => {
    const key = { id: '1', secret: randomBits(256) }
    const sealed = await Iron.seal(obj, key, Iron.defaults)
    const unsealed = await Iron.unseal(sealed, { '1': key }, Iron.defaults)
    assertEquals(unsealed, obj)
  })

  it('fails to parse a sealed object when password not found', async () => {
    const sealed = await Iron.seal(obj, { id: '1', secret: password }, Iron.defaults)
    await assertRejects(Iron.unseal(sealed, { '2': password }, Iron.defaults), 'Cannot find password: 1')
  })

  describe('seal()', () => {
    it('returns an error when password is missing', async () => {
      // @ts-expect-error
      await assertRejects(Iron.seal('data', null, Iron.defaults), 'Empty password')
    })

    it('returns an error when password is too short', async () => {
      await assertRejects(
        Iron.seal('data', 'password', Iron.defaults),
        'Password string too short (min 32 characters required)',
      )
    })

    it('returns an error when integrity options are missing', async () => {
      const options = Iron.clone(Iron.defaults)
      // @ts-expect-error
      options.integrity = {}
      await assertRejects(Iron.seal('data', password, options), 'Unknown algorithm: undefined')
    })

    it('returns an error when no salt and no salt bits are provided', async () => {
      const options = Iron.clone(Iron.defaults)
      // @ts-expect-error
      options.encryption.saltBits = undefined
      await assertRejects(Iron.seal('data', password, options), 'Missing salt and saltBits options')
    })

    it('returns an error when invalid salt bits are provided', async () => {
      const options = Iron.clone(Iron.defaults)
      options.encryption.saltBits = 999_999_999_999_999
      await assertRejects(Iron.seal('data', password, options), [
        'Invalid typed array length', // node
        'Array buffer allocation failed', // deno
        'length too large', // bun (older versions)
        'Out of memory', // bun
      ])
    })

    it('returns an error when password.id is invalid', async () => {
      await assertRejects(Iron.seal('data', { id: 'asd$', secret: 'asd' }, Iron.defaults), 'Invalid password id')
    })
  })

  describe('unseal()', () => {
    it('unseals a ticket', async () => {
      const ticket =
        'Fe26.2**0cdd607945dd1dffb7da0b0bf5f1a7daa6218cbae14cac51dcbd91fb077aeb5b*aOZLCKLhCt0D5IU1qLTtYw*g0ilNDlQ3TsdFUqJCqAm9iL7Wa60H7eYcHL_5oP136TOJREkS3BzheDC1dlxz5oJ**05b8943049af490e913bbc3a2485bee2aaf7b823f4c41d0ff0b7c168371a3772*R8yscVdTBRMdsoVbdDiFmUL8zb-c3PQLGJn4Y8C-AqI'
      const unsealed = await Iron.unseal(ticket, password, Iron.defaults)
      assertEquals(unsealed, obj)
    })

    it('unseals a aes-128-ctr ticket', async () => {
      const ticket =
        'Fe26.2**63c87cc87254b834dbb13cc62abc8713d1da035a9b38f54e5d5795135e217167*TpIsHHn-7txnl14Or7-D6A*HFGMGpcTRPUBSTQobuo27KOZ76MhVWgOsjA5SkFoy3vyqaHuixbd**3c8c403569a744a39c58adfb81e654f6860cb01f145488313e1895276e719f52*d5J1jY3WxP61klQza6q7zTqiYpjWPwocqHmjtDcSeq0'
      const options = Iron.clone(Iron.defaults)
      options.encryption.algorithm = 'aes-128-ctr'
      const unsealed = await Iron.unseal(ticket, password, options)
      assertEquals(unsealed, obj)
    })

    it('returns an error when number of sealed components is wrong', async () => {
      const ticket =
        'x*Fe26.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M**ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5*HfWzyJlz_UP9odmXvUaVK1TtdDuOCaezr-TAg2GjBCU'
      await assertRejects(Iron.unseal(ticket, password, Iron.defaults), 'Incorrect number of sealed components')
    })

    it('returns an error when password is missing', async () => {
      const ticket =
        'Fe26.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M**ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5*HfWzyJlz_UP9odmXvUaVK1TtdDuOCaezr-TAg2GjBCU'
      // @ts-expect-error
      await assertRejects(Iron.unseal(ticket, null, Iron.defaults), 'Empty password')
    })

    it('returns an error when mac prefix is wrong', async () => {
      const ticket =
        'Fe27.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M**ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5*HfWzyJlz_UP9odmXvUaVK1TtdDuOCaezr-TAg2GjBCU'
      await assertRejects(Iron.unseal(ticket, password, Iron.defaults), 'Wrong mac prefix')
    })

    it('returns an error when integrity check fails', async () => {
      const ticket =
        'Fe26.2**b3ad22402ccc60fa4d527f7d1c9ff2e37e9b2e5723e9e2ffba39a489e9849609*QKCeXLs6Rp7f4LL56V7hBg*OvZEoAq_nGOpA1zae-fAtl7VNCNdhZhCqo-hWFCBeWuTTpSupJ7LxQqzSQBRAcgw**72018a21d3fac5c1608a0f9e461de0fcf17b2befe97855978c17a793faa01db1*Qj53DFE3GZd5yigt-mVl9lnp0VUoSjh5a5jgDmod1EZ'
      await assertRejects(Iron.unseal(ticket, password, Iron.defaults), 'Bad hmac value')
    })

    it('returns an error when ciphertext base64 decoding fails', async () => {
      const parts = (await Iron.seal(obj, password, Iron.defaults)).split('*')
      parts[4] += '??' // mangle encrypted ciphertext (base64 decode runs before hmac verify)
      await assertRejects(Iron.unseal(parts.join('*'), password, Iron.defaults), [
        'Invalid character', // node
        'Found a character that cannot be part of a valid base64 string.', // deno
        'Uint8Array.fromBase64 requires a valid base64 string', // bun
      ])
    })

    it('returns an error when iv base64 decoding fails', async () => {
      const parts = (await Iron.seal(obj, password, Iron.defaults)).split('*')
      parts[3] += '??' // mangle iv (base64 decode runs before hmac verify)
      await assertRejects(Iron.unseal(parts.join('*'), password, Iron.defaults), [
        'Invalid character', // node
        'Found a character that cannot be part of a valid base64 string.', // deno
        'Uint8Array.fromBase64 requires a valid base64 string', // bun
      ])
    })

    it('returns an error when decrypted JSON is malformed', async () => {
      const options = Iron.clone(Iron.defaults)
      options.encode = () => '{asdasd'
      const ticket = await Iron.seal({}, password, options)
      await assertRejects(Iron.unseal(ticket, password, Iron.defaults), 'Failed parsing sealed object JSON')
    })

    it('returns an error when expired', async () => {
      const options = Iron.clone(Iron.defaults)
      options.ttl = 1
      const ticket = await Iron.seal(obj, password, options)
      const options2 = Iron.clone(Iron.defaults)
      options2.localtimeOffsetMsec = 70_000 // beyond ttl + timestampSkewSec
      await assertRejects(Iron.unseal(ticket, password, options2), 'Expired seal')
    })

    it('returns an error when expiration NaN', async () => {
      const parts = (await Iron.seal(obj, password, Iron.defaults)).split('*')
      parts[5] = 'a' // regex check rejects this before hmac verify
      await assertRejects(Iron.unseal(parts.join('*'), password, Iron.defaults), 'Invalid expiration')
    })
  })
})

async function assertRejects(promise: Promise<unknown>, expectedMessage: string | string[]): Promise<void> {
  let error = undefined
  try {
    await promise
  } catch (err) {
    error = err
  }
  if (!error) throw new AssertionError('Promise did not reject')
  if (!(error instanceof Error)) throw new AssertionError('Rejected value is not an Error')
  if (typeof expectedMessage === 'string') expectedMessage = [expectedMessage]
  const matches = expectedMessage.some((msg) => error.message.includes(msg))
  if (!matches) {
    throw new AssertionError(
      `Error message "${error.message}" does not include any of expected messages: ${expectedMessage.join(', ')}`,
    )
  }
}
