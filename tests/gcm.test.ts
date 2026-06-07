// deno-lint-ignore-file ban-ts-comment

import { describe, it } from 'cross-bdd'
import * as Iron from 'iron-webcrypto'
import * as Gcm from 'iron-webcrypto/gcm'
import { randomBits } from '../src/keys.ts'
import { assertEquals, assertNotEquals, assertRejects } from './assert.ts'

/**
 * Asserts a promise rejects with the runtime's native AES-GCM authentication failure. The GCM
 * endpoint no longer wraps this in a 'Bad hmac value' error — the Web Crypto spec mandates an
 * `OperationError` (a `DOMException`), and only its message wording differs across Deno/Node/Bun,
 * so we assert on the stable error name rather than the text.
 */
async function assertAuthFailure(promise: Promise<unknown>): Promise<void> {
  const err = await assertRejects(promise)
  assertEquals(err.name, 'OperationError')
}

describe('Iron (HKDF + AES-GCM)', () => {
  const obj = { a: 1, b: 2, c: [3, 4, 5], d: { e: 'f' } }
  const password = 'some_not_random_password_that_is_also_long_enough'
  const altPassword = 'another_password_that_is_also_definitely_long_enough'

  // Fe26.3 * id * salt * iv * ciphertext+tag * expiration
  const idPart = 1
  const saltPart = 2
  const ivPart = 3
  const ciphertextPart = 4
  const expirationPart = 5

  it('turns object into a ticket then parses the ticket successfully (no options)', async () => {
    const sealed = await Gcm.seal(obj, password)
    const unsealed = await Gcm.unseal(sealed, { default: password })
    assertEquals(unsealed, obj)
  })

  it('produces a six-component Fe26.3 ticket', async () => {
    const sealed = await Gcm.seal(obj, password)
    const parts = sealed.split('*')
    assertEquals(parts.length, 6)
    assertEquals(parts[0], Gcm.prefix)
    assertEquals(Gcm.prefix, 'Fe26.3')
    assertEquals(Gcm.prefix, 'Fe26.' + Gcm.formatVersion)
  })

  it('uses a fresh salt, nonce, and ciphertext for identical inputs (GCM nonce freshness)', async () => {
    // Reusing a (key, nonce) pair under AES-GCM is catastrophic, so two seals of the same
    // payload must never collide. This guards against a regression that pins or memoizes the IV.
    const a = Gcm.splitTicket(await Gcm.seal(obj, password))
    const b = Gcm.splitTicket(await Gcm.seal(obj, password))
    assertNotEquals(a[saltPart], b[saltPart])
    assertNotEquals(a[ivPart], b[ivPart])
    assertNotEquals(a[ciphertextPart], b[ciphertextPart])
    assertEquals(await Gcm.unseal(a.join('*'), password), obj)
    assertEquals(await Gcm.unseal(b.join('*'), password), obj)
  })

  it('seals and unseals an object with expiration', async () => {
    const sealed = await Gcm.seal(obj, password, { ttl: 200 })
    const unsealed = await Gcm.unseal(sealed, { default: password })
    assertEquals(unsealed, obj)
  })

  it('seals and unseals an object with expiration and time offset', async () => {
    const sealed = await Gcm.seal(obj, password, { ttl: 200, localtimeOffsetMsec: -100_000 })
    const unsealed = await Gcm.unseal(sealed, { default: password }, { localtimeOffsetMsec: -100_000 })
    assertEquals(unsealed, obj)
  })

  it('round-trips primitive and empty container values', async () => {
    for (const value of [null, true, false, 0, -1, 3.14, '', 'hello', '🚀', {}, [], [{}], { a: [] }]) {
      const sealed = await Gcm.seal(value, password)
      const unsealed = await Gcm.unseal(sealed, password)
      assertEquals(unsealed, value, `roundtrip failed for ${JSON.stringify(value)}`)
    }
  })

  it('turns object into a ticket then parses the ticket successfully (password buffer)', async () => {
    const key = randomBits(256)
    const sealed = await Gcm.seal(obj, key)
    const unsealed = await Gcm.unseal(sealed, key)
    assertEquals(unsealed, obj)
  })

  it('omits the salt for raw key buffers', async () => {
    const key = randomBits(256)
    const sealed = await Gcm.seal(obj, key)
    assertEquals(sealed.split('*')[saltPart], '')
  })

  it('turns object into a ticket then parses the ticket successfully (password buffer in object)', async () => {
    const key = randomBits(256)
    const sealed = await Gcm.seal(obj, key)
    const unsealed = await Gcm.unseal(sealed, { default: key })
    assertEquals(unsealed, obj)
  })

  it('fails to turn object into a ticket (password buffer too short)', async () => {
    const key = randomBits(128)
    await assertRejects(Gcm.seal(obj, key), 'Key buffer (password) too small')
  })

  it('fails to turn object into a ticket (failed to stringify object)', async () => {
    const cyclic: unknown[] = []
    cyclic[0] = cyclic
    await assertRejects(Gcm.seal(cyclic, password), 'Data is not JSON serializable')
  })

  it('turns object into a ticket then parses the ticket successfully (password object)', async () => {
    const sealed = await Gcm.seal(obj, { id: '1', secret: password })
    const unsealed = await Gcm.unseal(sealed, { '1': password })
    assertEquals(unsealed, obj)
  })

  it('handles a common password buffer (password object)', async () => {
    const key = { id: '1', secret: randomBits(256) }
    const sealed = await Gcm.seal(obj, key)
    const unsealed = await Gcm.unseal(sealed, { '1': key })
    assertEquals(unsealed, obj)
  })

  it('rejects a split encryption/integrity password (Specific is not supported)', async () => {
    // GCM derives a single key, so the CBC scheme's split-secret form has no GcmPassword variant.
    // @ts-expect-error - GcmPassword has no Specific (split encryption/integrity) form
    await assertRejects(Gcm.seal(obj, { encryption: password, integrity: password }), 'Empty password')
  })

  it('fails to parse a sealed object when password not found', async () => {
    const sealed = await Gcm.seal(obj, { id: '1', secret: password })
    await assertRejects(Gcm.unseal(sealed, { '2': password }), 'Cannot find password: 1')
  })

  describe('seal()', () => {
    it('returns an error when password is missing', async () => {
      // @ts-expect-error
      await assertRejects(Gcm.seal('data', null), 'Empty password')
    })

    it('returns an error when password is too short', async () => {
      await assertRejects(Gcm.seal('data', 'password'), 'Password string too short (min 32 characters required)')
    })

    it('returns an error when password.id is invalid', async () => {
      await assertRejects(Gcm.seal('data', { id: 'asd$', secret: 'asd' }), 'Invalid password id')
    })
  })

  describe('unseal()', () => {
    it('returns an error when number of sealed components is wrong', async () => {
      const ticket = await Gcm.seal(obj, password) + '*extra'
      await assertRejects(Gcm.unseal(ticket, password), 'Incorrect number of sealed components')
    })

    it('returns an error when password is missing', async () => {
      const ticket = await Gcm.seal(obj, password)
      // @ts-expect-error
      await assertRejects(Gcm.unseal(ticket, null), 'Empty password')
    })

    it('returns an error when the prefix is wrong (e.g. an older Fe26.2 version)', async () => {
      const parts = Gcm.splitTicket(await Gcm.seal(obj, password))
      parts[0] = 'Fe26.2'
      await assertRejects(Gcm.unseal(parts.join('*'), password), 'Wrong prefix')
    })

    it('returns an error when the authentication tag fails (tampered ciphertext)', async () => {
      const parts = Gcm.splitTicket(await Gcm.seal(obj, password))
      // Flip the leading base64url char of the ciphertext while keeping it decodable.
      parts[ciphertextPart] = (parts[ciphertextPart][0] === 'A' ? 'B' : 'A') + parts[ciphertextPart].slice(1)
      await assertAuthFailure(Gcm.unseal(parts.join('*'), password))
    })

    it('returns an error when the salt is tampered (derives a different key)', async () => {
      // The salt is an HKDF key-derivation input, so changing it derives a different key and
      // decryption fails on the tag — this proves key-derivation sensitivity, not AAD binding.
      // (The id- and expiration-tamper tests below cover AAD binding for AAD-only fields.)
      const parts = Gcm.splitTicket(await Gcm.seal(obj, password))
      parts[saltPart] = parts[saltPart].slice(0, -1) + (parts[saltPart].endsWith('a') ? 'b' : 'a')
      await assertAuthFailure(Gcm.unseal(parts.join('*'), password))
    })

    it('returns an error when bound metadata is tampered (expiration)', async () => {
      const parts = Gcm.splitTicket(await Gcm.seal(obj, password))
      parts[expirationPart] = '9999999999999' // valid, far-future, but not what was authenticated
      await assertAuthFailure(Gcm.unseal(parts.join('*'), password))
    })

    it('returns an error when the password id is tampered (AAD-only binding)', async () => {
      // The id never feeds key derivation — it is authenticated solely through the AAD. Register
      // the same secret under both ids so the lookup succeeds and the only failure left is the tag.
      const parts = Gcm.splitTicket(await Gcm.seal(obj, { id: '1', secret: password }))
      parts[idPart] = '2'
      await assertAuthFailure(Gcm.unseal(parts.join('*'), { '1': password, '2': password }))
    })

    it('detects a wrong encryption key (AEAD advantage over CBC + HMAC)', async () => {
      const sealed = await Gcm.seal(obj, password)
      await assertAuthFailure(Gcm.unseal(sealed, altPassword))
    })

    it('returns an error when ciphertext base64 decoding fails', async () => {
      const parts = Gcm.splitTicket(await Gcm.seal(obj, password))
      parts[ciphertextPart] += '??'
      await assertRejects(Gcm.unseal(parts.join('*'), password), [
        'Invalid character', // node
        'Found a character that cannot be part of a valid base64 string.', // deno
        'Uint8Array.fromBase64 requires a valid base64 string', // bun
      ])
    })

    it('returns an error when iv base64 decoding fails', async () => {
      const parts = Gcm.splitTicket(await Gcm.seal(obj, password))
      parts[ivPart] += '??'
      await assertRejects(Gcm.unseal(parts.join('*'), password), [
        'Invalid character', // node
        'Found a character that cannot be part of a valid base64 string.', // deno
        'Uint8Array.fromBase64 requires a valid base64 string', // bun
      ])
    })

    it('returns an error when decrypted JSON is malformed', async () => {
      const ticket = await Gcm.seal({}, password, { encode: () => '{asdasd' })
      await assertRejects(Gcm.unseal(ticket, password), 'Failed parsing sealed object JSON')
    })

    it('returns an error when expired', async () => {
      const ticket = await Gcm.seal(obj, password, { ttl: 1 })
      // localtimeOffsetMsec pushes "now" beyond ttl + the default timestampSkewSec (60s).
      await assertRejects(Gcm.unseal(ticket, password, { localtimeOffsetMsec: 70_000 }), 'Expired seal')
    })

    it('returns an error when expiration NaN', async () => {
      const parts = Gcm.splitTicket(await Gcm.seal(obj, password))
      parts[expirationPart] = 'a' // regex check rejects this before decryption
      await assertRejects(Gcm.unseal(parts.join('*'), password), 'Invalid expiration')
    })
  })

  describe('cross-scheme isolation', () => {
    it('a GCM ticket cannot be unsealed by the CBC scheme', async () => {
      const ticket = await Gcm.seal(obj, password)
      await assertRejects(Iron.unseal(ticket, password, Iron.defaults), 'Incorrect number of sealed components')
    })

    it('a CBC ticket cannot be unsealed by the GCM scheme', async () => {
      const ticket = await Iron.seal(obj, password, Iron.defaults)
      await assertRejects(Gcm.unseal(ticket, password), 'Incorrect number of sealed components')
    })
  })
})
