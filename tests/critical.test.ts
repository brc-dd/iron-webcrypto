// deno-lint-ignore-file ban-ts-comment

import { describe, it } from 'cross-bdd'
import * as Iron from 'iron-webcrypto'
import { algorithms, randomBits } from '../src/keys.ts'
import { isJson, losslessJsonStringify } from '../src/utils.ts'
import {
  assert,
  assertEquals,
  assertExists,
  assertFalse,
  assertMatch,
  assertNotEquals,
  assertNotMatch,
  assertRejects,
  assertThrows,
} from './assert.ts'

const PASSWORD = 'some_not_random_password_that_is_also_long_enough'
const ALT_PASSWORD = 'another_password_that_is_also_definitely_long_enough'

// ---------------------------------------------------------------------------
// Round-trip correctness for various data shapes
// ---------------------------------------------------------------------------

describe('round-trip correctness', () => {
  it('preserves primitive top-level values', async () => {
    for (const value of [null, true, false, 0, -1, 3.14159, '', 'hello', '123', '🚀']) {
      const sealed = await Iron.seal(value, PASSWORD, Iron.defaults)
      const unsealed = await Iron.unseal(sealed, PASSWORD, Iron.defaults)
      assertEquals(unsealed, value, `roundtrip failed for ${JSON.stringify(value)}`)
    }
  })

  it('preserves empty container shapes', async () => {
    for (const value of [{}, [], [[]], [{}], { a: {} }, { a: [] }]) {
      const sealed = await Iron.seal(value, PASSWORD, Iron.defaults)
      const unsealed = await Iron.unseal(sealed, PASSWORD, Iron.defaults)
      assertEquals(unsealed, value)
    }
  })

  it('preserves deeply nested objects and arrays', async () => {
    // Linear depth — avoid aliased subtrees which would explode JSON output.
    let obj: Record<PropertyKey, unknown> = { d: 'leaf' }
    for (let i = 0; i < 50; i++) obj = { d: obj }
    let arr: unknown[] = ['leaf']
    for (let i = 0; i < 50; i++) arr = [arr]
    const payload = { obj, arr }
    const sealed = await Iron.seal(payload, PASSWORD, Iron.defaults)
    const unsealed = await Iron.unseal(sealed, PASSWORD, Iron.defaults)
    assertEquals(unsealed, payload)
  })

  it('preserves Unicode (BMP, supplementary planes, emoji, control chars)', async () => {
    const payload = {
      ascii: 'hello world',
      bmp: 'résumé über naïve',
      supplementary: '\u{1F600}\u{1F4A9}\u{1F1FA}\u{1F1F8}', // emoji + flag (surrogate pairs)
      cjk: '日本語テスト中文',
      rtl: 'שלום العالم',
      control: '\b\t\n\r\f',
      quote: 'has "double" and \'single\' and \\ backslash',
      separator: 'contains * star * characters', // ensure value strings aren't misparsed
    }
    const sealed = await Iron.seal(payload, PASSWORD, Iron.defaults)
    const unsealed = await Iron.unseal(sealed, PASSWORD, Iron.defaults)
    assertEquals(unsealed, payload)
  })

  it('preserves large payloads (~256 KiB)', async () => {
    const big = { blob: 'x'.repeat(256 * 1024), arr: Array.from({ length: 1000 }, (_, i) => i) }
    const sealed = await Iron.seal(big, PASSWORD, Iron.defaults)
    const unsealed = (await Iron.unseal(sealed, PASSWORD, Iron.defaults)) as typeof big
    assertEquals(unsealed.arr, big.arr)
    assertEquals(unsealed.blob.length, big.blob.length)
  })

  it('produces different ciphertexts for identical payloads (random salt+IV)', async () => {
    const sealed1 = await Iron.seal({ a: 1 }, PASSWORD, Iron.defaults)
    const sealed2 = await Iron.seal({ a: 1 }, PASSWORD, Iron.defaults)
    assertNotEquals(sealed1, sealed2, 'two seals of the same payload must differ')
    const parts1 = Iron.splitTicket(sealed1)
    const parts2 = Iron.splitTicket(sealed2)
    assertNotEquals(parts1[2], parts2[2], 'encryption salt should be random')
    assertNotEquals(parts1[3], parts2[3], 'iv should be random')
    assertNotEquals(parts1[6], parts2[6], 'hmac salt should be random')
  })

  it('uses URL-safe base64 (no + / = characters)', async () => {
    for (let i = 0; i < 30; i++) {
      const sealed = await Iron.seal({ rand: Math.random(), i }, PASSWORD, Iron.defaults)
      assertNotMatch(sealed, /[+/=]/, `unexpected non-url-safe char in ticket: ${sealed}`)
    }
  })

  it('roundtrips with aes-128-ctr', async () => {
    const options = Iron.clone(Iron.defaults)
    options.encryption.algorithm = 'aes-128-ctr'
    const sealed = await Iron.seal({ msg: 'ctr-mode' }, PASSWORD, options)
    const unsealed = await Iron.unseal(sealed, PASSWORD, options)
    assertEquals(unsealed, { msg: 'ctr-mode' })
  })

  it('roundtrips with raw Uint8Array passwords of exact key length', async () => {
    const key = randomBits(256)
    const sealed = await Iron.seal({ ok: true }, key, Iron.defaults)
    const unsealed = await Iron.unseal(sealed, key, Iron.defaults)
    assertEquals(unsealed, { ok: true })
  })

  it('emits a ticket with the documented Fe26.2 prefix and 8 * components', async () => {
    const sealed = await Iron.seal({ x: 1 }, PASSWORD, Iron.defaults)
    assert(sealed.startsWith('Fe26.2*'), `prefix missing: ${sealed.slice(0, 12)}`)
    assertEquals(sealed.split('*').length, 8)
  })
})

// ---------------------------------------------------------------------------
// JSON validator (isJson / losslessJsonStringify)
// ---------------------------------------------------------------------------

describe('lossless JSON validator', () => {
  it('rejects NaN, Infinity, -Infinity', () => {
    for (const v of [NaN, Infinity, -Infinity]) {
      assertFalse(isJson(v), `expected ${v} to be rejected`)
      assertThrows(() => losslessJsonStringify(v), `expected losslessJsonStringify(${v}) to throw`)
    }
  })

  it('rejects BigInt', () => {
    assertFalse(isJson(1n))
  })

  it('rejects Symbol values and Symbol-keyed properties', () => {
    assertFalse(isJson(Symbol('x')))
    const obj: Record<PropertyKey, unknown> = { a: 1 }
    obj[Symbol('hidden')] = 2
    // Reflect.ownKeys != Object.keys -> rejected
    assertFalse(isJson(obj))
  })

  it('rejects Functions', () => {
    assertFalse(isJson(() => 1))
    assertFalse(isJson({ fn: () => 1 }))
  })

  it('rejects non-plain objects (Map, Set, Date, RegExp, class instances)', () => {
    class Foo {
      x = 1
    }
    for (const v of [new Map(), new Set(), new Date(), /re/, new Foo()]) {
      assertFalse(isJson(v), `expected ${v} to be rejected`)
    }
  })

  it('rejects undefined elements in arrays (since JSON.stringify silently turns them into null)', () => {
    const arr = [1, 2]
    arr[5] = 3 // sparse array - holes
    assertFalse(isJson([1, undefined, 2]))
    // Sparse arrays read holes as undefined; should also be rejected.
    assertFalse(isJson(arr))
  })

  it('allows undefined values in object positions (they are dropped by JSON.stringify)', () => {
    assert(isJson({ a: 1, b: undefined }))
  })

  it('rejects non-enumerable own properties', () => {
    const obj = {}
    Object.defineProperty(obj, 'hidden', { value: 1, enumerable: false })
    assertFalse(isJson(obj))
  })

  it('allows null-prototype objects (Object.create(null))', () => {
    const obj = Object.create(null)
    obj.a = 1
    assert(isJson(obj))
  })

  it('rejects circular references (via JSON.stringify throwing in losslessJsonStringify)', () => {
    const a: Record<PropertyKey, unknown> = {}
    a.self = a
    // isJson allows aliasing/cycles at the type-level check, but JSON.stringify
    // will throw — losslessJsonStringify catches that and reports the right error.
    assertThrows(() => losslessJsonStringify(a), Error, 'not JSON serializable')
  })

  it('allows DAG-style aliasing (same reference reused but not cyclic)', async () => {
    const shared = { v: 1 }
    const payload = { a: shared, b: shared }
    const sealed = await Iron.seal(payload, PASSWORD, Iron.defaults)
    const unsealed = await Iron.unseal(sealed, PASSWORD, Iron.defaults)
    // Decoded structure is structurally equal (aliasing collapses to two copies).
    assertEquals(unsealed, { a: { v: 1 }, b: { v: 1 } })
  })

  it('rejects values that JSON.stringify returns undefined for (e.g. bare undefined, function)', () => {
    assertThrows(() => losslessJsonStringify(undefined), 'bare undefined should be rejected')
  })
})

// ---------------------------------------------------------------------------
// Tamper resistance: every part of the ticket must be MAC-bound
// ---------------------------------------------------------------------------

describe('tamper resistance', () => {
  async function tamperedTicket(idx: number, transform: (s: string) => string): Promise<string> {
    const parts = Iron.splitTicket(await Iron.seal({ secret: 42 }, PASSWORD, Iron.defaults))
    parts[idx] = transform(parts[idx]!)
    return parts.join('*')
  }

  it('rejects mutated prefix', async () => {
    const bad = await tamperedTicket(0, () => 'Fe26.1')
    await assertRejects(Iron.unseal(bad, PASSWORD, Iron.defaults), 'Wrong mac prefix')
  })

  it('rejects mutated passwordId (HMAC binds passwordId)', async () => {
    // Use a passwordId-bearing seal so we can change the id slot.
    const parts = Iron.splitTicket(await Iron.seal({ x: 1 }, { id: 'alpha', secret: PASSWORD }, Iron.defaults))
    parts[1] = 'beta'
    await assertRejects(
      Iron.unseal(parts.join('*'), { alpha: PASSWORD, beta: PASSWORD }, Iron.defaults),
      'Bad hmac value',
    )
  })

  it('rejects mutated encryption salt', async () => {
    const bad = await tamperedTicket(2, (s) => s.replace(/^./, (c) => (c === '0' ? '1' : '0')))
    await assertRejects(Iron.unseal(bad, PASSWORD, Iron.defaults), 'Bad hmac value')
  })

  it('rejects mutated IV (after base64 still-valid)', async () => {
    // Flip one byte of the IV by swapping a character with another base64url char.
    const bad = await tamperedTicket(3, (s) => {
      const swap = s[0] === 'A' ? 'B' : 'A'
      return swap + s.slice(1)
    })
    await assertRejects(Iron.unseal(bad, PASSWORD, Iron.defaults), 'Bad hmac value')
  })

  it('rejects mutated ciphertext', async () => {
    const bad = await tamperedTicket(4, (s) => {
      const swap = s[0] === 'A' ? 'B' : 'A'
      return swap + s.slice(1)
    })
    await assertRejects(Iron.unseal(bad, PASSWORD, Iron.defaults), 'Bad hmac value')
  })

  it('rejects forged expiration (introducing a future timestamp into a non-expiring ticket)', async () => {
    // Original ticket has no ttl, so expiration is ''. Forging a value here
    // must fail HMAC since the MAC base string was computed with ''.
    const bad = await tamperedTicket(5, () => `${Date.now() + 1_000_000}`)
    await assertRejects(Iron.unseal(bad, PASSWORD, Iron.defaults), 'Bad hmac value')
  })

  it('rejects mutated HMAC salt (derives a different verification key)', async () => {
    const bad = await tamperedTicket(6, (s) => s.replace(/^./, (c) => (c === '0' ? '1' : '0')))
    await assertRejects(Iron.unseal(bad, PASSWORD, Iron.defaults), 'Bad hmac value')
  })

  it('rejects mutated HMAC digest', async () => {
    const bad = await tamperedTicket(7, (s) => {
      const swap = s[0] === 'A' ? 'B' : 'A'
      return swap + s.slice(1)
    })
    await assertRejects(Iron.unseal(bad, PASSWORD, Iron.defaults), 'Bad hmac value')
  })

  it('rejects ticket sealed with wrong password (HMAC mismatch, not a decryption oracle)', async () => {
    const sealed = await Iron.seal({ secret: 42 }, PASSWORD, Iron.defaults)
    await assertRejects(Iron.unseal(sealed, ALT_PASSWORD, Iron.defaults), 'Bad hmac value')
  })

  it('rejects truncated tickets (too few * separators)', async () => {
    const sealed = await Iron.seal({ x: 1 }, PASSWORD, Iron.defaults)
    await assertRejects(
      Iron.unseal(sealed.split('*').slice(0, 7).join('*'), PASSWORD, Iron.defaults),
      'Incorrect number of sealed components',
    )
  })

  it('rejects tickets with extra * separators', async () => {
    const sealed = await Iron.seal({ x: 1 }, PASSWORD, Iron.defaults)
    await assertRejects(
      Iron.unseal(sealed + '*extra', PASSWORD, Iron.defaults),
      'Incorrect number of sealed components',
    )
  })

  it('rejects empty string ticket', async () => {
    await assertRejects(Iron.unseal('', PASSWORD, Iron.defaults), 'Incorrect number of sealed components')
  })

  it('reports HMAC failure before decryption error (no decryption oracle on tampered tickets)', async () => {
    // Sanity: when both MAC and ciphertext have been mangled, only the
    // generic 'Bad hmac value' should leak — never a CBC padding error.
    const parts = Iron.splitTicket(await Iron.seal({ x: 1 }, PASSWORD, Iron.defaults))
    parts[4] = parts[4].replace(/^./, (c) => (c === 'A' ? 'B' : 'A'))
    parts[7] = parts[7].replace(/^./, (c) => (c === 'A' ? 'B' : 'A'))
    const err = await assertRejects(Iron.unseal(parts.join('*'), PASSWORD, Iron.defaults), 'Bad hmac value')
    // Make sure no padding info leaks
    assertNotMatch(err.message, /padding|pad block|bad decrypt/i, `leak suspected: ${err.message}`)
  })
})

// ---------------------------------------------------------------------------
// Password normalization, rotation, and identification
// ---------------------------------------------------------------------------

describe('password handling', () => {
  it('supports password rotation by id (matching key found in the hash)', async () => {
    const sealed = await Iron.seal({ k: 1 }, { id: 'k2024', secret: PASSWORD }, Iron.defaults)
    const unsealed = await Iron.unseal(sealed, { k2023: ALT_PASSWORD, k2024: PASSWORD }, Iron.defaults)
    assertEquals(unsealed, { k: 1 })
  })

  it('fails clearly when the passwordId cannot be resolved in the hash', async () => {
    const sealed = await Iron.seal({ k: 1 }, { id: 'k2024', secret: PASSWORD }, Iron.defaults)
    await assertRejects(Iron.unseal(sealed, { k2023: ALT_PASSWORD }, Iron.defaults), 'Cannot find password: k2024')
  })

  it('treats an id-less seal as the "default" key in a hash on unseal', async () => {
    const sealed = await Iron.seal({ k: 1 }, PASSWORD, Iron.defaults)
    const unsealed = await Iron.unseal(sealed, { default: PASSWORD }, Iron.defaults)
    assertEquals(unsealed, { k: 1 })
  })

  it('rejects empty Uint8Array password', async () => {
    await assertRejects(Iron.seal({ x: 1 }, new Uint8Array(0), Iron.defaults), 'Empty password')
  })

  it('rejects too-short Uint8Array password for AES-256', async () => {
    await assertRejects(Iron.seal({ x: 1 }, randomBits(128), Iron.defaults), 'Key buffer (password) too small')
  })

  it('accepts a Uint8Array of minimum size for AES-256 (32 bytes)', async () => {
    const sealed = await Iron.seal({ ok: 1 }, new Uint8Array(32).fill(7), Iron.defaults)
    const unsealed = await Iron.unseal(sealed, new Uint8Array(32).fill(7), Iron.defaults)
    assertEquals(unsealed, { ok: 1 })
  })

  it('accepts AES-128-CTR with 16-byte key', async () => {
    const options = Iron.clone(Iron.defaults)
    options.encryption.algorithm = 'aes-128-ctr'
    const encKey = new Uint8Array(16).fill(3)
    const intKey = new Uint8Array(32).fill(5)
    const sealed = await Iron.seal({ ok: 1 }, { id: 'k', encryption: encKey, integrity: intKey }, options)
    const unsealed = await Iron.unseal(sealed, { k: { id: 'k', encryption: encKey, integrity: intKey } }, options)
    assertEquals(unsealed, { ok: 1 })
  })

  it('rejects AES-128-CTR with a too-short buffer', async () => {
    const options = Iron.clone(Iron.defaults)
    options.encryption.algorithm = 'aes-128-ctr'
    const sealed = Iron.seal(
      { x: 1 },
      { id: 'k', encryption: new Uint8Array(8), integrity: new Uint8Array(32).fill(5) },
      options,
    )
    await assertRejects(sealed, 'Key buffer (password) too small')
  })

  it('rejects password with non-word-character id (invalid id)', async () => {
    const cases = [
      'has space',
      'has-hyphen',
      'has.period',
      'has*star',
      'has/slash',
      'has+plus',
      'has\nnewline',
      'has\ttab',
      '🚀',
    ]
    for (const id of cases) {
      await assertRejects(Iron.seal({ x: 1 }, { id, secret: PASSWORD }, Iron.defaults), 'Invalid password id')
    }
  })

  it('accepts password id consisting only of word chars (alnum + underscore)', async () => {
    for (const id of ['a', 'A1', 'k_2024', '___', '0', 'longerKey42']) {
      const sealed = await Iron.seal({ x: 1 }, { id, secret: PASSWORD }, Iron.defaults)
      const unsealed = await Iron.unseal(sealed, { [id]: PASSWORD }, Iron.defaults)
      assertEquals(unsealed, { x: 1 })
    }
  })

  it('rejects Specific password with empty encryption secret', async () => {
    await assertRejects(
      Iron.seal({ x: 1 }, { id: 'k', encryption: '', integrity: PASSWORD }, Iron.defaults),
      'Empty password',
    )
  })

  it('rejects Specific password with empty integrity secret', async () => {
    await assertRejects(
      Iron.seal({ x: 1 }, { id: 'k', encryption: PASSWORD, integrity: '' }, Iron.defaults),
      'Empty password',
    )
  })

  it('uses the `secret` field even when `encryption`/`integrity` are also present (Secret takes precedence)', async () => {
    // 'secret' in password short-circuits the normalization, so a stray encryption/integrity field is ignored.
    const sealed = await Iron.seal(
      { x: 1 },
      { id: 'k', secret: PASSWORD, encryption: 'wrongA', integrity: 'wrongB' },
      Iron.defaults,
    )
    const unsealed = await Iron.unseal(sealed, PASSWORD, Iron.defaults)
    assertEquals(unsealed, { x: 1 })
  })

  it('handles Specific password with different encryption and integrity secrets', async () => {
    const key = {
      id: 'split',
      encryption: 'this_is_a_long_encryption_secret___________',
      integrity: 'this_is_a_different_long_integrity_secret___',
    }
    const sealed = await Iron.seal({ a: 1 }, key, Iron.defaults)
    const unsealed = await Iron.unseal(sealed, { split: key }, Iron.defaults)
    assertEquals(unsealed, { a: 1 })
  })

  it('rejects ticket sealed with split encryption/integrity but unsealed with only one of them', async () => {
    const encryption = 'this_is_a_long_encryption_secret___________'
    const integrity = 'this_is_a_different_long_integrity_secret___'
    const sealed = await Iron.seal({ a: 1 }, { id: 'split', encryption, integrity }, Iron.defaults)
    // Swapped secrets in lookup -> HMAC verification key differs -> reject.
    await assertRejects(
      Iron.unseal(sealed, { split: { id: 'split', encryption: integrity, integrity: encryption } }, Iron.defaults),
      'Bad hmac value',
    )
  })

  it('rejects undefined password on both seal and unseal', async () => {
    // @ts-expect-error
    await assertRejects(Iron.seal({ x: 1 }, undefined, Iron.defaults), 'Empty password')
    const sealed = await Iron.seal({ x: 1 }, PASSWORD, Iron.defaults)
    // @ts-expect-error
    await assertRejects(Iron.unseal(sealed, undefined, Iron.defaults), 'Empty password')
  })

  it('rejects numeric / boolean / empty-object passwords', async () => {
    // deno-lint-ignore no-explicit-any
    for (const pw of [0, false, true, 123, {}] as any[]) {
      await assertRejects(Iron.seal({ x: 1 }, pw, Iron.defaults), 'Empty password')
    }
  })
})

// ---------------------------------------------------------------------------
// Expiration / TTL semantics
// ---------------------------------------------------------------------------

describe('expiration', () => {
  it('does not embed an expiration when ttl=0', async () => {
    const sealed = await Iron.seal({ x: 1 }, PASSWORD, Iron.defaults)
    const parts = Iron.splitTicket(sealed)
    assertEquals(parts[5], '', 'expiration field must be empty when ttl=0')
  })

  it('embeds an expiration when ttl>0', async () => {
    const options = Iron.clone(Iron.defaults)
    options.ttl = 60_000
    const sealed = await Iron.seal({ x: 1 }, PASSWORD, options)
    const parts = Iron.splitTicket(sealed)
    assert(parts[5].length > 0, 'expiration field must be populated when ttl>0')
    assertMatch(parts[5], /^[1-9]\d*$/, `expiration should be a positive integer; got "${parts[5]}"`)
  })

  it('rejects ticket where expiration was reformatted as "0" (regex rejects leading zero)', async () => {
    const options = Iron.clone(Iron.defaults)
    options.ttl = 60_000
    const parts = Iron.splitTicket(await Iron.seal({ x: 1 }, PASSWORD, options))
    parts[5] = '0'
    await assertRejects(Iron.unseal(parts.join('*'), PASSWORD, options), 'Invalid expiration')
  })

  it('rejects expiration with leading zero', async () => {
    const options = Iron.clone(Iron.defaults)
    options.ttl = 60_000
    const parts = Iron.splitTicket(await Iron.seal({ x: 1 }, PASSWORD, options))
    parts[5] = '0' + parts[5]
    await assertRejects(Iron.unseal(parts.join('*'), PASSWORD, options), 'Invalid expiration')
  })

  it('rejects expiration with non-digit characters', async () => {
    const options = Iron.clone(Iron.defaults)
    options.ttl = 60_000
    const parts = Iron.splitTicket(await Iron.seal({ x: 1 }, PASSWORD, options))
    parts[5] = '12.34'
    await assertRejects(Iron.unseal(parts.join('*'), PASSWORD, options), 'Invalid expiration')
  })

  it('rejects expiration "-1" (no negative numbers allowed)', async () => {
    const options = Iron.clone(Iron.defaults)
    options.ttl = 60_000
    const parts = Iron.splitTicket(await Iron.seal({ x: 1 }, PASSWORD, options))
    parts[5] = '-1'
    await assertRejects(Iron.unseal(parts.join('*'), PASSWORD, options), 'Invalid expiration')
  })

  it('accepts a ticket just inside the allowed clock skew window', async () => {
    const options = Iron.clone(Iron.defaults)
    options.ttl = 1 // expires almost immediately
    const sealed = await Iron.seal({ x: 1 }, PASSWORD, options)
    // Pretend our clock is ahead by less than (ttl + skew). Should still be valid.
    const unsealOpts = Iron.clone(Iron.defaults)
    unsealOpts.localtimeOffsetMsec = 1_000 // 1s ahead, well within 60s skew
    const unsealed = await Iron.unseal(sealed, PASSWORD, unsealOpts)
    assertEquals(unsealed, { x: 1 })
  })

  it('rejects an expired ticket beyond the skew window', async () => {
    const options = Iron.clone(Iron.defaults)
    options.ttl = 1
    const sealed = await Iron.seal({ x: 1 }, PASSWORD, options)
    const unsealOpts = Iron.clone(Iron.defaults)
    unsealOpts.localtimeOffsetMsec = 120_000 // far beyond ttl + skew
    await assertRejects(Iron.unseal(sealed, PASSWORD, unsealOpts), 'Expired seal')
  })

  it('expiration check happens before HMAC verify (defense in depth)', async () => {
    // If we hand-craft an expired ticket and also break the HMAC, we should
    // see the 'Expired seal' message — this confirms expiry is cheap-checked
    // up front and avoids spending crypto time on stale junk.
    const options = Iron.clone(Iron.defaults)
    options.ttl = 1
    const sealed = await Iron.seal({ x: 1 }, PASSWORD, options)
    const parts = Iron.splitTicket(sealed)
    parts[7] = 'A'.repeat(parts[7].length) // garbage digest
    const unsealOpts = Iron.clone(Iron.defaults)
    unsealOpts.localtimeOffsetMsec = 120_000
    await assertRejects(Iron.unseal(parts.join('*'), PASSWORD, unsealOpts), 'Expired seal')
  })

  it('does not check expiration when expiration field is empty (ttl=0 tickets are perpetual)', async () => {
    const sealed = await Iron.seal({ x: 1 }, PASSWORD, Iron.defaults)
    // Even with a wildly skewed clock the ticket should still validate.
    const opts = Iron.clone(Iron.defaults)
    opts.localtimeOffsetMsec = 1_000_000_000
    const unsealed = await Iron.unseal(sealed, PASSWORD, opts)
    assertEquals(unsealed, { x: 1 })
  })
})

// ---------------------------------------------------------------------------
// Algorithm confusion / option drift
// ---------------------------------------------------------------------------

describe('algorithm and option binding', () => {
  it('rejects ticket sealed with aes-256-cbc when unsealed under aes-128-ctr options', async () => {
    const sealed = await Iron.seal({ x: 1 }, PASSWORD, Iron.defaults)
    const altOpts = Iron.clone(Iron.defaults)
    altOpts.encryption.algorithm = 'aes-128-ctr'
    // HMAC base string doesn't include the algorithm name, but the encryption
    // key derivation differs (key length 128 vs 256). The library should
    // produce *some* error rather than silently returning garbled data.
    await assertRejects(Iron.unseal(sealed, PASSWORD, altOpts))
  })

  it('rejects ticket where the integrity algorithm name was changed (unknown algorithm)', async () => {
    const sealed = await Iron.seal({ x: 1 }, PASSWORD, Iron.defaults)
    const altOpts = Iron.clone(Iron.defaults)
    // @ts-expect-error
    altOpts.integrity.algorithm = 'sha512'
    await assertRejects(Iron.unseal(sealed, PASSWORD, altOpts), 'Unknown algorithm: sha512')
  })

  it('rejects unknown encryption algorithm at seal time', async () => {
    const opts = Iron.clone(Iron.defaults)
    // @ts-expect-error
    opts.encryption.algorithm = 'rot13'
    await assertRejects(Iron.seal({ x: 1 }, PASSWORD, opts), 'Unknown algorithm: rot13')
  })

  it('exposes the supported algorithms metadata as readonly', () => {
    assertEquals(algorithms['aes-256-cbc'].keyBits, 256)
    assertEquals(algorithms['aes-256-cbc'].ivBits, 128)
    assertEquals(algorithms['aes-128-ctr'].keyBits, 128)
    assertEquals(algorithms['aes-128-ctr'].ivBits, 128)
    assertEquals(algorithms['sha256'].keyBits, 256)
    assertEquals(algorithms['sha256'].ivBits, undefined)
  })

  it('seals with different iteration counts produce different ciphertexts (iteration count affects key derivation)', async () => {
    const a = Iron.clone(Iron.defaults)
    a.encryption.iterations = 1
    const b = Iron.clone(Iron.defaults)
    b.encryption.iterations = 5
    // Same fixed salt/iv so iteration count is the only difference.
    const fixedSalt = 'a'.repeat(64)
    const fixedIv = new Uint8Array(16)
    a.encryption = { ...a.encryption, salt: fixedSalt, iv: fixedIv }
    b.encryption = { ...b.encryption, salt: fixedSalt, iv: fixedIv }
    a.integrity = { ...a.integrity, salt: fixedSalt }
    b.integrity = { ...b.integrity, salt: fixedSalt }

    const sa = await Iron.seal({ x: 1 }, PASSWORD, a)
    const sb = await Iron.seal({ x: 1 }, PASSWORD, b)
    const partsA = Iron.splitTicket(sa)
    const partsB = Iron.splitTicket(sb)
    assertNotEquals(partsA[4], partsB[4], 'ciphertext should differ when iteration count differs')
  })
})

// ---------------------------------------------------------------------------
// Custom encode / decode hooks
// ---------------------------------------------------------------------------

describe('custom serialization', () => {
  it('round-trips with a custom encode/decode pair', async () => {
    const opts = Iron.clone(Iron.defaults)
    opts.encode = (data) => 'pfx:' + JSON.stringify(data)
    opts.decode = (str) => JSON.parse(str.replace(/^pfx:/, ''))
    const sealed = await Iron.seal({ msg: 'hi' }, PASSWORD, opts)
    const unsealed = await Iron.unseal(sealed, PASSWORD, opts)
    assertEquals(unsealed, { msg: 'hi' })
  })

  it('uses JSON.stringify when encode is provided as the standard one (preserves prior behavior)', async () => {
    const opts = Iron.clone(Iron.defaults)
    opts.encode = JSON.stringify
    // JSON.stringify silently allows things lossless mode rejects (e.g. NaN -> 'null')
    const sealed = await Iron.seal({ a: NaN, b: Infinity }, PASSWORD, opts)
    const unsealed = await Iron.unseal(sealed, PASSWORD, opts)
    assertEquals(unsealed, { a: null, b: null })
  })

  it('surfaces decode errors verbatim', async () => {
    const opts = Iron.clone(Iron.defaults)
    opts.decode = () => {
      throw new Error('custom-decode-failure')
    }
    const sealed = await Iron.seal({ x: 1 }, PASSWORD, Iron.defaults)
    await assertRejects(Iron.unseal(sealed, PASSWORD, opts), 'custom-decode-failure')
  })
})

// ---------------------------------------------------------------------------
// Decryption integrity at the decode boundary
// ---------------------------------------------------------------------------

// The HMAC authenticates the ciphertext under the *integrity* key only; it does not
// commit to the encryption key. So a wrong encryption secret paired with the correct
// integrity secret passes the MAC and decrypts to garbage. unseal decodes the plaintext
// as strict UTF-8 first, so that garbage is rejected rather than silently reaching a
// lenient decoder. This is defense-in-depth, not authentication — AEAD (AES-GCM) would be
// required to actually detect a wrong key.
//
// Note this isn't practically exploitable by an attacker: forging a ticket that passes the
// HMAC requires the integrity key, so this path is only reachable by a misconfigured caller
// that holds the right integrity secret but the wrong encryption secret (e.g. mismatched
// split secrets) — not by an outside party.
describe('decryption integrity at the decode boundary', () => {
  it('rejects a wrong encryption secret that still passes the HMAC (default codec)', async () => {
    // Matching integrity secret (HMAC passes) but a wrong encryption secret on unseal. The
    // default CBC + JSON codec rejects the resulting garbage; this is the probabilistic CBC
    // counterpart to the deterministic CTR case below.
    const encryption = 'long_encryption_secret_for_seal_test______'
    const integrity = 'a_different_integrity_secret_long_enough__'
    const sealed = await Iron.seal({ a: 1 }, { id: 'k', encryption, integrity }, Iron.defaults)
    await assertRejects(
      Iron.unseal(
        sealed,
        { k: { id: 'k', encryption: 'a_completely_different_enc_secret_long____', integrity } },
        Iron.defaults,
      ),
      [
        // AES-CBC almost always rejects the wrong-key plaintext as a padding error...
        'The operation failed for an operation-specific reason', // node / bun
        'Decryption failed', // deno
        // ...but ~1/256 of the time the garbage carries valid PKCS#7 padding; the strict
        // UTF-8 decode then rejects it (or, for rare valid-UTF-8 garbage, JSON parsing does).
        'The encoded data was not valid for encoding utf-8', // node
        'The encoded data is not valid', // deno
        'Invalid byte sequence', // bun
        'Failed parsing sealed object JSON',
      ],
    )
  })

  it('rejects wrong-key garbage instead of leaking it to a passthrough decoder', async () => {
    const integrity = 'shared_integrity_secret_that_is_long_enough'
    const opts = Iron.clone(Iron.defaults)
    // CTR has no padding, so wrong-key decryption always yields garbage, and
    // pinning salt+iv makes that garbage deterministic.
    opts.encryption = { ...opts.encryption, algorithm: 'aes-128-ctr', salt: 'a'.repeat(64), iv: new Uint8Array(16) }
    opts.integrity = { ...opts.integrity, salt: 'a'.repeat(64) }
    opts.encode = (data) => data as string
    opts.decode = (str) => str // passthrough: would silently return garbage without the UTF-8 guard
    const sealed = await Iron.seal(
      'x'.repeat(64),
      { id: 'k', encryption: 'the_correct_encryption_secret_long_enough_', integrity },
      opts,
    )
    await assertRejects(
      Iron.unseal(
        sealed,
        { k: { id: 'k', encryption: 'a_totally_different_wrong_secret_long_xxx_', integrity } },
        opts,
      ),
      [
        'The encoded data was not valid for encoding utf-8', // node
        'The encoded data is not valid', // deno
        'Invalid byte sequence', // bun
      ],
    )
  })

  it('still round-trips a valid payload through a passthrough decoder (no false positive)', async () => {
    const opts = Iron.clone(Iron.defaults)
    opts.encode = (data) => data as string
    opts.decode = (str) => str
    const payload = 'hello, world — café 日本語 🚀'
    const sealed = await Iron.seal(payload, PASSWORD, opts)
    assertEquals(await Iron.unseal(sealed, PASSWORD, opts), payload)
  })
})

// ---------------------------------------------------------------------------
// Prototype pollution surface
// ---------------------------------------------------------------------------

// The library does NOT sanitize decoded output. JSON.parse follows
// CreateDataProperty for `__proto__`, so Iron.unseal itself does not pollute
// `Object.prototype`. But the returned value can carry a `__proto__` own
// property whose use downstream (Object.assign, spread-into-existing) would
// pollute the *target*. README recommends Bourne for those use cases.
describe('prototype pollution surface', () => {
  it('lossless serializer refuses payloads with a non-default own prototype', async () => {
    // Note: this is a *serialization correctness* check (the encoder rejects
    // non-plain objects), not a pollution control. Object literal syntax
    // `{ __proto__: x }` mutates the prototype rather than adding a key, so
    // there's no key to encode anyway.
    const payload = { __proto__: { polluted: 'YES' } }
    await assertRejects(Iron.seal(payload, PASSWORD, Iron.defaults), 'Data is not JSON serializable')
  })

  it('Iron.unseal does not pollute Object.prototype when ciphertext encodes a "__proto__" key', async () => {
    // Bypass the lossless serializer with a custom encoder so a literal
    // "__proto__" key reaches the wire. Default decoder is JSON.parse, which
    // per spec uses CreateDataProperty and does not invoke the __proto__
    // setter — so the *global* prototype is untouched at the iron boundary.
    const opts = Iron.clone(Iron.defaults)
    opts.encode = () => '{"__proto__":{"polluted":"YES"},"ok":true}'
    const sealed = await Iron.seal({}, PASSWORD, opts)
    await Iron.unseal(sealed, PASSWORD, Iron.defaults)
    // deno-lint-ignore no-explicit-any
    assertEquals(({} as any).polluted, undefined, 'Object.prototype must not be polluted at iron boundary')
  })

  it('documents the hazard: unsealed output retains __proto__ as an own data property', async () => {
    // This is intentional library behavior, not a defect. Callers planning
    // to splat the result into another object should pass a sanitizing
    // decoder (Bourne.parse or equivalent). The test exists to pin the
    // contract: future "fixes" that strip __proto__ silently would break
    // round-trip semantics for callers who legitimately store the key.
    const opts = Iron.clone(Iron.defaults)
    opts.encode = () => '{"__proto__":{"polluted":"YES"},"ok":true}'
    const sealed = await Iron.seal({}, PASSWORD, opts)
    const unsealed = await Iron.unseal(sealed, PASSWORD, Iron.defaults)
    // The own-property form (parsed via CreateDataProperty) survives.
    const ownProto = Object.getOwnPropertyDescriptor(unsealed, '__proto__')
    assertExists(ownProto, '__proto__ should remain as an own property on the parsed result')
    assertEquals(ownProto.value.polluted, 'YES')
  })

  // it('downstream Object.assign hazard is real on runtimes that still expose the __proto__ setter (Node), inert on those that removed it (modern Deno/V8)', async () => {
  //   // Cross-runtime reality check. This library ships to Node, Deno, Bun,
  //   // Workers, etc. The legacy `Object.prototype.__proto__` accessor was
  //   // removed in modern V8/Deno, so `t.__proto__ = x` becomes a plain own
  //   // data assignment there. In Node it's still an accessor that mutates
  //   // [[Prototype]] — and Object.assign of an unsealed __proto__-bearing
  //   // object pollutes the target.
  //   const opts = Iron.clone(Iron.defaults)
  //   opts.encode = () => '{"__proto__":{"polluted":"FROM_ASSIGN"},"ok":true}'
  //   const sealed = await Iron.seal({}, PASSWORD, opts)
  //   const unsealed = await Iron.unseal(sealed, PASSWORD, Iron.defaults)

  //   const setterExists = typeof Object.getOwnPropertyDescriptor(Object.prototype, '__proto__')?.set === 'function'
  //   const target = {}
  //   Object.assign(target, unsealed)
  //   try {
  //     if (setterExists) {
  //       // deno-lint-ignore no-explicit-any
  //       assertEquals((target as any).polluted, 'FROM_ASSIGN', 'expected pollution on runtimes with __proto__ setter')
  //     } else {
  //       // No setter: `__proto__` becomes a plain own data property on target.
  //       // deno-lint-ignore no-explicit-any
  //       assertEquals((target as any).polluted, undefined, 'no setter -> no pollution path')
  //       assertEquals(Object.getPrototypeOf(target), Object.prototype, 'target prototype unchanged')
  //     }
  //   } finally {
  //     // Restore target's prototype so this test doesn't leak state.
  //     Object.setPrototypeOf(target, Object.prototype)
  //   }
  //   // Fresh objects are never affected — only an explicit assignment-target was.
  //   // deno-lint-ignore no-explicit-any
  //   assertEquals(({} as any).polluted, undefined)
  // })

  it('a Bourne-style sanitizing decoder neutralizes the downstream hazard', async () => {
    // Demonstrate the documented mitigation: a decoder that strips __proto__
    // keys before returning. After sanitizing, downstream Object.assign is safe.
    const opts = Iron.clone(Iron.defaults)
    opts.encode = () => '{"__proto__":{"polluted":"YES"},"ok":true}'
    const unsealOpts = Iron.clone(Iron.defaults)
    unsealOpts.decode = (s) => {
      const out = JSON.parse(s)
      if (Object.prototype.hasOwnProperty.call(out, '__proto__')) delete out.__proto__
      return out
    }
    const sealed = await Iron.seal({}, PASSWORD, opts)
    const unsealed = await Iron.unseal(sealed, PASSWORD, unsealOpts)
    const target = {}
    Object.assign(target, unsealed)
    // deno-lint-ignore no-explicit-any
    assertEquals((target as any).polluted, undefined, 'sanitizing decoder must defang the __proto__ key')
  })

  it('Iron.unseal does not pollute Object.prototype via constructor.prototype either', async () => {
    const opts = Iron.clone(Iron.defaults)
    opts.encode = () => '{"constructor":{"prototype":{"polluted":"YES"}},"ok":true}'
    const sealed = await Iron.seal({}, PASSWORD, opts)
    await Iron.unseal(sealed, PASSWORD, Iron.defaults)
    // deno-lint-ignore no-explicit-any
    assertEquals(({} as any).polluted, undefined)
  })
})

// ---------------------------------------------------------------------------
// Options / defaults integrity
// ---------------------------------------------------------------------------

describe('defaults and clone', () => {
  it('Iron.defaults is frozen at every level', () => {
    assert(Object.isFrozen(Iron.defaults))
    assert(Object.isFrozen(Iron.defaults.encryption))
    assert(Object.isFrozen(Iron.defaults.integrity))
  })

  it('Iron.clone returns a deeply-mutable copy', () => {
    const c = Iron.clone(Iron.defaults)
    c.ttl = 999
    c.encryption.iterations = 42
    c.integrity.algorithm = 'sha256'
    assertEquals(c.ttl, 999)
    assertEquals(c.encryption.iterations, 42)
    // Original is untouched
    assertEquals(Iron.defaults.ttl, 0)
    assertEquals(Iron.defaults.encryption.iterations, 1)
  })

  it('macPrefix and macFormatVersion are consistent', () => {
    assertEquals(Iron.macPrefix, 'Fe26.' + Iron.macFormatVersion)
  })
})

// ---------------------------------------------------------------------------
// Determinism with caller-supplied salt + IV (an advanced/dangerous use case
// that should still behave correctly when invoked)
// ---------------------------------------------------------------------------

describe('deterministic seal with caller-supplied salt+iv', () => {
  it('produces identical tickets when salt and IV are pinned', async () => {
    const fixedSalt = 'a'.repeat(64)
    const fixedIv = new Uint8Array(16)
    const opts = Iron.clone(Iron.defaults)
    opts.encryption = { ...opts.encryption, salt: fixedSalt, iv: fixedIv }
    opts.integrity = { ...opts.integrity, salt: fixedSalt }

    const s1 = await Iron.seal({ x: 1 }, PASSWORD, opts)
    const s2 = await Iron.seal({ x: 1 }, PASSWORD, opts)
    assertEquals(s1, s2, 'with pinned salt+iv the seal must be deterministic')
  })

  it('differs across distinct payloads even with pinned salt+iv', async () => {
    const fixedSalt = 'b'.repeat(64)
    const fixedIv = new Uint8Array(16).fill(1)
    const opts = Iron.clone(Iron.defaults)
    opts.encryption = { ...opts.encryption, salt: fixedSalt, iv: fixedIv }
    opts.integrity = { ...opts.integrity, salt: fixedSalt }

    const a = await Iron.seal({ x: 1 }, PASSWORD, opts)
    const b = await Iron.seal({ x: 2 }, PASSWORD, opts)
    assertNotEquals(a, b)
  })
})
