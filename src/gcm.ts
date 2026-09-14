/**
 * Seal and unseal a JSON-serializable value as a compact, URL-safe string that is encrypted and
 * authenticated with AES-256-GCM under a key derived via HKDF-SHA256.
 *
 * A single key both encrypts and authenticates the payload, and the ticket's non-secret metadata
 * is bound as additional authenticated data, so any tampering — or a wrong key — is detected on
 * unseal. A fresh salt and nonce are generated for every seal, so every ticket is encrypted under
 * its own derived key.
 *
 * @example
 * ```ts
 * import { seal, unseal } from "iron-webcrypto/gcm"
 *
 * const secret = "f48865d781133e7a669c4fe3caf99b21"
 * const sealed = await seal({ hello: "world" }, secret)
 * const data = await unseal(sealed, secret) // { hello: "world" }
 * ```
 *
 * For repeated use, {@link createSealer} imports the secret once and reuses it:
 *
 * ```ts
 * import { createSealer } from "iron-webcrypto/gcm"
 *
 * const sealer = createSealer(secret, { ttl: 60 * 60 * 1000 })
 * const sealed = await sealer.seal({ hello: "world" })
 * const data = await sealer.unseal(sealed)
 * ```
 *
 * @module
 */

import { randomBits } from './keys.ts'
import type { Password, password } from './types.ts'
import { b64ToU8, dec, enc, jsonParse, losslessJsonStringify, u8ToB64, u8ToHex } from './utils.ts'

export type { Password } from './types.ts'

type TupleOf<L extends number, T, R extends unknown[] = []> = //
  R['length'] extends L ? R : TupleOf<L, T, [T, ...R]>

/** AES-256-GCM parameters: 256-bit key, 96-bit nonce, 128-bit authentication tag. */
const KEY_BITS = 256
const IV_BITS = 96
const TAG_BITS = 128

/** Bits of random HKDF salt generated per seal. */
const SALT_BITS = 256

/** Minimum length of a string password. */
const MIN_PASSWORD_LENGTH = 32

/** HKDF `info` value binding derived keys to this scheme. */
const HKDF_INFO = 'aes-256-gcm'

/** Options for {@link seal} and {@link unseal}; every field is optional and defaults when omitted. */
export type GcmSealOptions = Readonly<{
  /** Sealed object lifetime in milliseconds, where 0 means forever. Defaults to 0. */
  ttl?: number

  /** Permitted clock skew, in seconds, for incoming expirations. Defaults to 60. */
  timestampSkewSec?: number

  /** Local clock offset in milliseconds, positive or negative. Defaults to 0. */
  localtimeOffsetMsec?: number

  /** Serializer applied to the value before encryption. Defaults to a lossless JSON stringifier. */
  encode?: (data: unknown) => string

  /** Deserializer applied to the decrypted string. Defaults to `JSON.parse`. */
  decode?: (data: string) => unknown
}>

/**
 * A password: a raw secret (string or buffer), or a `{ id, secret }` object whose `id` selects
 * the matching secret from a {@link GcmPasswordHash} on unseal.
 *
 * The secret must be **high-entropy**, not a human-memorable passphrase: HKDF expands keying
 * material but does no password stretching, so the derived key is only as strong as the secret.
 * Generate it with a CSPRNG — e.g. `openssl rand -base64 32`, or
 * `crypto.getRandomValues(new Uint8Array(32))`.
 */
export type GcmPassword = Password | Readonly<{ id?: string | undefined; secret: Password }>

/** Maps a password id to its {@link GcmPassword}, for selecting a secret by id on unseal. */
export type GcmPasswordHash = Readonly<{ [id: string]: GcmPassword }>

/** A {@link seal}/{@link unseal} pair bound to a password, returned by {@link createSealer}. */
export type GcmSealer = Readonly<{
  /** Seals a value. Per-call `options` override those given to {@link createSealer}. */
  seal: (object: unknown, options?: GcmSealOptions) => Promise<string>

  /** Unseals a ticket. Per-call `options` override those given to {@link createSealer}. */
  unseal: (sealed: string, options?: GcmSealOptions) => Promise<unknown>
}>

/** Protocol format version, carried in the ticket {@link prefix}. */
export const formatVersion = '3'

/** Ticket prefix and first component; unseal rejects any ticket that does not begin with it. */
export const prefix = `Fe26.${formatVersion}`

/** Resolves a password to a single `{ id?, secret }`, throwing if the secret is empty. */
function normalizePassword(password: GcmPassword | undefined): password.Secret {
  const normalized = typeof password === 'string' || password instanceof Uint8Array
    ? { secret: password }
    : password && typeof password === 'object' && 'secret' in password
    ? { id: password.id, secret: password.secret }
    : undefined

  if (!normalized || !normalized.secret || normalized.secret.length === 0) {
    throw new Error('Empty password')
  }
  if (normalized.id && !/^\w+$/.test(normalized.id)) throw new Error('Invalid password id')

  return normalized
}

function isPasswordHash(password: GcmPassword | GcmPasswordHash): password is GcmPasswordHash {
  return typeof password === 'object' && password !== null && !(password instanceof Uint8Array) &&
    !('secret' in password)
}

function passwordFromHash(password: Password | GcmPasswordHash, passwordId: string): GcmPassword | undefined {
  if (typeof password === 'string' || password instanceof Uint8Array) return password
  if (typeof password !== 'object' || password === null) return undefined

  const passwordIdKey = passwordId || 'default'
  const pass = password[passwordIdKey]
  if (!pass) throw new Error(`Cannot find password: ${passwordIdKey}`)
  return pass
}

/**
 * Imports a secret as a non-extractable HKDF base key. String passwords are UTF-8 encoded; raw
 * key buffers are used as-is.
 */
function importBaseKey(secret: Password): Promise<CryptoKey> {
  let material: Uint8Array<ArrayBuffer>
  if (typeof secret === 'string') {
    if (secret.length < MIN_PASSWORD_LENGTH) {
      throw new Error(`Password string too short (min ${MIN_PASSWORD_LENGTH} characters required)`)
    }
    material = enc.encode(secret)
  } else {
    if (secret.length < KEY_BITS / 8) throw new Error('Key buffer (password) too small')
    material = secret.slice()
  }
  return crypto.subtle.importKey('raw', material, 'HKDF', false, ['deriveKey'])
}

/**
 * Derives a non-extractable AES-GCM key scoped to a single `usage` ('encrypt' for sealing,
 * 'decrypt' for unsealing). The base key is run through HKDF-SHA256 with the per-seal salt.
 */
function deriveKey(baseKey: CryptoKey, salt: string, usage: 'encrypt' | 'decrypt'): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: enc.encode(salt), info: enc.encode(HKDF_INFO) },
    baseKey,
    { name: 'AES-GCM', length: KEY_BITS },
    false,
    [usage],
  )
}

async function sealWithKey(object: unknown, id: string, baseKey: CryptoKey, options: GcmSealOptions): Promise<string> {
  const now = Date.now() + (options.localtimeOffsetMsec ?? 0)

  const dataString = (options.encode ?? losslessJsonStringify)(object)

  const salt = u8ToHex(randomBits(SALT_BITS))
  const key = await deriveKey(baseKey, salt, 'encrypt')
  const iv = randomBits(IV_BITS)
  const ivB64 = u8ToB64(iv)

  const ttl = options.ttl ?? 0
  const expiration = ttl ? now + ttl : ''

  // Authenticate the framing (prefix, id, salt, iv, expiration) as additional data so tampering
  // with any of it is detected on unseal.
  const aad = `${prefix}*${id}*${salt}*${ivB64}*${expiration}`
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: enc.encode(aad), tagLength: TAG_BITS },
    key,
    enc.encode(dataString),
  )

  return `${prefix}*${id}*${salt}*${ivB64}*${u8ToB64(encrypted)}*${expiration}`
}

async function unsealWithKey(
  sealed: string,
  getBaseKey: (passwordId: string) => Promise<CryptoKey>,
  options: GcmSealOptions,
): Promise<unknown> {
  const now = Date.now() + (options.localtimeOffsetMsec ?? 0)

  const [ticketPrefix, passwordId, salt, ivB64, encryptedB64, expiration] = splitTicket(sealed)

  if (ticketPrefix !== prefix) throw new Error('Wrong prefix')

  if (expiration) {
    if (!/^[1-9]\d*$/.test(expiration)) throw new Error('Invalid expiration')
    const exp = Number.parseInt(expiration, 10)
    if (exp <= now - (options.timestampSkewSec ?? 60) * 1000) throw new Error('Expired seal')
  }

  const baseKey = getBaseKey(passwordId)

  const iv = b64ToU8(ivB64)
  const encrypted = b64ToU8(encryptedB64)

  const key = await deriveKey(await baseKey, salt, 'decrypt')

  // Recompute the same AAD as seal. A tampered field or wrong key fails the tag check, which
  // throws the runtime's native AES-GCM error (a DOMException named OperationError).
  const aad = `${prefix}*${passwordId}*${salt}*${ivB64}*${expiration}`
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: enc.encode(aad), tagLength: TAG_BITS },
    key,
    encrypted,
  )

  return (options.decode ?? jsonParse)(dec.decode(decrypted))
}

/**
 * Serializes, encrypts, and authenticates a value into a ticket string.
 * @param object The value to seal.
 * @param password The password to seal with.
 * @param options Optional settings; see {@link GcmSealOptions}.
 * @returns The sealed ticket string.
 */
export async function seal(
  object: unknown,
  password: GcmPassword,
  options: GcmSealOptions = {},
): Promise<string> {
  const { id = '', secret } = normalizePassword(password)
  return sealWithKey(object, id, await importBaseKey(secret), options)
}

/**
 * Splits a ticket into its six `*`-separated components — prefix, id, salt, iv, ciphertext (with
 * tag), expiration — throwing if the count is wrong.
 * @internal
 */
export function splitTicket(sealed: string): TupleOf<6, string> {
  const parts = sealed.split('*')
  if (parts.length !== 6) throw new Error('Incorrect number of sealed components')
  return parts as TupleOf<6, string>
}

/**
 * Verifies, decrypts, and returns the value from a ticket string.
 * @param sealed The ticket string.
 * @param password The password to unseal with.
 * @param options Optional settings; see {@link GcmSealOptions}.
 * @returns The unsealed value.
 */
export function unseal(
  sealed: string,
  password: Password | GcmPasswordHash,
  options: GcmSealOptions = {},
): Promise<unknown> {
  return unsealWithKey(
    sealed,
    (passwordId) => importBaseKey(normalizePassword(passwordFromHash(password, passwordId)).secret),
    options,
  )
}

/**
 * Creates a {@link GcmSealer} that imports the secret once, as a non-extractable `CryptoKey`,
 * and reuses it across calls.
 *
 * With a {@link GcmPasswordHash}, tickets are sealed under the first entry and unsealed under any
 * entry, so `{ v2: current, v1: previous }` rotates secrets.
 *
 * @param password The password, or a hash of passwords keyed by id.
 * @param options Default settings for every call; see {@link GcmSealOptions}.
 * @returns The sealer.
 */
export function createSealer(password: GcmPassword | GcmPasswordHash, options: GcmSealOptions = {}): GcmSealer {
  const hash = isPasswordHash(password)
  const sealId = hash ? Object.keys(password)[0] ?? '' : normalizePassword(password).id ?? ''

  const baseKeys = new Map<string, Promise<CryptoKey>>()
  const getBaseKey = (passwordId: string): Promise<CryptoKey> => {
    const cacheKey = hash ? passwordId || 'default' : ''
    let baseKey = baseKeys.get(cacheKey)
    if (!baseKey) {
      const entry = hash ? passwordFromHash(password, passwordId) : password
      baseKey = importBaseKey(normalizePassword(entry).secret)
      baseKeys.set(cacheKey, baseKey)
    }
    return baseKey
  }

  return {
    seal: async (object, callOptions) =>
      sealWithKey(object, sealId, await getBaseKey(sealId), { ...options, ...callOptions }),
    unseal: (sealed, callOptions) => unsealWithKey(sealed, getBaseKey, { ...options, ...callOptions }),
  }
}
