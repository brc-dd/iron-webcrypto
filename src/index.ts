import { generateKeys } from './keys.ts'
import type { EncryptionAlgorithm, Key, Password, password, SealOptions } from './types.ts'
import { b64ToU8, dec, enc, jsonParse, losslessJsonStringify, u8ToB64 } from './utils.ts'

export type * from './types.ts'
export { algorithms } from './keys.ts'

type Mutable<T> = { -readonly [K in keyof T]: T[K] }

type TupleOf<L extends number, T, R extends unknown[] = []> = //
  R['length'] extends L ? R : TupleOf<L, T, [T, ...R]>

/**
 * The default encryption and integrity settings.
 */
export const defaults: SealOptions = /* @__PURE__ */ Object.freeze({
  encryption: /* @__PURE__ */ Object.freeze({
    algorithm: 'aes-256-cbc',
    saltBits: 256,
    iterations: 1,
    minPasswordLength: 32,
  }),

  integrity: /* @__PURE__ */ Object.freeze({
    algorithm: 'sha256',
    saltBits: 256,
    iterations: 1,
    minPasswordLength: 32,
  }),

  ttl: 0,
  timestampSkewSec: 60,
  localtimeOffsetMsec: 0,
})

/**
 * Clones the options object.
 * @param options The options to clone.
 * @returns A mutable copy of the options.
 *
 * @internal
 */
export function clone(options: SealOptions): Mutable<SealOptions> & {
  encryption: Mutable<SealOptions['encryption']>
  integrity: Mutable<SealOptions['integrity']>
} {
  return { ...options, encryption: { ...options.encryption }, integrity: { ...options.integrity } }
}

/**
 * MAC normalization format version.
 * Prevents comparison of MAC values generated with different normalized string formats.
 */
export const macFormatVersion = '2'

/**
 * MAC normalization prefix.
 */
export const macPrefix = 'Fe26.2' // `Fe26.${macFormatVersion}`

/**
 * Normalizes a password parameter.
 * @param password The password to normalize.
 * @returns The normalized password object.
 */
function normalizePassword(password: password.Hash[string] | undefined): password.Specific {
  const normalized = typeof password === 'string' || password instanceof Uint8Array
    ? { encryption: password, integrity: password }
    : password && typeof password === 'object'
    ? 'secret' in password
      ? { id: password.id, encryption: password.secret, integrity: password.secret }
      : { id: password.id, encryption: password.encryption, integrity: password.integrity }
    : undefined

  if (
    !normalized ||
    !normalized.encryption || normalized.encryption.length === 0 ||
    !normalized.integrity || normalized.integrity.length === 0
  ) throw new Error('Empty password')

  return normalized
}

function passwordFromHash(password: Password | password.Hash, passwordId: string): password.Hash[string] | undefined {
  if (typeof password === 'string' || password instanceof Uint8Array) return password
  if (typeof password !== 'object' || password === null) return undefined

  const passwordIdKey = passwordId || 'default'
  const pass = password[passwordIdKey]
  if (!pass) throw new Error(`Cannot find password: ${passwordIdKey}`)
  return pass
}

function getEncryptParams(
  algorithm: EncryptionAlgorithm,
  key: Key<EncryptionAlgorithm>,
  data: Uint8Array | string,
): [AesCbcParams | AesCtrParams, CryptoKey, Uint8Array<ArrayBuffer>] {
  return [
    algorithm === 'aes-128-ctr' ? { name: 'AES-CTR', counter: key.iv, length: 128 } : { name: 'AES-CBC', iv: key.iv },
    key.key,
    typeof data === 'string' ? enc.encode(data) : data.slice(),
  ]
}

/**
 * Serializes, encrypts, and signs an object into an iron protocol string.
 * @param object The object to seal.
 * @param password The password to use for sealing.
 * @param options The sealing options.
 * @returns The sealed string.
 */
export async function seal(object: unknown, password: password.Hash[string], options: SealOptions): Promise<string> {
  const now = Date.now() + (options.localtimeOffsetMsec || 0)

  const { id = '', encryption, integrity } = normalizePassword(password)
  if (id && !/^\w+$/.test(id)) throw new Error('Invalid password id')

  const dataString = (options.encode || losslessJsonStringify)(object)
  const [encKey, intKey] = await generateKeys(encryption, integrity, options.encryption, options.integrity)
  const encrypted = await crypto.subtle.encrypt(...getEncryptParams(options.encryption.algorithm, encKey, dataString))

  const expiration = options.ttl ? now + options.ttl : ''
  const macBaseString = `${macPrefix}*${id}*${encKey.salt}*${u8ToB64(encKey.iv)}*${u8ToB64(encrypted)}*${expiration}`
  const signed = await crypto.subtle.sign('HMAC', intKey.key, enc.encode(macBaseString))

  return `${macBaseString}*${intKey.salt}*${u8ToB64(signed)}`
}

/**
 * Verifies, decrypts, and reconstructs an object from an iron protocol string.
 * @param sealed The sealed string.
 * @param password The password to use for unsealing.
 * @param options The unsealing options.
 * @returns The unsealed object.
 */
export async function unseal(
  sealed: string,
  password: Password | password.Hash,
  options: SealOptions,
): Promise<unknown> {
  const now = Date.now() + (options.localtimeOffsetMsec || 0)

  const parts = sealed.split('*')
  if (parts.length !== 8) throw new Error('Incorrect number of sealed components')

  const [prefix, passwordId, encryptionSalt, ivB64, encryptedB64, expiration, hmacSalt, hmacDigestB64] =
    parts as TupleOf<8, string>

  if (prefix !== macPrefix) throw new Error('Wrong mac prefix')

  if (expiration) {
    if (!/^[1-9]\d*$/.test(expiration)) throw new Error('Invalid expiration')
    const exp = Number.parseInt(expiration, 10)
    if (exp <= now - options.timestampSkewSec * 1000) throw new Error('Expired seal')
  }

  const pass = normalizePassword(passwordFromHash(password, passwordId))

  // Decode base64 inputs synchronously up-front so any malformed input fails fast
  // before we kick off the (parallel) crypto work below.
  const iv = b64ToU8(ivB64)
  const encrypted = b64ToU8(encryptedB64)
  const hmacDigest = b64ToU8(hmacDigestB64)

  const [encKey, intKey] = await generateKeys(
    pass.encryption,
    pass.integrity,
    options.encryption,
    options.integrity,
    encryptionSalt,
    iv,
    hmacSalt,
  )

  const macBaseString = `${macPrefix}*${passwordId}*${encryptionSalt}*${ivB64}*${encryptedB64}*${expiration}`

  // Run HMAC verification and AES decryption in parallel. We still surface the
  // 'Bad hmac value' error first when verification fails — decryption errors
  // are only revealed when the MAC is valid, preserving the original semantics.
  const verifyPromise = crypto.subtle.verify('HMAC', intKey.key, hmacDigest, enc.encode(macBaseString))
  const decryptPromise = crypto.subtle.decrypt(
    ...getEncryptParams(options.encryption.algorithm, encKey, encrypted),
  ).catch((err: unknown) => err instanceof Error ? err : new Error(String(err)))

  const [verify, decryptedOrErr] = await Promise.all([verifyPromise, decryptPromise])
  if (!verify) throw new Error('Bad hmac value')
  if (decryptedOrErr instanceof Error) throw decryptedOrErr

  return (options.decode || jsonParse)(dec.decode(decryptedOrErr))
}
