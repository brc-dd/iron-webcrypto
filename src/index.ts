import { base64ToUint8Array, uint8ArrayToBase64, uint8ArrayToHex } from 'uint8array-extras'
import type {
  Algorithms,
  EncryptionAlgorithm,
  GenerateKeyOptions,
  HmacResult,
  IntegrityAlgorithm,
  Key,
  Password,
  password,
  SealOptions,
} from './types.ts'
import { jsonParse, losslessJsonStringify } from './utils.ts'

export type * from './types.ts'

type TupleOf<L extends number, T, R extends unknown[] = []> = //
  R['length'] extends L ? R : TupleOf<L, T, [T, ...R]>

const enc = /* @__PURE__ */ new TextEncoder()
const dec = /* @__PURE__ */ new TextDecoder()

const jsBase64Enabled = /* @__PURE__ */ (() =>
  typeof Uint8Array.fromBase64 === 'function' &&
  typeof Uint8Array.prototype.toBase64 === 'function' &&
  typeof Uint8Array.prototype.toHex === 'function')()

function b64ToU8(str: string): Uint8Array<ArrayBuffer> {
  if (jsBase64Enabled) return Uint8Array.fromBase64(str, { alphabet: 'base64url' })
  return base64ToUint8Array(str)
}

function u8ToB64(arr: Uint8Array | ArrayBuffer): string {
  arr = arr instanceof ArrayBuffer ? new Uint8Array(arr) : arr
  if (jsBase64Enabled) return arr.toBase64({ alphabet: 'base64url', omitPadding: true })
  return uint8ArrayToBase64(arr, { urlSafe: true })
}

function u8ToHex(arr: Uint8Array | ArrayBuffer): string {
  arr = arr instanceof ArrayBuffer ? new Uint8Array(arr) : arr
  if (jsBase64Enabled) return arr.toHex()
  return uint8ArrayToHex(arr)
}

/**
 * The default encryption and integrity settings.
 */
export const defaults: SealOptions = /* @__PURE__ */ Object.freeze({
  encryption: /* @__PURE__ */ Object.freeze({
    saltBits: 256,
    algorithm: 'aes-256-cbc',
    iterations: 1,
    minPasswordlength: 32,
  }),

  integrity: /* @__PURE__ */ Object.freeze({
    saltBits: 256,
    algorithm: 'sha256',
    iterations: 1,
    minPasswordlength: 32,
  }),

  ttl: 0,
  timestampSkewSec: 60,
  localtimeOffsetMsec: 0,
})

type Mutable<T> = { -readonly [K in keyof T]: T[K] }

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
 * Configuration of each supported algorithm.
 */
export const algorithms: Algorithms = /* @__PURE__ */ Object.freeze({
  'aes-128-ctr': /* @__PURE__ */ Object.freeze({ keyBits: 128, ivBits: 128, name: 'AES-CTR' }),
  'aes-256-cbc': /* @__PURE__ */ Object.freeze({ keyBits: 256, ivBits: 128, name: 'AES-CBC' }),
  'sha256': /* @__PURE__ */ Object.freeze({ keyBits: 256, ivBits: undefined, name: 'SHA-256' }),
})

/**
 * MAC normalization format version.
 * Prevents comparison of MAC values generated with different normalized string formats.
 */
export const macFormatVersion = '2'

/**
 * MAC normalization prefix.
 */
export const macPrefix = 'Fe26.2' // 'Fe26.' + macFormatVersion

/**
 * Generates cryptographically strong pseudorandom bits.
 * @param bits Number of bits to generate (must be a positive multiple of 8).
 * @returns Uint8Array containing the random bits.
 *
 * @internal
 */
export function randomBits(bits: number): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(bits / 8))
}

/**
 * Generates a key from the password.
 * @param password The password string or buffer.
 * @param options Key generation options.
 * @returns The generated key and associated parameters.
 */
export async function generateKey(
  password: Password,
  options: GenerateKeyOptions<EncryptionAlgorithm>,
): Promise<Key<EncryptionAlgorithm>>
export async function generateKey(
  password: Password,
  options: GenerateKeyOptions<IntegrityAlgorithm>,
): Promise<Key<IntegrityAlgorithm>>
export async function generateKey(
  password: Password,
  options: GenerateKeyOptions,
): Promise<Key> {
  if (!password || !password.length) throw new Error('Empty password')
  if (!options || typeof options !== 'object') throw new Error('Bad options')

  const algorithm = algorithms[options.algorithm]
  if (!algorithm) throw new Error('Unknown algorithm: ' + options.algorithm)

  const isHmac = algorithm.name === 'SHA-256' // keep in sync with IntegrityAlgorithm type
  const id = isHmac
    ? { name: 'HMAC', hash: algorithm.name, length: algorithm.keyBits }
    : { name: algorithm.name, length: algorithm.keyBits }
  const usages: KeyUsage[] = isHmac ? ['sign', 'verify'] : ['encrypt', 'decrypt']

  const iv = options.iv || (algorithm.ivBits ? randomBits(algorithm.ivBits) : undefined)

  if (typeof password === 'string') {
    if (password.length < options.minPasswordlength) {
      throw new Error('Password string too short (min ' + options.minPasswordlength + ' characters required)')
    }

    let salt = options.salt
    if (!salt) {
      if (!options.saltBits) throw new Error('Missing salt and saltBits options')
      salt = u8ToHex(randomBits(options.saltBits))
    }

    const baseKey = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey'])
    const algorithm = { name: 'PBKDF2', salt: enc.encode(salt), iterations: options.iterations, hash: 'SHA-1' }
    const derivedKey = await crypto.subtle.deriveKey(algorithm, baseKey, id, false, usages)

    return { key: derivedKey, iv, salt }
  }

  if (password.length < algorithm.keyBits / 8) throw new Error('Key buffer (password) too small')
  const key = await crypto.subtle.importKey('raw', password.slice(), id, false, usages)

  return { key, iv, salt: '' }
}

/**
 * @internal
 */
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
 * Encrypts data.
 * @param password The password string or buffer.
 * @param options Key generation options.
 * @param data The data string to encrypt.
 * @returns The encrypted data and associated key information.
 */
export async function encrypt(
  password: Password,
  options: GenerateKeyOptions<EncryptionAlgorithm>,
  data: Uint8Array | string,
): Promise<{ encrypted: Uint8Array<ArrayBuffer>; key: Key<EncryptionAlgorithm> }> {
  const key = await generateKey(password, options)
  const encrypted = await crypto.subtle.encrypt(...getEncryptParams(options.algorithm, key, data))
  return { encrypted: new Uint8Array(encrypted), key }
}

/**
 * Decrypts data.
 * @param password The password string or buffer.
 * @param options Key generation options.
 * @param data The encrypted data to decrypt.
 * @returns The decrypted data string.
 */
export async function decrypt(
  password: Password,
  options: GenerateKeyOptions<EncryptionAlgorithm>,
  data: Uint8Array | string,
): Promise<string> {
  const key = await generateKey(password, options)
  const decrypted = await crypto.subtle.decrypt(...getEncryptParams(options.algorithm, key, data))
  return dec.decode(decrypted)
}

/**
 * Calculates a HMAC digest.
 * @param password The password string or buffer.
 * @param options Key generation options.
 * @param data The data string to HMAC.
 * @returns The HMAC digest and associated key information.
 */
export async function hmacWithPassword(
  password: Password,
  options: GenerateKeyOptions<IntegrityAlgorithm>,
  data: string,
): Promise<HmacResult> {
  const key = await generateKey(password, options)
  const signed = await crypto.subtle.sign('HMAC', key.key, enc.encode(data))
  return { digest: u8ToB64(signed), salt: key.salt }
}

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

  const { encrypted, key } = await encrypt(
    encryption,
    options.encryption,
    (options.encode || losslessJsonStringify)(object),
  )

  const expiration = options.ttl ? now + options.ttl : ''
  const macBaseString = //
    macPrefix + '*' + id + '*' + key.salt + '*' + u8ToB64(key.iv) + '*' + u8ToB64(encrypted) + '*' + expiration

  const mac = await hmacWithPassword(integrity, options.integrity, macBaseString)
  return macBaseString + '*' + mac.salt + '*' + mac.digest
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

  let pass
  if (typeof password === 'string' || password instanceof Uint8Array) pass = password
  else if (typeof password === 'object' && password !== null) {
    const passwordIdKey = passwordId || 'default'
    pass = password[passwordIdKey]
    if (!pass) throw new Error('Cannot find password: ' + passwordIdKey)
  }
  pass = normalizePassword(pass)

  const key = await generateKey(pass.integrity, { ...options.integrity, salt: hmacSalt })
  const macBaseString = //
    prefix + '*' + passwordId + '*' + encryptionSalt + '*' + ivB64 + '*' + encryptedB64 + '*' + expiration

  const verify = await crypto.subtle.verify('HMAC', key.key, b64ToU8(hmacDigestB64), enc.encode(macBaseString))
  if (!verify) throw new Error('Bad hmac value')

  const decryptedString = await decrypt(pass.encryption, {
    ...options.encryption,
    salt: encryptionSalt,
    iv: b64ToU8(ivB64),
  }, b64ToU8(encryptedB64))

  return (options.decode || jsonParse)(decryptedString)
}
