import type { Algorithms, EncryptionAlgorithm, GenerateKeyOptions, IntegrityAlgorithm, Key, Password } from './types.ts'
import { enc, u8ToHex } from './utils.ts'

/** Configuration of each supported algorithm. */
export const algorithms: Algorithms = /* @__PURE__ */ Object.freeze({
  'aes-128-ctr': /* @__PURE__ */ Object.freeze({ keyBits: 128, ivBits: 128, name: 'AES-CTR' }),
  'aes-256-cbc': /* @__PURE__ */ Object.freeze({ keyBits: 256, ivBits: 128, name: 'AES-CBC' }),
  'sha256': /* @__PURE__ */ Object.freeze({ keyBits: 256, ivBits: undefined, name: 'SHA-256' }),
})

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

/** Resolve an algorithm spec, throwing on unknown names. */
function getAlgorithmSpec<T extends keyof typeof algorithms>(name: T): (typeof algorithms)[T] {
  const alg = algorithms[name]
  if (!alg) throw new Error('Unknown algorithm: ' + name)
  return alg
}

/** Pick override -> option -> random; only random-generates for the string-password path. */
function resolveSalt(
  override: string | undefined,
  optSalt: string | undefined,
  isStringPassword: boolean,
  saltBits: number | undefined,
): string | undefined {
  const salt = override || optSalt
  if (salt || !isStringPassword) return salt
  if (!saltBits) throw new Error('Missing salt and saltBits options')
  return u8ToHex(randomBits(saltBits))
}

/** Ensure the password/key meets the minimum size required by the chosen mode. */
function validatePasswordSize(
  password: Password,
  isString: boolean,
  minPasswordLength: number,
  keyBits: number,
): void {
  if (isString) {
    if ((password as string).length < minPasswordLength) {
      throw new Error(`Password string too short (min ${minPasswordLength} characters required)`)
    }
  } else if ((password as Uint8Array).length < keyBits / 8) {
    throw new Error('Key buffer (password) too small')
  }
}

/** Import a string password as a PBKDF2 base key. */
function importPbkdf2BaseKey(password: string): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey'])
}

/** Derive an AES encryption key from a PBKDF2 base. */
function deriveEncryptionKey(
  baseKey: CryptoKey,
  salt: string,
  iterations: number,
  alg: { name: string; keyBits: number },
): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: enc.encode(salt), iterations, hash: 'SHA-1' },
    baseKey,
    { name: alg.name, length: alg.keyBits },
    false,
    ['encrypt', 'decrypt'],
  )
}

/** Derive an HMAC integrity key from a PBKDF2 base. */
function deriveIntegrityKey(
  baseKey: CryptoKey,
  salt: string,
  iterations: number,
  alg: { name: string; keyBits: number },
): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: enc.encode(salt), iterations, hash: 'SHA-1' },
    baseKey,
    { name: 'HMAC', hash: alg.name, length: alg.keyBits },
    false,
    ['sign', 'verify'],
  )
}

/** Import a raw buffer as an AES encryption key. */
function importRawEncryptionKey(
  key: Uint8Array,
  alg: { name: string; keyBits: number },
): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    key.slice(),
    { name: alg.name, length: alg.keyBits },
    false,
    ['encrypt', 'decrypt'],
  )
}

/** Import a raw buffer as an HMAC integrity key. */
function importRawIntegrityKey(
  key: Uint8Array,
  alg: { name: string; keyBits: number },
): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    key.slice(),
    { name: 'HMAC', hash: alg.name, length: alg.keyBits },
    false,
    ['sign', 'verify'],
  )
}

/** Derives both the encryption key and the integrity key in one shot. */
export async function generateKeys(
  encryption: Password,
  integrity: Password,
  encOptions: GenerateKeyOptions<EncryptionAlgorithm>,
  intOptions: GenerateKeyOptions<IntegrityAlgorithm>,
  encSaltOverride?: string,
  ivOverride?: Uint8Array<ArrayBuffer>,
  intSaltOverride?: string,
): Promise<[Key<EncryptionAlgorithm>, Key<IntegrityAlgorithm>]> {
  const encAlg = getAlgorithmSpec(encOptions.algorithm)
  const intAlg = getAlgorithmSpec(intOptions.algorithm)

  const encIsString = typeof encryption === 'string'
  const intIsString = typeof integrity === 'string'

  // Salt is only meaningful for the PBKDF2 (string-password) path.
  const encSalt = resolveSalt(encSaltOverride, encOptions.salt, encIsString, encOptions.saltBits)
  const intSalt = resolveSalt(intSaltOverride, intOptions.salt, intIsString, intOptions.saltBits)

  const iv = ivOverride || encOptions.iv || randomBits(encAlg.ivBits)

  validatePasswordSize(encryption, encIsString, encOptions.minPasswordLength, encAlg.keyBits)
  validatePasswordSize(integrity, intIsString, intOptions.minPasswordLength, intAlg.keyBits)

  let encKeyPromise: Promise<CryptoKey>
  let intKeyPromise: Promise<CryptoKey>

  // Fast path: same string password for both — import the PBKDF2 base key
  // once and derive both keys from it in parallel.
  if (encIsString && intIsString && encryption === integrity) {
    const baseKey = await importPbkdf2BaseKey(encryption)
    encKeyPromise = deriveEncryptionKey(baseKey, encSalt!, encOptions.iterations, encAlg)
    intKeyPromise = deriveIntegrityKey(baseKey, intSalt!, intOptions.iterations, intAlg)
  } else {
    encKeyPromise = encIsString
      ? importPbkdf2BaseKey(encryption).then((baseKey) =>
        deriveEncryptionKey(baseKey, encSalt!, encOptions.iterations, encAlg)
      )
      : importRawEncryptionKey(encryption, encAlg)

    intKeyPromise = intIsString
      ? importPbkdf2BaseKey(integrity).then((baseKey) =>
        deriveIntegrityKey(baseKey, intSalt!, intOptions.iterations, intAlg)
      )
      : importRawIntegrityKey(integrity, intAlg)
  }

  const [encKey, intKey] = await Promise.all([encKeyPromise, intKeyPromise])

  return [
    { key: encKey, iv, salt: encIsString ? encSalt! : '' },
    { key: intKey, iv: undefined, salt: intIsString ? intSalt! : '' },
  ]
}
