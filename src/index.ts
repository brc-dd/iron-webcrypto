import type { _Crypto } from './_crypto.js'
import type {
  GenerateKeyOptions,
  HMacResult,
  Key,
  Password,
  RawPassword,
  SealOptions,
  password
} from './types.js'
import { base64urlDecode, base64urlEncode, bufferToString, stringToBuffer } from './utils.js'

// re-export all types and utilities
export type * from './types.js'
export * from './utils.js'

/**
 * The default encryption and integrity settings.
 */
export const defaults: SealOptions = {
  encryption: { saltBits: 256, algorithm: 'aes-256-cbc', iterations: 1, minPasswordlength: 32 },
  integrity: { saltBits: 256, algorithm: 'sha256', iterations: 1, minPasswordlength: 32 },
  ttl: 0,
  timestampSkewSec: 60,
  localtimeOffsetMsec: 0
}

/**
 * Clones the options object.
 * @param options The options object to clone
 * @returns A new options object
 */
export const clone = (options: SealOptions): SealOptions => ({
  ...options,
  encryption: { ...options.encryption },
  integrity: { ...options.integrity }
})

/**
 * Configuration of each supported algorithm.
 */
export const algorithms = {
  'aes-128-ctr': { keyBits: 128, ivBits: 128, name: 'AES-CTR' },
  'aes-256-cbc': { keyBits: 256, ivBits: 128, name: 'AES-CBC' },
  sha256: { keyBits: 256, name: 'SHA-256' }
} as const

/**
 * MAC normalization format version.
 */
export const macFormatVersion = '2'

/**
 * MAC normalization prefix.
 */
export const macPrefix = 'Fe26.2' // `Fe26.${macFormatVersion}`

/**
 * Generates cryptographically strong pseudorandom bytes.
 * @param _crypto Custom WebCrypto implementation
 * @param size Number of bytes to generate
 * @returns Buffer
 */
const randomBytes = (_crypto: _Crypto, size: number): Uint8Array => {
  const bytes = new Uint8Array(size)
  _crypto.getRandomValues(bytes)
  return bytes
}

/**
 * Generate cryptographically strong pseudorandom bits.
 * @param _crypto Custom WebCrypto implementation
 * @param bits Number of bits to generate
 * @returns Buffer
 */
export const randomBits = (_crypto: _Crypto, bits: number): Uint8Array => {
  if (bits < 1) throw new Error('Invalid random bits count')
  const bytes = Math.ceil(bits / 8)
  return randomBytes(_crypto, bytes)
}

/**
 * Provides an asynchronous Password-Based Key Derivation Function 2 (PBKDF2) implementation.
 * @param _crypto Custom WebCrypto implementation
 * @param password A password string or buffer key
 * @param salt A salt string or buffer
 * @param iterations The number of iterations to use
 * @param keyLength The length of the derived key in bytes
 * @param hash The hash algorithm to use
 */
const pbkdf2 = async (
  _crypto: _Crypto,
  password: string,
  salt: string,
  iterations: number,
  keyLength: number,
  hash: HashAlgorithmIdentifier
): Promise<ArrayBuffer> => {
  const passwordBuffer = stringToBuffer(password)
  const importedKey = await _crypto.subtle.importKey('raw', passwordBuffer, 'PBKDF2', false, [
    'deriveBits'
  ])
  const saltBuffer = stringToBuffer(salt)
  const params = { name: 'PBKDF2', hash, salt: saltBuffer, iterations }
  const derivation = await _crypto.subtle.deriveBits(params, importedKey, keyLength * 8)
  return derivation
}

/**
 * Generates a key from the password.
 * @param _crypto Custom WebCrypto implementation
 * @param password A password string or buffer key
 * @param options Object used to customize the key derivation algorithm
 * @returns An object with keys: key, salt, iv
 */
export const generateKey = async (
  _crypto: _Crypto,
  password: Password,
  options: GenerateKeyOptions
): Promise<Key> => {
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
  if (!password?.length) throw new Error('Empty password')
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
  if (options == null || typeof options !== 'object') throw new Error('Bad options')
  if (!(options.algorithm in algorithms)) throw new Error(`Unknown algorithm: ${options.algorithm}`)

  const algorithm = algorithms[options.algorithm]
  const result: Partial<Key> = {}

  const hmac = options.hmac ?? false
  const id = hmac ? { name: 'HMAC', hash: algorithm.name } : { name: algorithm.name }
  const usage: KeyUsage[] = hmac ? ['sign', 'verify'] : ['encrypt', 'decrypt']

  if (typeof password === 'string') {
    if (password.length < options.minPasswordlength)
      throw new Error(
        `Password string too short (min ${options.minPasswordlength} characters required)`
      )

    let { salt = '' } = options
    if (!salt) {
      const { saltBits = 0 } = options
      if (!saltBits) throw new Error('Missing salt and saltBits options')
      const randomSalt = randomBits(_crypto, saltBits)
      salt = [...new Uint8Array(randomSalt)].map((x) => x.toString(16).padStart(2, '0')).join('')
    }

    const derivedKey = await pbkdf2(
      _crypto,
      password,
      salt,
      options.iterations,
      algorithm.keyBits / 8,
      'SHA-1'
    )
    const importedEncryptionKey = await _crypto.subtle.importKey(
      'raw',
      derivedKey,
      id,
      false,
      usage
    )
    result.key = importedEncryptionKey
    result.salt = salt

    //
  } else {
    if (password.length < algorithm.keyBits / 8) throw new Error('Key buffer (password) too small')
    result.key = await _crypto.subtle.importKey('raw', password, id, false, usage)
    result.salt = ''
  }

  if (options.iv) result.iv = options.iv
  else if ('ivBits' in algorithm) result.iv = randomBits(_crypto, algorithm.ivBits)
  return result as Key
}

/**
 * Encrypts data.
 * @param _crypto Custom WebCrypto implementation
 * @param password A password string or buffer key
 * @param options Object used to customize the key derivation algorithm
 * @param data String to encrypt
 * @returns An object with keys: encrypted, key
 */
export const encrypt = async (
  _crypto: _Crypto,
  password: Password,
  options: GenerateKeyOptions,
  data: string
): Promise<{ encrypted: Uint8Array; key: Key }> => {
  const key = await generateKey(_crypto, password, options)
  const textBuffer = stringToBuffer(data)
  const encrypted = await _crypto.subtle.encrypt(
    { name: algorithms[options.algorithm].name, iv: key.iv },
    key.key,
    textBuffer
  )
  return { encrypted: new Uint8Array(encrypted), key }
}

/**
 * Decrypts data.
 * @param _crypto Custom WebCrypto implementation
 * @param password A password string or buffer key
 * @param options Object used to customize the key derivation algorithm
 * @param data Buffer to decrypt
 * @returns Decrypted string
 */
export const decrypt = async (
  _crypto: _Crypto,
  password: Password,
  options: GenerateKeyOptions,
  data: Uint8Array | string
): Promise<string> => {
  const key = await generateKey(_crypto, password, options)
  const decrypted = await _crypto.subtle.decrypt(
    { name: algorithms[options.algorithm].name, iv: key.iv },
    key.key,
    typeof data === 'string' ? stringToBuffer(data) : data
  )
  return bufferToString(new Uint8Array(decrypted))
}

/**
 * Calculates a HMAC digest.
 * @param _crypto Custom WebCrypto implementation
 * @param password A password string or buffer
 * @param options Object used to customize the key derivation algorithm
 * @param data String to calculate the HMAC over
 * @returns An object with keys: digest, salt
 */
export const hmacWithPassword = async (
  _crypto: _Crypto,
  password: Password,
  options: GenerateKeyOptions,
  data: string
): Promise<HMacResult> => {
  const key = await generateKey(_crypto, password, { ...options, hmac: true })
  const textBuffer = stringToBuffer(data)
  const signed = await _crypto.subtle.sign({ name: 'HMAC' }, key.key, textBuffer)
  const digest = base64urlEncode(new Uint8Array(signed))
  return { digest, salt: key.salt }
}

/**
 * Normalizes a password parameter.
 * @param password
 * @returns An object with keys: id, encryption, integrity
 */
const normalizePassword = (password: RawPassword): password.Specific => {
  if (typeof password === 'string' || password instanceof Uint8Array)
    return { encryption: password, integrity: password }
  if ('secret' in password)
    return { id: password.id, encryption: password.secret, integrity: password.secret }
  return { id: password.id, encryption: password.encryption, integrity: password.integrity }
}

/**
 * Serializes, encrypts, and signs objects into an iron protocol string.
 * @param _crypto Custom WebCrypto implementation
 * @param object Data being sealed
 * @param password A string, buffer or object
 * @param options Object used to customize the key derivation algorithm
 * @returns Iron sealed string
 */
export const seal = async (
  _crypto: _Crypto,
  object: unknown,
  password: RawPassword,
  options: SealOptions
): Promise<string> => {
  // eslint-disable-next-line @typescript-eslint/strict-boolean-expressions
  if (!password) throw new Error('Empty password')

  const opts = clone(options)
  const now = Date.now() + (opts.localtimeOffsetMsec || 0)
  const objectString = JSON.stringify(object)

  const pass = normalizePassword(password)
  const { id = '', encryption, integrity } = pass
  if (id && !/^\w+$/.test(id)) throw new Error('Invalid password id')

  const { encrypted, key } = await encrypt(_crypto, encryption, opts.encryption, objectString)

  const encryptedB64 = base64urlEncode(new Uint8Array(encrypted))
  const iv = base64urlEncode(key.iv)
  const expiration = opts.ttl ? now + opts.ttl : ''
  const macBaseString = `${macPrefix}*${id}*${key.salt}*${iv}*${encryptedB64}*${expiration}`

  const mac = await hmacWithPassword(_crypto, integrity, opts.integrity, macBaseString)
  const sealed = `${macBaseString}*${mac.salt}*${mac.digest}`
  return sealed
}

/**
 * Implements a constant-time comparison algorithm.
 * @param a Original string (running time is always proportional to its length)
 * @param b String to compare to original string
 * @returns Returns true if `a` is equal to `b`, without leaking timing information
 *          that would allow an attacker to guess one of the values.
 */
const fixedTimeComparison = (a: string, b: string): boolean => {
  let mismatch = a.length === b.length ? 0 : 1
  // eslint-disable-next-line no-param-reassign
  if (mismatch) b = a
  // eslint-disable-next-line no-bitwise, unicorn/prefer-code-point
  for (let i = 0; i < a.length; i += 1) mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return mismatch === 0
}

/**
 * Verifies, decrypts, and reconstruct an iron protocol string into an object.
 * @param _crypto Custom WebCrypto implementation
 * @param sealed The iron protocol string generated with seal()
 * @param password A string, buffer, or object
 * @param options Object used to customize the key derivation algorithm
 * @returns The verified decrypted object (can be null)
 */
export const unseal = async (
  _crypto: _Crypto,
  sealed: string,
  password: Password | password.Hash,
  options: SealOptions
): Promise<unknown> => {
  // eslint-disable-next-line @typescript-eslint/strict-boolean-expressions
  if (!password) throw new Error('Empty password')

  const opts = clone(options)
  const now = Date.now() + (opts.localtimeOffsetMsec || 0)

  const parts = sealed.split('*')
  if (parts.length !== 8) throw new Error('Incorrect number of sealed components')

  /* eslint-disable @typescript-eslint/no-non-null-assertion */
  const prefix = parts[0]!
  let passwordId = parts[1]!
  const encryptionSalt = parts[2]!
  const encryptionIv = parts[3]!
  const encryptedB64 = parts[4]!
  const expiration = parts[5]!
  const hmacSalt = parts[6]!
  const hmac = parts[7]!
  const macBaseString = `${prefix}*${passwordId}*${encryptionSalt}*${encryptionIv}*${encryptedB64}*${expiration}`
  /* eslint-enable */

  if (macPrefix !== prefix) throw new Error('Wrong mac prefix')

  if (expiration) {
    if (!/^\d+$/.test(expiration)) throw new Error('Invalid expiration')
    const exp = Number.parseInt(expiration, 10)
    if (exp <= now - opts.timestampSkewSec * 1000) throw new Error('Expired seal')
  }

  let pass: RawPassword = ''
  passwordId = passwordId || 'default'

  if (typeof password === 'string' || password instanceof Uint8Array) pass = password
  else if (passwordId in password) {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    pass = password[passwordId]!
  } else {
    throw new Error(`Cannot find password: ${passwordId}`)
  }

  pass = normalizePassword(pass)

  const macOptions: GenerateKeyOptions = opts.integrity
  macOptions.salt = hmacSalt
  const mac = await hmacWithPassword(_crypto, pass.integrity, macOptions, macBaseString)

  if (!fixedTimeComparison(mac.digest, hmac)) throw new Error('Bad hmac value')

  const encrypted = base64urlDecode(encryptedB64)
  const decryptOptions: GenerateKeyOptions = opts.encryption
  decryptOptions.salt = encryptionSalt
  decryptOptions.iv = base64urlDecode(encryptionIv)

  const decrypted = await decrypt(_crypto, pass.encryption, decryptOptions, encrypted)
  if (decrypted) return JSON.parse(decrypted) as unknown
  return null
}
