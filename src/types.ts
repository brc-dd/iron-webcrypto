/**
 * Algorithm used for encryption and decryption.
 */
export type EncryptionAlgorithm = 'aes-128-ctr' | 'aes-256-cbc'

/**
 * Algorithm used for integrity verification.
 */
export type IntegrityAlgorithm = 'sha256'

/**
 * @internal
 */
export type _Algorithm = EncryptionAlgorithm | IntegrityAlgorithm

/**
 * Configuration of each supported algorithm.
 */
export type Algorithms = {
  readonly [Algorithm in EncryptionAlgorithm | IntegrityAlgorithm]: Algorithm extends EncryptionAlgorithm
    ? Readonly<{ keyBits: number; ivBits: number; name: string }>
    : Readonly<{ keyBits: number; ivBits: undefined; name: string }>
}

/**
 * seal() method options.
 */
export type SealOptionsSub<Algorithm extends _Algorithm = _Algorithm> = Readonly<{
  /**
   * The length of the salt (random buffer used to ensure that two identical objects will generate a different encrypted result). Defaults to 256.
   */
  saltBits: number

  /**
   * The algorithm used. Defaults to 'aes-256-cbc' for encryption and 'sha256' for integrity.
   */
  algorithm: Algorithm

  /**
   * The number of iterations used to derive a key from the password. Defaults to 1.
   */
  iterations: number

  /**
   * Minimum password size. Defaults to 32.
   */
  minPasswordlength: number
}>

/**
 * Options for customizing the key derivation algorithm used to generate encryption and integrity verification keys as well as the algorithms and salt sizes used.
 */
export type SealOptions = Readonly<{
  /**
   * Encryption step options.
   */
  encryption: SealOptionsSub<EncryptionAlgorithm>

  /**
   * Integrity step options.
   */
  integrity: SealOptionsSub<IntegrityAlgorithm>

  /**
   * Sealed object lifetime in milliseconds where 0 means forever. Defaults to 0.
   */
  ttl: number

  /**
   * Number of seconds of permitted clock skew for incoming expirations. Defaults to 60 seconds.
   */
  timestampSkewSec: number

  /**
   * Local clock time offset, expressed in number of milliseconds (positive or negative). Defaults to 0.
   */
  localtimeOffsetMsec: number

  /**
   * Custom encoder for serializing data before encryption. Defaults to lossless JSON stringify. \
   * To revert to v1 behavior, use `JSON.stringify`. \
   * For complex data types, you can use cbor or msgpack encoders.
   */
  encode?: (data: unknown) => string

  /**
   * Custom decoder for deserializing data after decryption. Defaults to `JSON.parse`. \
   * To align with `@hapi/iron`'s behavior, use `Bourne.parse`.
   */
  decode?: (data: string) => unknown
}>

/**
 * generateKey() method options.
 */
export type GenerateKeyOptions<Algorithm extends _Algorithm = _Algorithm> =
  & Pick<SealOptionsSub<Algorithm>, 'algorithm' | 'iterations' | 'minPasswordlength'>
  & {
    saltBits?: number | undefined
    salt?: string | undefined
    iv?: Uint8Array<ArrayBuffer> | undefined
  }

/**
 * Generated internal key object.
 */
export type Key<Algorithm extends _Algorithm = _Algorithm> = {
  key: CryptoKey
  salt: string
  iv: Algorithm extends EncryptionAlgorithm ? Uint8Array<ArrayBuffer> : undefined
}

/**
 * Generated HMAC internal results.
 */
export type HmacResult = {
  digest: string
  salt: string
}

/**
 * @deprecated Use {@link HmacResult} instead.
 */
export type HMacResult = HmacResult

/**
 * Password secret string or buffer.
 */
export type Password = Uint8Array | string

export declare namespace password {
  /**
   * Secret object with optional id.
   */
  type Secret = Readonly<{
    id?: string | undefined
    secret: Password
  }>

  /**
   * Secret object with optional id and specified password for each encryption and integrity.
   */
  type Specific = Readonly<{
    id?: string | undefined
    encryption: Password
    integrity: Password
  }>

  /**
   * Key-value pairs hash of password id to value.
   */
  type Hash = Readonly<{
    [id: string]: Password | Secret | Specific
  }>
}
