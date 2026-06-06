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
export type Algorithms = Readonly<
  {
    [Algorithm in EncryptionAlgorithm | IntegrityAlgorithm]: Algorithm extends EncryptionAlgorithm
      ? Readonly<{ keyBits: number; ivBits: number; name: string }>
      : Readonly<{ keyBits: number; ivBits: undefined; name: string }>
  }
>

/**
 * Per-step (`encryption` / `integrity`) options for {@link SealOptions}.
 *
 * The salt is supplied one of two ways, and at least one is required: provide `saltBits`
 * to have a random salt generated on each seal, or provide a fixed `salt` directly (in
 * which case `saltBits` is unused).
 */
export type SealOptionsSub<Algorithm extends _Algorithm = _Algorithm> = Readonly<
  & {
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
    minPasswordLength: number

    /**
     * Advanced: a fixed initialization vector. Only meaningful for encryption algorithms —
     * integrity options do not accept an IV. When omitted, a random IV is generated on each
     * seal. Pinning the IV makes sealing deterministic — only do this if you understand the
     * implications.
     */
    iv?: Algorithm extends EncryptionAlgorithm ? Uint8Array<ArrayBuffer> | undefined : never
  }
  & (
    | {
      /**
       * The length of the salt (random buffer used to ensure that two identical objects will
       * generate a different encrypted result), generated fresh on each seal. Defaults to 256.
       */
      saltBits: number

      /** Advanced: a fixed salt; when present, takes precedence over `saltBits`. */
      salt?: string | undefined
    }
    | {
      /**
       * Advanced: a fixed salt (hex string) used to derive the key, instead of generating a
       * random one from `saltBits`. Only applies to string passwords (PBKDF2); ignored for raw
       * key buffers. Pinning the salt makes sealing deterministic — only do this if you
       * understand the implications.
       */
      salt: string

      /** Unused when a fixed `salt` is provided. */
      saltBits?: number | undefined
    }
  )
>

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
 * Generated internal key object.
 */
export type Key<Algorithm extends _Algorithm = _Algorithm> = Readonly<{
  key: CryptoKey
  salt: string
  iv: Algorithm extends EncryptionAlgorithm ? Uint8Array<ArrayBuffer> : undefined
}>

/**
 * Generated HMAC internal results.
 */
export type HmacResult = Readonly<{
  digest: string
  salt: string
}>

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
