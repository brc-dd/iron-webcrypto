/* eslint-disable @typescript-eslint/dot-notation, @typescript-eslint/no-non-null-assertion, no-bitwise, no-plusplus, unicorn/prefer-code-point */

// https://github.com/smithy-lang/smithy-typescript/blob/9275e12bb1db680284681d5ff7277fe3315bbfba/packages/util-base64/src/constants.browser.ts

const alphabetByEncoding: Record<string, number> = {}
const alphabetByValue: string[] = Array.from({ length: 64 })

for (let i = 0, start = 'A'.charCodeAt(0), limit = 'Z'.charCodeAt(0); i + start <= limit; i++) {
  const char = String.fromCharCode(i + start)
  alphabetByEncoding[char] = i
  alphabetByValue[i] = char
}

for (let i = 0, start = 'a'.charCodeAt(0), limit = 'z'.charCodeAt(0); i + start <= limit; i++) {
  const char = String.fromCharCode(i + start)
  const index = i + 26
  alphabetByEncoding[char] = index
  alphabetByValue[index] = char
}

for (let i = 0; i < 10; i++) {
  alphabetByEncoding[i.toString(10)] = i + 52
  const char = i.toString(10)
  const index = i + 52
  alphabetByEncoding[char] = index
  alphabetByValue[index] = char
}

// modified to use - and _ instead of + and /
alphabetByEncoding['-'] = 62
alphabetByValue[62] = '-'
alphabetByEncoding['_'] = 63
alphabetByValue[63] = '_'

const bitsPerLetter = 6
const bitsPerByte = 8
const maxLetterValue = 0b11_1111

/**
 * Convert a string to a Uint8Array.
 * @param value The string to convert
 * @returns The Uint8Array
 */
export const stringToBuffer = (value: string): Uint8Array => {
  return new TextEncoder().encode(value)
}

/**
 * Convert a Uint8Array to a string.
 * @param value The Uint8Array to convert
 * @returns The string
 */
export const bufferToString = (value: Uint8Array): string => {
  return new TextDecoder().decode(value)
}

// https://github.com/smithy-lang/smithy-typescript/blob/9275e12bb1db680284681d5ff7277fe3315bbfba/packages/util-base64/src/fromBase64.browser.ts

/**
 * Decode a base64url string to a Uint8Array.
 * @param _input The base64url string to decode (automatically padded as necessary)
 * @returns The Uint8Array
 *
 * @see https://tools.ietf.org/html/rfc4648#section-5
 */
export const base64urlDecode = (_input: string): Uint8Array => {
  // added to pad with = to a multiple of 4
  const input = _input + '='.repeat((4 - (_input.length % 4)) % 4)

  let totalByteLength = (input.length / 4) * 3
  if (input.endsWith('==')) {
    totalByteLength -= 2
  } else if (input.endsWith('=')) {
    totalByteLength--
  }
  const out = new ArrayBuffer(totalByteLength)
  const dataView = new DataView(out)
  for (let i = 0; i < input.length; i += 4) {
    let bits = 0
    let bitLength = 0
    for (let j = i, limit = i + 3; j <= limit; j++) {
      if (input[j] === '=') {
        bits >>= bitsPerLetter
      } else {
        // If we don't check for this, we'll end up using undefined in a bitwise
        // operation, in which it will be treated as 0.
        if (!(input[j]! in alphabetByEncoding)) {
          throw new TypeError(`Invalid character ${input[j]} in base64 string.`)
        }
        bits |= alphabetByEncoding[input[j]!]! << ((limit - j) * bitsPerLetter)
        bitLength += bitsPerLetter
      }
    }

    const chunkOffset = (i / 4) * 3
    bits >>= bitLength % bitsPerByte
    const byteLength = Math.floor(bitLength / bitsPerByte)
    for (let k = 0; k < byteLength; k++) {
      const offset = (byteLength - k - 1) * bitsPerByte
      dataView.setUint8(chunkOffset + k, (bits & (255 << offset)) >> offset)
    }
  }

  return new Uint8Array(out)
}

// https://github.com/smithy-lang/smithy-typescript/blob/9275e12bb1db680284681d5ff7277fe3315bbfba/packages/util-base64/src/toBase64.browser.ts

/**
 * Encode a Uint8Array to a base64url string.
 * @param _input The Uint8Array to encode
 * @returns The base64url string (without padding)
 *
 * @see https://tools.ietf.org/html/rfc4648#section-5
 */
export const base64urlEncode = (_input: Uint8Array | string): string => {
  const input = typeof _input === 'string' ? stringToBuffer(_input) : _input
  let str = ''
  for (let i = 0; i < input.length; i += 3) {
    let bits = 0
    let bitLength = 0
    for (let j = i, limit = Math.min(i + 3, input.length); j < limit; j++) {
      bits |= input[j]! << ((limit - j - 1) * bitsPerByte)
      bitLength += bitsPerByte
    }

    const bitClusterCount = Math.ceil(bitLength / bitsPerLetter)
    bits <<= bitClusterCount * bitsPerLetter - bitLength
    for (let k = 1; k <= bitClusterCount; k++) {
      const offset = (bitClusterCount - k) * bitsPerLetter
      str += alphabetByValue[(bits & (maxLetterValue << offset)) >> offset]
    }
  }

  // removed padding

  return str
}
