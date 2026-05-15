import { base64ToUint8Array, uint8ArrayToBase64, uint8ArrayToHex } from 'uint8array-extras'

export const enc = /* @__PURE__ */ new TextEncoder()
export const dec = /* @__PURE__ */ new TextDecoder()

const jsBase64Enabled = /* @__PURE__ */ (() =>
  typeof Uint8Array.fromBase64 === 'function' &&
  typeof Uint8Array.prototype.toBase64 === 'function' &&
  typeof Uint8Array.prototype.toHex === 'function')()

export function b64ToU8(str: string): Uint8Array<ArrayBuffer> {
  if (jsBase64Enabled) return Uint8Array.fromBase64(str, { alphabet: 'base64url' })
  // deno-coverage-ignore
  return base64ToUint8Array(str)
}

export function u8ToB64(arr: Uint8Array | ArrayBuffer): string {
  arr = arr instanceof ArrayBuffer ? new Uint8Array(arr) : arr
  if (jsBase64Enabled) return arr.toBase64({ alphabet: 'base64url', omitPadding: true })
  // deno-coverage-ignore
  return uint8ArrayToBase64(arr, { urlSafe: true })
}

export function u8ToHex(arr: Uint8Array | ArrayBuffer): string {
  arr = arr instanceof ArrayBuffer ? new Uint8Array(arr) : arr
  if (jsBase64Enabled) return arr.toHex()
  // deno-coverage-ignore
  return uint8ArrayToHex(arr)
}

export function losslessJsonStringify(data: unknown): string {
  try {
    if (isJson(data)) {
      const stringified = JSON.stringify(data)
      if (stringified) return stringified
    }
  } catch { /* ignore */ }
  throw new Error('Data is not JSON serializable')
}

export function jsonParse(string: string): unknown {
  try {
    return JSON.parse(string)
  } catch (err) {
    throw new Error('Failed parsing sealed object JSON: ' + (err as Error).message)
  }
}

export function isJson(val: unknown): boolean {
  const stack: unknown[] = []
  const seen = new WeakSet()

  const check = (val: unknown): boolean => {
    if (val === null || typeof val === 'string' || typeof val === 'boolean') return true
    if (typeof val === 'number') return Number.isFinite(val)
    if (typeof val !== 'object') return false

    // allow aliasing and cycles at this level
    // circular references will throw during serialization
    if (seen.has(val)) return true

    seen.add(val)
    stack.push(val)

    return true
  }

  if (!check(val)) return false

  while (stack.length) {
    const obj = stack.pop()!

    if (Array.isArray(obj)) {
      let i = obj.length
      while (i--) if (!check(obj[i])) return false
      continue
    }

    const proto = Object.getPrototypeOf(obj)
    if (proto !== null && proto !== Object.prototype) return false

    const keys = Object.keys(obj)
    if (Reflect.ownKeys(obj).length !== keys.length) return false

    let i = keys.length

    while (i--) {
      const val = (obj as Record<string, unknown>)[keys[i]!]
      // allow undefined values even though they are lost during serialization
      // undefined elements in arrays are not allowed because they become null
      if (val !== undefined && !check(val)) return false
    }
  }

  return true
}
