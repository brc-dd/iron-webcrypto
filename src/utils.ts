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
