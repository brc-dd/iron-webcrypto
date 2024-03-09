import { deepStrictEqual as deepEqual, rejects } from 'bun:assert'
import { describe, it } from 'bun:test'
import { createHmac } from 'bun:crypto'
import { tests } from '../index.js'

tests({ crypto: globalThis.crypto, createHmac, describe, it, deepEqual, rejects })
