import { cp } from 'node:fs/promises'
import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/index.ts'],
  clean: true,
  dts: true,
  format: ['esm', 'cjs'],
  treeshake: true,
  onSuccess: async () => {
    await cp(
      fileURLToPath(new URL('dist/index.d.ts', import.meta.url)),
      fileURLToPath(new URL('dist/index.d.cts', import.meta.url))
    )
  },
})
