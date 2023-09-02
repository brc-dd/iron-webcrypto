import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/index.ts'],
  clean: true,
  dts: true,
  format: ['esm', 'cjs'],
  target: 'node10',
  treeshake: true,
  publicDir: true
})
