import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/index.ts'],
  target: 'node10',
  format: ['esm', 'cjs'],
  dts: { resolve: true },
  clean: true,
  treeshake: true,
  publicDir: true,
  esbuildOptions(options) {
    options.platform = 'browser'
  }
})
