import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  target: 'es2022',
  splitting: false,
  sourcemap: true,
  clean: true,
  dts: true,
  minify: false,
  skipNodeModulesBundle: true,
  shims: true,
  treeshake: true,
  keepNames: true,
});

