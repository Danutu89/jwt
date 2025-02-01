import { defineConfig } from 'vite';
import dts from 'vite-plugin-dts';
import { resolve } from 'path';

export default defineConfig({
  build: {
    lib: {
      // Entry file of your library
      entry: resolve(__dirname, 'src/index.ts'),
      // Global name for UMD/IIFE builds (not used by ESM)
      name: 'JWT',
      // File naming pattern: will generate my-lib.es.js and my-lib.umd.js
      fileName: (format) => `jwt.${format}.js`,
      // Specify the formats: including 'es' for tree shaking and 'umd' for compatibility
      formats: ['es', 'umd']
    },
    rollupOptions: {
      // Mark dependencies as external if necessary:
      external: [],
      output: {
        globals: {}
      }
    }
  },
  plugins: [
    // Generate .d.ts declaration files
    dts({
      insertTypesEntry: true,
    }),
  ],
  // Vitest configuration
  test: {
    globals: true,
    environment: 'jsdom'
  }
});
