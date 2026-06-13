import { defineConfig } from 'vitest/config';
import { version } from './package.json';

export default defineConfig({
  // Mirror tsup.config.ts so __APP_VERSION__ is replaced under vitest too;
  // without this a bare __APP_VERSION__ reference would throw ReferenceError.
  define: {
    __APP_VERSION__: JSON.stringify(version),
  },
  test: {
    globals: true,
    environment: 'node',
    include: ['test/**/*.test.ts'],
  },
});
