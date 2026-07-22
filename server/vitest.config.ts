import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  root: path.resolve(__dirname),
  test: {
    environment: 'node',
    globals: true,
    setupFiles: ['src/__tests__/setup/disable-rate-limiter.ts'],
    include: ['src/__tests__/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/agents/VerifierAgent.ts', 'src/lib/intelligence/simhash.ts'],
    },
  },
});
