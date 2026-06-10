import { defineConfig } from 'vitest/config'

// Unit tests for pure presentation/logic modules (no DOM). Component rendering
// is validated by tsc + the Vercel build; logic lives in testable pure modules.
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    environment: 'node',
  },
})
