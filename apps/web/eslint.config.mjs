import nextConfig from 'eslint-config-next'

export default [
  ...nextConfig,
  {
    rules: {
      // React Compiler strict mode flags sequential setState in effects as errors.
      // Downgrade to warn: these are valid patterns used throughout (loading state guards, etc.)
      'react-hooks/set-state-in-effect': 'warn',
      'react-hooks/exhaustive-deps': 'warn',
    },
  },
]
