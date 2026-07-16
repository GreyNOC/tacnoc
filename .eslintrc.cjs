/* ESLint configuration (classic .eslintrc format for ESLint 8). */
module.exports = {
  root: true,
  env: {
    node: true,
    browser: true,
    es2023: true,
  },
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 2023,
    sourceType: 'module',
    ecmaFeatures: { jsx: true },
  },
  plugins: ['@typescript-eslint', 'react', 'react-hooks'],
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:react/recommended',
    'plugin:react-hooks/recommended',
  ],
  settings: {
    react: { version: 'detect' },
  },
  rules: {
    'react/react-in-jsx-scope': 'off',
    'react/prop-types': 'off',
    '@typescript-eslint/no-unused-vars': [
      'error',
      { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
    ],
    '@typescript-eslint/no-explicit-any': 'warn',
    '@typescript-eslint/explicit-module-boundary-types': 'off',
    'no-console': 'off',
    eqeqeq: ['error', 'smart'],
  },
  ignorePatterns: [
    'node_modules/',
    'out/',
    'dist/',
    'coverage/',
    'playwright-report/',
    'test-results/',
    '*.cjs',
  ],
};
