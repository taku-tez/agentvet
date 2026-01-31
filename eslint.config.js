module.exports = [
  {
    files: ['**/*.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'commonjs',
      globals: {
        require: 'readonly',
        module: 'readonly',
        exports: 'writable',
        process: 'readonly',
        console: 'readonly',
        Buffer: 'readonly',
        __dirname: 'readonly',
        __filename: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        setInterval: 'readonly',
        clearInterval: 'readonly',
        // Node.js 18+ globals
        fetch: 'readonly',
        AbortSignal: 'readonly',
        AbortController: 'readonly',
        URL: 'readonly',
        URLSearchParams: 'readonly',
        FormData: 'readonly',
        Headers: 'readonly',
        Request: 'readonly',
        Response: 'readonly',
      },
    },
    rules: {
      // Errors - relaxed for existing codebase
      'no-unused-vars': ['warn', { 
        argsIgnorePattern: '^_',
        varsIgnorePattern: '^_',
        caughtErrorsIgnorePattern: '^(e|error|err)$',
      }],
      'no-undef': 'error',
      'no-const-assign': 'error',
      'no-dupe-keys': 'error',
      'no-duplicate-case': 'error',
      
      // Warnings
      'no-console': 'off', // CLI tool, console is fine
      'prefer-const': 'warn',
      'no-var': 'warn',
      
      // Style (less strict for existing codebase)
      'semi': ['warn', 'always'],
      'quotes': ['warn', 'single', { avoidEscape: true }],
    },
  },
  {
    ignores: [
      'node_modules/**',
      'test/fixtures/**',
      'examples/**',
      'coverage/**',
    ],
  },
];
