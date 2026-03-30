import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';
import stylistic from '@stylistic/eslint-plugin';
import perfectionist from 'eslint-plugin-perfectionist';

/**
 * ESLint Flat Config — Argon2id Password Hasher Worker
 *
 * Three environments:
 *   1. workers/benchmark-proxy  — Cloudflare Workers (no Node globals)
 *   2. benchmark/src            — Node.js + Vitest (process, console, etc.)
 *   3. Root config files        — relaxed rules
 *
 * @see https://eslint.org/docs/latest/use/configure/configuration-files
 * @type {import('eslint').Linter.Config[]}
 */
export default [
  {
    ignores: [
      'dist/**',
      '**/build/**',
      'target/**',
      'node_modules/**',
      '**/.wrangler/**',
      '*.wasm',
      'workers/password-hasher/entry.mjs',
    ],
  },
  {
    files: ['**/*.ts', '**/*.js'],
    languageOptions: {
      sourceType: 'module',
    },
    rules: eslint.configs.recommended.rules,
  },

  // ========================================
  // TYPESCRIPT ESLINT TYPE-CHECKED RULES
  // ========================================
  ...tseslint.configs.strictTypeChecked.map((config) => ({
    ...config,
    files: ['**/*.ts'],
  })),
  ...tseslint.configs.stylisticTypeChecked.map((config) => ({
    ...config,
    files: ['**/*.ts'],
  })),
  {
    files: ['**/*.ts'],
    languageOptions: {
      parserOptions: {
        projectService: {
          allowDefaultProject: ['vitest.config.ts'],
        },
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },

  // ========================================
  // STYLISTIC RULES
  // ========================================
  {
    files: ['**/*.ts', '**/*.js'],
    plugins: {
      '@stylistic': stylistic,
    },
    rules: {
      ...stylistic.configs.customize({
        indent: 2,
        quotes: 'single',
        semi: true,
        jsx: false,
        arrowParens: true,
        braceStyle: '1tbs',
        blockSpacing: true,
        quoteProps: 'consistent-as-needed',
        commaDangle: 'always-multiline',
      }).rules,
    },
  },

  // ========================================
  // Custom TypeScript rules
  // ========================================
  {
    files: ['**/*.ts'],
    plugins: {
      perfectionist,
    },
    rules: {
      // ----------------------------------------
      // TypeScript strict rules adjustments
      // ----------------------------------------
      '@typescript-eslint/no-unused-vars': ['error', {
        argsIgnorePattern: '^_',
        varsIgnorePattern: '^_',
        caughtErrorsIgnorePattern: '^_',
      }],
      '@typescript-eslint/explicit-function-return-type': 'error',
      '@typescript-eslint/explicit-module-boundary-types': 'error',
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-non-null-assertion': 'warn',
      '@typescript-eslint/prefer-nullish-coalescing': 'error',
      '@typescript-eslint/prefer-optional-chain': 'error',
      '@typescript-eslint/strict-boolean-expressions': 'off',
      '@typescript-eslint/no-confusing-void-expression': ['error', {
        ignoreArrowShorthand: true,
      }],
      '@typescript-eslint/no-extraneous-class': 'error',

      // ----------------------------------------
      // Type import/export consistency
      // ----------------------------------------
      '@typescript-eslint/consistent-type-imports': ['error', {
        prefer: 'type-imports',
        fixStyle: 'inline-type-imports',
        disallowTypeAnnotations: true,
      }],
      '@typescript-eslint/consistent-type-exports': ['error', {
        fixMixedExportsWithInlineTypeSpecifier: true,
      }],
      '@typescript-eslint/no-import-type-side-effects': 'error',

      // ----------------------------------------
      // Type definition consistency
      // ----------------------------------------
      '@typescript-eslint/consistent-type-definitions': ['error', 'interface'],

      // ----------------------------------------
      // Perfectionist sorting rules
      // ----------------------------------------
      'perfectionist/sort-imports': ['error', {
        type: 'natural',
        groups: [
          'builtin',
          'external',
          'internal',
          'parent',
          'sibling',
          'index',
          'type',
        ],
        newlinesBetween: 1,
      }],
      'perfectionist/sort-named-imports': ['error', {
        type: 'natural',
      }],
      'perfectionist/sort-named-exports': ['error', {
        type: 'natural',
      }],
      'perfectionist/sort-interfaces': ['warn', {
        type: 'natural',
      }],
      'perfectionist/sort-object-types': ['warn', {
        type: 'natural',
      }],
      'perfectionist/sort-union-types': ['warn', {
        type: 'natural',
      }],
      'perfectionist/sort-enums': ['warn', {
        type: 'natural',
      }],

      // ----------------------------------------
      // Naming conventions
      // ----------------------------------------
      '@typescript-eslint/naming-convention': [
        'error',
        {
          selector: 'variable',
          format: ['camelCase', 'UPPER_CASE'],
          leadingUnderscore: 'allow',
        },
        {
          selector: 'function',
          format: ['camelCase', 'PascalCase'],
        },
        {
          selector: 'parameter',
          format: ['camelCase'],
          leadingUnderscore: 'allow',
        },
        {
          selector: 'classProperty',
          format: ['camelCase', 'UPPER_CASE'],
          leadingUnderscore: 'allow',
        },
        {
          selector: 'objectLiteralProperty',
          format: null,
        },
        {
          selector: 'property',
          format: ['camelCase', 'UPPER_CASE', 'snake_case'],
        },
        {
          selector: 'typeProperty',
          format: ['camelCase', 'snake_case', 'UPPER_CASE'],
        },
        {
          selector: 'method',
          format: ['camelCase'],
        },
        {
          selector: 'typeLike',
          format: ['PascalCase'],
        },
        {
          selector: 'enumMember',
          format: ['PascalCase', 'UPPER_CASE'],
        },
      ],

      // ----------------------------------------
      // Array safety
      // ----------------------------------------
      '@typescript-eslint/require-array-sort-compare': ['error', {
        ignoreStringArrays: true,
      }],

      // ----------------------------------------
      // General best practices
      // ----------------------------------------
      'no-console': 'warn',
      'no-debugger': 'error',
      'prefer-const': 'error',
      'no-var': 'error',
      'eqeqeq': ['error', 'always'],
      'curly': ['error', 'multi-line'],
      'no-nested-ternary': 'error',
      'no-unneeded-ternary': 'error',
      'no-else-return': ['error', { allowElseIf: false }],
      'no-lonely-if': 'error',
      'prefer-template': 'error',
      'object-shorthand': ['error', 'always'],
      'prefer-destructuring': ['warn', {
        VariableDeclarator: {
          array: false,
          object: true,
        },
        AssignmentExpression: {
          array: false,
          object: false,
        },
      }, {
        enforceForRenamedProperties: false,
      }],
      'no-useless-rename': 'error',
      'no-useless-computed-key': 'error',

      // ----------------------------------------
      // Stylistic adjustments
      // ----------------------------------------
      '@stylistic/max-len': ['warn', {
        code: 100,
        ignoreUrls: true,
        ignoreStrings: true,
        ignoreTemplateLiterals: true,
        ignoreRegExpLiterals: true,
        ignoreComments: true,
        ignorePattern: '^\\s*import\\s',
      }],
      '@stylistic/object-curly-spacing': ['error', 'always'],
      '@stylistic/array-bracket-spacing': ['error', 'never'],
      '@stylistic/comma-spacing': ['error', { before: false, after: true }],
      '@stylistic/key-spacing': ['error', { beforeColon: false, afterColon: true }],
      '@stylistic/space-infix-ops': 'error',
      '@stylistic/keyword-spacing': ['error', { before: true, after: true }],
      '@stylistic/space-before-blocks': 'error',
      '@stylistic/no-multiple-empty-lines': ['error', { max: 1, maxEOF: 0, maxBOF: 0 }],
      '@stylistic/eol-last': ['error', 'always'],
      '@stylistic/no-trailing-spaces': 'error',
      '@stylistic/padded-blocks': ['error', 'never'],
      '@stylistic/lines-between-class-members': ['error', 'always', {
        exceptAfterSingleLine: true,
      }],
      '@stylistic/padding-line-between-statements': [
        'error',
        { blankLine: 'always', prev: 'import', next: '*' },
        { blankLine: 'any', prev: 'import', next: 'import' },
        { blankLine: 'always', prev: '*', next: ['function', 'class', 'export'] },
        { blankLine: 'always', prev: ['function', 'class'], next: '*' },
        { blankLine: 'any', prev: 'export', next: 'export' },
      ],
    },
  },

  // ========================================
  // Benchmark-proxy worker (Cloudflare Workers environment)
  // ========================================
  {
    files: ['workers/benchmark-proxy/**/*.ts'],
    rules: {
      // Audit logging via console.log is intentional in workers
      'no-console': 'off',
      // WorkerEntrypoint subclass is required by Cloudflare
      '@typescript-eslint/no-extraneous-class': 'off',
    },
  },

  // ========================================
  // Benchmark runner & test utilities (Node.js environment)
  // ========================================
  {
    files: ['benchmark/src/**/*.ts'],
    rules: {
      // Runner and test output rely on console
      'no-console': 'off',
    },
  },

  // ========================================
  // Test files (relaxed rules for test ergonomics)
  // ========================================
  {
    files: ['**/*.test.ts'],
    rules: {
      // Test callbacks don't need return types — vitest infers them
      '@typescript-eslint/explicit-function-return-type': 'off',
      '@typescript-eslint/explicit-module-boundary-types': 'off',
      // Tests frequently use non-null assertions on known values
      '@typescript-eslint/no-non-null-assertion': 'off',
      // Test assertions often use floating promises with expect()
      '@typescript-eslint/no-floating-promises': 'off',
      // Naming is relaxed for test description strings and inline objects
      '@typescript-eslint/naming-convention': 'off',
      // Magic numbers in test assertions are fine
      '@typescript-eslint/no-magic-numbers': 'off',
      // Allow numbers/booleans in template literals for test output
      '@typescript-eslint/restrict-template-expressions': ['error', {
        allowNumber: true,
        allowBoolean: true,
      }],
    },
  },

  // ========================================
  // Config files (relaxed rules)
  // ========================================
  {
    files: ['*.config.js', '*.config.ts', '*.config.mjs'],
    rules: {
      'no-console': 'off',
      '@typescript-eslint/explicit-function-return-type': 'off',
      '@typescript-eslint/explicit-module-boundary-types': 'off',
    },
  },
];
