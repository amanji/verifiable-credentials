export const preset = 'ts-jest';
export const testEnvironment = 'node';
export const roots = ['<rootDir>/src'];
export const testMatch = ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'];
export const collectCoverageFrom = [
  'src/**/*.ts',
  '!src/**/*.d.ts',
  '!src/**/__tests__/**',
  '!src/**/*.test.ts',
  '!src/**/*.spec.ts'
];
export const coverageDirectory = 'coverage';
export const coverageThreshold = {
  global: {
    branches: 70,
    functions: 70,
    lines: 70,
    statements: 70
  }
};
export const moduleNameMapper = {
  // Prefer precompiled CJS validator imports for Jest, but fall back to the original
  // JS module when generated .cjs files are not present on a fresh checkout.
  '^(.*)/compiled/(validate-[^.]+)\\.js$': [
    '$1/compiled/$2.cjs',
    '$1/compiled/$2.js'
  ],
};
export const moduleFileExtensions = ['ts', 'tsx', 'js', 'cjs', 'jsx', 'json'];
export const verbose = true;
export const transform = {
  '^.+\\.ts$': 'ts-jest',
  '^.+\\.js$': 'ts-jest'
};
export const transformIgnorePatterns = [
  'node_modules/(?!jose|@noble/)'
];