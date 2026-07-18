import { normalizeApiBaseUrl, resolveApiBaseUrl } from './apiConfig';

function expectEqual(actual: unknown, expected: unknown, message: string): void {
  if (actual !== expected) {
    throw new Error(`${message}: expected ${String(expected)}, got ${String(actual)}`);
  }
}

function expectThrows(fn: () => unknown, pattern: RegExp, message: string): void {
  try {
    fn();
  } catch (error) {
    const text = error instanceof Error ? error.message : String(error);
    if (!pattern.test(text)) {
      throw new Error(`${message}: wrong error ${text}`);
    }
    return;
  }

  throw new Error(`${message}: expected function to throw`);
}

expectEqual(
  resolveApiBaseUrl({ MODE: 'development' }),
  '/api/v1',
  'development mode uses intentional relative API path'
);

expectEqual(
  resolveApiBaseUrl({ DEV: true }),
  '/api/v1',
  'DEV flag uses intentional relative API path'
);

expectEqual(
  resolveApiBaseUrl({
    MODE: 'production',
    VITE_API_BASE_URL: 'https://api.example.com/api/v1/',
  }),
  'https://api.example.com/api/v1',
  'configured base URL is normalized without trailing slash'
);

expectEqual(
  normalizeApiBaseUrl(' https://api.example.com// '),
  'https://api.example.com',
  'normalizer trims whitespace and trailing slashes'
);

expectThrows(
  () => resolveApiBaseUrl({ MODE: 'production', PROD: true }),
  /VITE_API_BASE_URL is required/,
  'production without VITE_API_BASE_URL fails fast'
);

expectThrows(
  () => resolveApiBaseUrl({ VITE_API_BASE_URL: '   ' }),
  /VITE_API_BASE_URL is configured but empty/,
  'empty configured URL fails clearly'
);
