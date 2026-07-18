export interface ApiEnvironment {
  VITE_API_BASE_URL?: string;
  MODE?: string;
  DEV?: boolean;
  PROD?: boolean;
}

export const DEVELOPMENT_API_BASE_URL = '/api/v1';

export function normalizeApiBaseUrl(value: string): string {
  const trimmed = value.trim();

  if (!trimmed) {
    throw new Error('VITE_API_BASE_URL is configured but empty.');
  }

  return trimmed.replace(/\/+$/, '');
}

export function resolveApiBaseUrl(env: ApiEnvironment): string {
  const configured = env.VITE_API_BASE_URL;

  if (typeof configured === 'string' && configured.trim()) {
    return normalizeApiBaseUrl(configured);
  }

  if (env.DEV === true || env.MODE === 'development') {
    return DEVELOPMENT_API_BASE_URL;
  }

  throw new Error(
    'VITE_API_BASE_URL is required outside development; refusing to fall back to localhost.'
  );
}

export function resolveImportMetaApiBaseUrl(): string {
  const env =
    ((import.meta as unknown as { env?: ApiEnvironment }).env ?? {}) as ApiEnvironment;

  return resolveApiBaseUrl(env);
}
