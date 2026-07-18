import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import url from 'node:url';

const root = path.resolve(url.fileURLToPath(new URL('..', import.meta.url)));
const sourceDir = path.join(root, 'src', 'services');

function createStorage(initial = {}) {
  const data = new Map(Object.entries(initial));
  return {
    getItem(key) {
      return data.has(key) ? data.get(key) : null;
    },
    setItem(key, value) {
      data.set(key, String(value));
    },
    removeItem(key) {
      data.delete(key);
    },
    dump() {
      return Object.fromEntries(data);
    },
  };
}

function encodeToken(expOffsetSeconds = 3600) {
  const payload = Buffer.from(
    JSON.stringify({ exp: Math.floor(Date.now() / 1000) + expOffsetSeconds }),
  ).toString('base64url');
  return `header.${payload}.signature`;
}

async function loadAuthModule(postImpl) {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), 'tot-auth-refresh-'));

  const apiModule = `
    export const calls = [];
    export async function post(path, body) {
      calls.push({ path, body });
      return globalThis.__authPost(path, body);
    }
    export async function get() { throw new Error('get not expected'); }
    export async function del() { return { data: null }; }
    export async function put() { throw new Error('put not expected'); }
  `;

  const authSource = await readFile(path.join(sourceDir, 'auth.ts'), 'utf8');
  const authModule = authSource.replace("from './api'", "from './api.mjs'");

  await writeFile(path.join(tempDir, 'api.mjs'), apiModule);
  await writeFile(path.join(tempDir, 'auth.mts'), authModule);

  const storage = createStorage({
    tot_auth_tokens: JSON.stringify({
      accessToken: encodeToken(),
      refreshToken: 'refresh-original',
      expiresIn: 120,
      tokenType: 'Bearer',
    }),
    tot_user_data: JSON.stringify({ id: 'u1' }),
  });

  globalThis.localStorage = storage;
  globalThis.window = {
    setTimeout() {
      return 1;
    },
    clearTimeout() {},
  };
  globalThis.__authPost = postImpl;

  const auth = await import(`${url.pathToFileURL(path.join(tempDir, 'auth.mts')).href}?t=${Date.now()}`);
  const api = await import(url.pathToFileURL(path.join(tempDir, 'api.mjs')).href);

  return {
    api,
    auth,
    async cleanup() {
      delete globalThis.__authPost;
      delete globalThis.localStorage;
      delete globalThis.window;
      await rm(tempDir, { recursive: true, force: true });
    },
    storage,
  };
}

test('refreshTokens shares one in-flight refresh across concurrent callers', async () => {
  let resolveRefresh;
  let requestCount = 0;
  const refreshedTokens = {
    accessToken: encodeToken(),
    refreshToken: 'refresh-next',
    expiresIn: 300,
    tokenType: 'Bearer',
  };

  const { api, auth, cleanup, storage } = await loadAuthModule((pathName, body) => {
    requestCount += 1;
    assert.equal(pathName, '/auth/refresh');
    assert.deepEqual(body, { refreshToken: 'refresh-original' });
    return new Promise(resolve => {
      resolveRefresh = () => resolve({ data: { tokens: refreshedTokens } });
    });
  });

  try {
    const first = auth.refreshTokens();
    const second = auth.refreshTokens();
    const third = auth.refreshTokens();

    assert.equal(first, second);
    assert.equal(second, third);
    assert.equal(requestCount, 1);

    resolveRefresh();
    const results = await Promise.all([first, second, third]);

    assert.deepEqual(results, [refreshedTokens, refreshedTokens, refreshedTokens]);
    assert.equal(api.calls.length, 1);
    assert.deepEqual(JSON.parse(storage.dump().tot_auth_tokens), refreshedTokens);
  } finally {
    await cleanup();
  }
});

test('refreshTokens clears auth state once when the shared refresh fails', async () => {
  let rejectRefresh;
  let requestCount = 0;

  const { auth, cleanup, storage } = await loadAuthModule(() => {
    requestCount += 1;
    return new Promise((_, reject) => {
      rejectRefresh = () => reject(new Error('refresh failed'));
    });
  });

  try {
    let notificationCount = 0;
    auth.onAuthChange(user => {
      assert.equal(user, null);
      notificationCount += 1;
    });

    const first = auth.refreshTokens();
    const second = auth.refreshTokens();

    assert.equal(first, second);
    assert.equal(requestCount, 1);

    rejectRefresh();
    const results = await Promise.all([first, second]);

    assert.deepEqual(results, [null, null]);
    assert.equal(notificationCount, 1);
    assert.equal(storage.dump().tot_auth_tokens, undefined);
    assert.equal(storage.dump().tot_user_data, undefined);

    await auth.refreshTokens();
    assert.equal(requestCount, 1);
  } finally {
    await cleanup();
  }
});
