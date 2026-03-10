const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');

const repoRoot = path.resolve(__dirname, '..');
const serverPath = path.join(repoRoot, 'src', 'server.js');

function randomPort() {
  return 35000 + Math.floor(Math.random() * 20000);
}

async function waitForHealth(baseUrl, timeoutMs = 10000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const res = await fetch(`${baseUrl}/api/health`);
      if (res.ok) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('Server did not become ready in time');
}

async function withServer(extraEnv, run) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'parking-test-'));
  const previousCwd = process.cwd();
  const previousEnv = {};
  const port = randomPort();
  const envPatch = {
    PORT: String(port),
    APP_BASE_URL: `http://127.0.0.1:${port}`,
    ...extraEnv
  };

  fs.writeFileSync(path.join(tempDir, 'index.html'), '<!doctype html><html><body>test</body></html>');
  process.chdir(tempDir);
  for (const [key, value] of Object.entries(envPatch)) {
    previousEnv[key] = process.env[key];
    process.env[key] = value;
  }

  delete require.cache[require.resolve(serverPath)];
  const mod = require(serverPath);
  try {
    await waitForHealth(envPatch.APP_BASE_URL);
    await run(envPatch.APP_BASE_URL);
  } finally {
    await mod.closeServer();
    delete require.cache[require.resolve(serverPath)];
    process.chdir(previousCwd);
    for (const [key, value] of Object.entries(previousEnv)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

async function jsonRequest(baseUrl, pathname, { method = 'GET', token, body, headers = {} } = {}) {
  const res = await fetch(`${baseUrl}${pathname}`, {
    method,
    headers: {
      ...(body ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...headers
    },
    body: body ? JSON.stringify(body) : undefined
  });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch {}
  return { status: res.status, json, text, headers: res.headers };
}

test('bootstrap is protected by token in production mode', async () => {
  await withServer({ NODE_ENV: 'production', BOOTSTRAP_TOKEN: 'install-secret' }, async (baseUrl) => {
    const health = await jsonRequest(baseUrl, '/api/health');
    assert.equal(health.status, 200);
    assert.equal(health.json.bootstrapRequiresToken, true);

    const denied = await jsonRequest(baseUrl, '/api/bootstrap', {
      method: 'POST',
      body: { adminPassword: 'strongpass1' }
    });
    assert.equal(denied.status, 403);

    const allowed = await jsonRequest(baseUrl, '/api/bootstrap', {
      method: 'POST',
      body: { adminPassword: 'strongpass1', bootstrapToken: 'install-secret' }
    });
    assert.equal(allowed.status, 200);
  });
});

test('login is rate-limited and sessions can be revoked', async () => {
  await withServer({ AUTH_RATE_LIMIT_MAX: '2', RATE_LIMIT_WINDOW_MS: '1000' }, async (baseUrl) => {
    await jsonRequest(baseUrl, '/api/bootstrap', {
      method: 'POST',
      body: { adminPassword: 'strongpass1' }
    });

    const bad1 = await jsonRequest(baseUrl, '/api/login', {
      method: 'POST',
      body: { username: 'admin', password: 'wrongpass' }
    });
    const bad2 = await jsonRequest(baseUrl, '/api/login', {
      method: 'POST',
      body: { username: 'admin', password: 'wrongpass' }
    });
    const limited = await jsonRequest(baseUrl, '/api/login', {
      method: 'POST',
      body: { username: 'admin', password: 'wrongpass' }
    });
    assert.equal(bad1.status, 401);
    assert.equal(bad2.status, 401);
    assert.equal(limited.status, 429);

    await new Promise((resolve) => setTimeout(resolve, 1100));
    const login = await jsonRequest(baseUrl, '/api/login', {
      method: 'POST',
      body: { username: 'admin', password: 'strongpass1' }
    });
    assert.equal(login.status, 200);

    const token = login.json.token;
    const me = await jsonRequest(baseUrl, '/api/me', { token });
    assert.equal(me.status, 200);

    const logout = await jsonRequest(baseUrl, '/api/logout', { method: 'POST', token });
    assert.equal(logout.status, 200);

    const meAfterLogout = await jsonRequest(baseUrl, '/api/me', { token });
    assert.equal(meAfterLogout.status, 401);
  });
});

test('sessions expire based on configured ttl', async () => {
  await withServer({ SESSION_TTL_SECONDS: '1' }, async (baseUrl) => {
    await jsonRequest(baseUrl, '/api/bootstrap', {
      method: 'POST',
      body: { adminPassword: 'strongpass1' }
    });
    const login = await jsonRequest(baseUrl, '/api/login', {
      method: 'POST',
      body: { username: 'admin', password: 'strongpass1' }
    });
    assert.equal(login.status, 200);
    const token = login.json.token;
    await new Promise((resolve) => setTimeout(resolve, 1200));
    const me = await jsonRequest(baseUrl, '/api/me', { token });
    assert.equal(me.status, 401);
  });
});

test('user validation, floor/space CRUD, and booking overlap rules work', async () => {
  await withServer({}, async (baseUrl) => {
    await jsonRequest(baseUrl, '/api/bootstrap', {
      method: 'POST',
      body: { adminPassword: 'strongpass1' }
    });
    const login = await jsonRequest(baseUrl, '/api/login', {
      method: 'POST',
      body: { username: 'admin', password: 'strongpass1' }
    });
    const token = login.json.token;

    const invalidUser = await jsonRequest(baseUrl, '/api/users', {
      method: 'POST',
      token,
      body: { username: 'bob', fullName: 'Bob', password: '1234' }
    });
    assert.equal(invalidUser.status, 400);

    const user = await jsonRequest(baseUrl, '/api/users', {
      method: 'POST',
      token,
      body: { username: 'bob', fullName: 'Bob', password: 'strongpass2' }
    });
    assert.equal(user.status, 200);

    const floor = await jsonRequest(baseUrl, '/api/floors', {
      method: 'POST',
      token,
      body: { name: 'Main floor' }
    });
    assert.equal(floor.status, 200);

    const space = await jsonRequest(baseUrl, '/api/spaces', {
      method: 'POST',
      token,
      body: { floorId: floor.json.id, spaceNumber: 'A1' }
    });
    assert.equal(space.status, 200);

    const booking = await jsonRequest(baseUrl, '/api/bookings', {
      method: 'POST',
      token,
      body: {
        floorId: floor.json.id,
        spaceId: space.json.id,
        userId: user.json.id,
        startDate: '2026-04-01',
        endDate: '2026-04-03'
      }
    });
    assert.equal(booking.status, 200);

    const overlap = await jsonRequest(baseUrl, '/api/bookings', {
      method: 'POST',
      token,
      body: {
        floorId: floor.json.id,
        spaceId: space.json.id,
        userId: user.json.id,
        startDate: '2026-04-02',
        endDate: '2026-04-05'
      }
    });
    assert.equal(overlap.status, 400);

    const release = await jsonRequest(baseUrl, '/api/bookings/release', {
      method: 'POST',
      token,
      body: {
        spaceId: space.json.id,
        date: '2026-04-02',
        userId: user.json.id,
        releaseStart: '2026-04-02',
        releaseEnd: '2026-04-02'
      }
    });
    assert.equal(release.status, 200);

    const bookings = await jsonRequest(baseUrl, `/api/bookings?floorId=${floor.json.id}`, { token });
    assert.equal(bookings.status, 200);
    assert.equal(bookings.json.length, 2);
    assert.deepEqual(bookings.json.map((row) => [row.start_date, row.end_date]), [
      ['2026-04-01', '2026-04-01'],
      ['2026-04-03', '2026-04-03']
    ]);
  });
});

test('admin SSO configuration validates redirect URI and enablement prerequisites', async () => {
  await withServer({}, async (baseUrl) => {
    await jsonRequest(baseUrl, '/api/bootstrap', {
      method: 'POST',
      body: { adminPassword: 'strongpass1' }
    });
    const login = await jsonRequest(baseUrl, '/api/login', {
      method: 'POST',
      body: { username: 'admin', password: 'strongpass1' }
    });
    const token = login.json.token;

    const badRedirect = await jsonRequest(baseUrl, '/api/admin/sso', {
      method: 'POST',
      token,
      body: { enabled: false, tenantId: 'common', clientId: 'cid', redirectUri: 'not-a-url' }
    });
    assert.equal(badRedirect.status, 400);

    const cannotEnable = await jsonRequest(baseUrl, '/api/admin/sso', {
      method: 'POST',
      token,
      body: { enabled: true, tenantId: 'common', clientId: 'cid', redirectUri: 'https://example.com/callback' }
    });
    assert.equal(cannotEnable.status, 400);
  });
});
