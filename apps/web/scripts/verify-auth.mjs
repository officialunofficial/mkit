#!/usr/bin/env node
// One real WebAuthn identity; no workspace creation, terminal, or model requests.
import assert from 'node:assert/strict';
import { access } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';

const args = process.argv.slice(2);
if (args.includes('--help')) {
  console.log('Usage: node scripts/verify-auth.mjs [http://localhost:4173] [--mock-session]\nOptional: CHROME_EXECUTABLE=/path/to/chromium');
  process.exit(0);
}
const mockSession = args.includes('--mock-session');
const positional = args.filter((arg) => !arg.startsWith('--'));
if (positional.length > 1 || args.some((arg) => arg.startsWith('--') && arg !== '--mock-session')) {
  console.log(JSON.stringify({ passed: false, stage: 'arguments', error: 'Expected one URL and optional --mock-session.' }));
  process.exit(1);
}

const routes = [
  ['/', 'Overview'], ['/create', 'Create'], ['/concepts', 'Concepts'],
  ['/performance', 'Performance'], ['/parity', 'Parity'], ['/specs', 'Specs'], ['/multiplayer', 'Multiplayer'],
];
const report = { passed: false, mockSession, checks: [], ceremonies: { created: 0, asserted: 0 } };
let browser;
let chromium;
let stage = 'browser setup';
let base;
let session = null;
let sessionDeletes = 0;
let forbiddenWrites = 0;
let browserErrors = 0;

function check(name) { report.checks.push(name); }

async function executablePath() {
  if (process.env.CHROME_EXECUTABLE) return process.env.CHROME_EXECUTABLE;
  const candidates = [chromium.executablePath(),
    ...(process.platform === 'darwin' ? ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'] : []),
    '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome',
  ];
  for (const candidate of candidates) {
    try { await access(candidate); return candidate; } catch { /* Try the next installed browser. */ }
  }
  throw new Error('Chromium not installed');
}

async function account(page, auth, signing, publicKey) {
  await page.waitForFunction(({ auth, signing, publicKey }) => {
    const node = document.querySelector('[aria-label="Account"][data-auth-status]');
    return node?.getAttribute('data-auth-status') === auth
      && node.getAttribute('data-signing-status') === signing
      && (publicKey === undefined || node.getAttribute('data-public-key') === publicKey);
  }, { auth, signing, publicKey });
  assert.equal(await page.locator('[aria-label="Account"][data-auth-status]').count(), 1);
}

function accountRegion(page) {
  return page.locator('[aria-label="Account"][data-auth-status]');
}

async function navigate(page, path, label) {
  if (new URL(page.url()).pathname === path) return;
  await page.locator('nav[aria-label="Primary"]:visible').getByRole('link', { name: label, exact: true }).click();
  await page.waitForURL((url) => url.origin === base.origin && url.pathname === path, { waitUntil: 'domcontentloaded' });
}

function ceremonyCount() { return JSON.stringify(report.ceremonies); }

async function storageIsPublic(page) {
  // Values stay inside this process. The report contains names of checks only.
  const storage = await page.evaluate(() => [localStorage, sessionStorage].map((store) =>
    Object.fromEntries(Array.from({ length: store.length }, (_, i) => {
      const key = store.key(i);
      return [key, store.getItem(key)];
    })),
  ));
  for (const entries of storage) {
    if (entries['mkit-identity']) {
      const persisted = JSON.parse(entries['mkit-identity']);
      assert.deepEqual(Object.keys(persisted).sort(), ['state', 'version']);
      const allowed = new Set(['credentialId', 'p256PubkeyHex', 'knownPublicKey', 'room', 'name']);
      assert(Object.keys(persisted.state).every((key) => allowed.has(key)));
      assert(Object.values(persisted.state).every((value) => value === null || typeof value === 'string'));
    }
    if (entries['mkit-auth-change']) {
      const signal = JSON.parse(entries['mkit-auth-change']);
      assert.deepEqual(Object.keys(signal).sort(), ['action', 'nonce']);
      assert(['session', 'logout', 'lock'].includes(signal.action));
      assert.equal(typeof signal.nonce, 'string');
    }
    if (entries['mkit-query-cache']) {
      const cache = JSON.parse(entries['mkit-query-cache']);
      assert.deepEqual(cache.clientState.mutations, []);
      for (const query of cache.clientState.queries) {
        assert.equal(query.queryKey.length, 3);
        assert.equal(query.queryKey[0], 'keys');
        assert.equal(query.queryKey[1], 'name');
        assert.match(query.queryKey[2], /^[0-9a-f]{64}$/);
        assert(query.state.data === null || typeof query.state.data === 'string');
      }
    }
    // Catch signing/session authority accidentally persisted under a new app key too.
    for (const [key, value] of Object.entries(entries)) {
      if (!key.startsWith('mkit')) continue;
      assert(!/"(?:seedHex|seed|privateKey|unlocked|signingStatus|accessToken|sessionToken)"\s*:/.test(value));
    }
  }
}

try {
  base = new URL(positional[0] ?? 'http://localhost:4173');
  assert(['http:', 'https:'].includes(base.protocol));
  assert(!base.username && !base.password && !base.search && !base.hash);
  report.origin = base.origin;
  ({ chromium } = await import('playwright-core'));
  browser = await chromium.launch({ headless: true, executablePath: await executablePath() });
  report.browser = browser.version();
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  context.setDefaultTimeout(30_000);
  context.setDefaultNavigationTimeout(45_000);
  context.on('page', (page) => page.on('pageerror', () => { browserErrors++; }));
  await context.route('**/*', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const method = request.method();
    const isSession = url.origin === base.origin && url.pathname === '/api/workspaces/session';
    if (isSession && method === 'DELETE') sessionDeletes++;
    if (url.origin === base.origin && url.pathname.startsWith('/api/workspaces') && !isSession
      && !['GET', 'HEAD', 'OPTIONS'].includes(method)) {
      forbiddenWrites++;
      await route.abort();
      return;
    }
    if (!mockSession || !isSession) { await route.continue(); return; }
    if (method === 'POST') {
      const publicKey = request.headers()['x-public-key'];
      if (!publicKey || !/^[0-9a-f]{64}$/.test(publicKey)) {
        await route.fulfill({ status: 400, json: { error: 'Missing public signing identity.' } });
        return;
      }
      session = { id: randomUUID(), publicKey, expiresAt: Date.now() + 7 * 86_400_000 };
    } else if (method === 'DELETE') session = null;
    else if (method !== 'GET') { await route.fulfill({ status: 405, body: '' }); return; }
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(session) });
  });
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable', { enableUI: false });
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
    protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal', hasResidentKey: true,
    hasUserVerification: true, hasPrf: true, isUserVerified: true, automaticPresenceSimulation: true,
  } });
  cdp.on('WebAuthn.credentialAdded', () => { report.ceremonies.created++; });
  cdp.on('WebAuthn.credentialAsserted', () => { report.ceremonies.asserted++; });

  stage = 'shared account signed-out state';
  await page.goto(base.origin, { waitUntil: 'domcontentloaded' });
  await account(page, 'signed-out', 'locked', '');
  stage = 'native passkey creation';
  await accountRegion(page).getByRole('button', { name: 'Sign in', exact: true }).click();
  await accountRegion(page).getByRole('button', { name: 'Create a passkey', exact: true }).click();
  await page.getByRole('button', { name: 'Close account', exact: true }).click();
  await account(page, 'signed-in', 'unlocked');
  const publicKey = await accountRegion(page).getAttribute('data-public-key');
  assert.match(publicKey, /^[0-9a-f]{64}$/);
  assert.equal(report.ceremonies.created, 1);
  const afterCreate = ceremonyCount();
  await storageIsPublic(page);
  check('one native PRF identity created; persisted state contains no signing authority');

  stage = 'SPA navigation across all seven routes';
  for (const [path, label] of routes) {
    await navigate(page, path, label);
    await account(page, 'signed-in', 'unlocked', publicKey);
    assert.equal(ceremonyCount(), afterCreate);
  }
  await page.goBack({ waitUntil: 'domcontentloaded' });
  await account(page, 'signed-in', 'unlocked', publicKey);
  await page.goForward({ waitUntil: 'domcontentloaded' });
  await account(page, 'signed-in', 'unlocked', publicKey);
  assert.equal(ceremonyCount(), afterCreate);
  check('seven routes and browser history preserve identity and signing unlock without another ceremony');

  stage = 'second tab preserves existing login and first-tab signing';
  const other = await context.newPage();
  await other.goto(base.origin + '/concepts', { waitUntil: 'domcontentloaded' });
  await account(other, 'signed-in', 'locked', publicKey);
  await account(page, 'signed-in', 'unlocked', publicKey);
  check('second tab remembers login without unlocking signing or revoking the first tab');

  stage = 'lock signing broadcasts without signing out';
  if (!(await accountRegion(page).getByRole('button', { name: 'Lock signing', exact: true }).isVisible())) await accountRegion(page).getByRole('button', { name: 'Account', exact: true }).click();
  await accountRegion(page).getByRole('button', { name: 'Lock signing', exact: true }).click();
  if (await page.getByRole('button', { name: 'Close account', exact: true }).isVisible()) await page.getByRole('button', { name: 'Close account', exact: true }).click();
  await account(page, 'signed-in', 'locked', publicKey);
  await account(other, 'signed-in', 'locked', publicKey);
  assert.equal(ceremonyCount(), afterCreate);
  stage = 'native signing recovery';
  if (!(await accountRegion(page).getByRole('button', { name: 'Unlock signing', exact: true }).isVisible())) await accountRegion(page).getByRole('button', { name: 'Account', exact: true }).click();
  await accountRegion(page).getByRole('button', { name: 'Unlock signing', exact: true }).click();
  if (await page.getByRole('button', { name: 'Close account', exact: true }).isVisible()) await page.getByRole('button', { name: 'Close account', exact: true }).click();
  await account(page, 'signed-in', 'unlocked', publicKey);
  assert.equal(report.ceremonies.created, 1);
  assert(report.ceremonies.asserted > JSON.parse(afterCreate).asserted);
  const afterUnlock = ceremonyCount();
  check('explicit lock preserves login; native unlock recovers the same public identity');

  stage = 'refresh on every route remembers login and locks signing';
  for (const [path, label] of routes) {
    stage = `refresh remembers login: ${path}`;
    await navigate(page, path, label);
    await page.reload({ waitUntil: 'domcontentloaded' });
    await account(page, 'signed-in', 'locked', publicKey);
    assert.equal(ceremonyCount(), afterUnlock);
    await storageIsPublic(page);
  }
  check('refresh on all seven routes remembers identity without automatic passkey prompts');

  stage = 'unlock signing before remote sign-out';
  if (!(await accountRegion(page).getByRole('button', { name: 'Unlock signing', exact: true }).isVisible())) await accountRegion(page).getByRole('button', { name: 'Account', exact: true }).click();
  await accountRegion(page).getByRole('button', { name: 'Unlock signing', exact: true }).click();
  if (await page.getByRole('button', { name: 'Close account', exact: true }).isVisible()) await page.getByRole('button', { name: 'Close account', exact: true }).click();
  await account(page, 'signed-in', 'unlocked', publicKey);
  assert.equal(report.ceremonies.created, 1);
  assert(report.ceremonies.asserted > JSON.parse(afterUnlock).asserted);
  const beforeSignout = ceremonyCount();
  stage = 'reference-page sign-out reaches both tabs';
  const deletesBeforeSignout = sessionDeletes;
  if (!(await accountRegion(other).getByRole('button', { name: 'Sign out', exact: true }).isVisible())) await accountRegion(other).getByRole('button', { name: 'Account', exact: true }).click();
  await accountRegion(other).getByRole('button', { name: 'Sign out', exact: true }).click();
  if (await other.getByRole('button', { name: 'Close account', exact: true }).isVisible()) await other.getByRole('button', { name: 'Close account', exact: true }).click();
  await account(other, 'signed-out', 'locked', '');
  await account(page, 'signed-out', 'locked', '');
  assert(sessionDeletes > deletesBeforeSignout);
  await page.reload({ waitUntil: 'domcontentloaded' });
  await account(page, 'signed-out', 'locked', '');
  await storageIsPublic(page);
  await storageIsPublic(other);
  assert.equal(ceremonyCount(), beforeSignout);
  assert.equal(forbiddenWrites, 0);
  assert.equal(browserErrors, 0);
  check('reference-page sign-out reaches both tabs and survives refresh; persisted caches are public only');
  report.passed = true;
} catch (error) {
  report.errorType = error?.name ?? 'Error';
  if (error?.name === 'AssertionError') report.assertion = error.message.split('\n').slice(0, 4).join('\n');
  // Never serialize Playwright exceptions: their call logs can contain cookies or request headers.
  report.stage = stage;
  report.error = 'Verification failed at this stage. Check the Account contract, session endpoint, and Chromium PRF support.';
  process.exitCode = 1;
} finally {
  if (browser) await browser.close().catch(() => {});
  console.log(JSON.stringify(report, null, 2));
}
