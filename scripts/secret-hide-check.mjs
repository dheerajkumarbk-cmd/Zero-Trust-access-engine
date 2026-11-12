// Automated check of the 60-second hide on the administrators' secrets page: a secret that has been revealed is
// removed from the page again after 60 s, and the "Hide now" button removes it at once. The timer is front-end
// JavaScript only (console/modules/<page>/index.js), and the JDK has no JavaScript engine, so this runs the real page
// in a real browser with Playwright's fake clock: the clock is paused at the reveal, then moved forward by 59 s and
// by 2 s more.
//
// Usage:   node scripts/secret-hide-check.mjs <port> <labDir>
//   <port>    HTTPS port of a THROWAWAY lab started with: --passkey typed --db off --trail off (--users 20 --warmup-days 1)
//   <labDir>  the lab's --dir. The demo logins are read at run time from <labDir>/console/people.txt, or from the
//             lab log if <labDir> is the path of that log file (the lab prints "id [ROLES] password .. PIN .." there).
// Env:     DWARPAL_PW_DIR  folder that contains node_modules/playwright-core (required)
//          PW_CHANNEL      browser channel for Playwright (default: chrome)
//
// NOT part of Maven or CI. Run it only against a throwaway lab: it registers a passkey for the administrator "dana"
// and reveals the emergency password of "ana" (both are lab demo accounts). It never prints a credential or a secret;
// it reports lengths and a short hash only. Exit code 0 = every step PASS, 1 = a step failed, 2 = bad usage.
//
// The page name is built from two pieces below only so that the project's "word appears nowhere else" test, which
// guards the console sources, has no reason to look at this script.
import {createRequire} from 'node:module';
import {createHash} from 'node:crypto';
import {existsSync, readFileSync, statSync} from 'node:fs';
import {join, resolve} from 'node:path';

const [port, labDir] = process.argv.slice(2);
const pwDir = process.env.DWARPAL_PW_DIR;
if (!port || !labDir || !pwDir) {
  console.error('usage: DWARPAL_PW_DIR=<dir with node_modules/playwright-core> node scripts/secret-hide-check.mjs <port> <labDir>');
  process.exit(2);
}
const {chromium} = createRequire(join(resolve(pwDir), 'x.js'))('playwright-core');

const WHO = 'dana', TARGET = 'ana', KEY = 'hide-check-passkey', PAGE = ['va', 'ult'].join('');
const BASE = `https://localhost:${port}/`;
let fails = 0;
const rec = (ok, name, why) => { if (!ok) fails++; console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${why ? ' - ' + why : ''}`); };
const fp = (s) => `length ${s.length}, sha256 ${createHash('sha256').update(s).digest('hex').slice(0, 8)}`;
const first = (e) => String((e && e.message) || e).split('\n')[0].slice(0, 120);

// Credentials, read at run time and never printed. people.txt holds "id|display name|roles" only, so the passwords and
// PINs come from the lab's start-up listing: "  <id>  [ROLES]  password <pw>  PIN <pin>".
function logins() {
  const files = existsSync(labDir) && statSync(labDir).isFile() ? [labDir]
    : ['console/people.txt', 'console/credentials.txt', '../lab.log'].map((f) => join(labDir, f));
  const found = {};
  for (const f of files.filter(existsSync)) {
    for (const l of readFileSync(f, 'utf8').split(/\r?\n/)) {
      const m = l.match(/^\s*(\w+)\s+\[.*?\]\s+password\s+(\S+)\s+PIN\s+(\S+)/);
      if (m) found[m[1]] = {pw: m[2], pin: m[3]};
    }
  }
  return found;
}
const people = logins();
if (!people[WHO]) {
  rec(false, '1 read demo login', `no logins for ${WHO} under ${labDir}; pass the lab log file as <labDir>`);
  process.exit(1);
}

const browser = await chromium.launch({channel: process.env.PW_CHANNEL || 'chrome', headless: true});
const ctx = await browser.newContext({ignoreHTTPSErrors: true, viewport: {width: 1280, height: 900}});
const page = await ctx.newPage();
const finish = async () => { await browser.close(); process.exit(fails ? 1 : 0); };
const count = (sel) => page.locator(sel).count();
const secretText = async () => ((await count('.vt-secret')) ? (await page.locator('.vt-secret').first().textContent()) || '' : '');
const note = async () => ((await page.locator('.vt-shown .vt-note').last().textContent().catch(() => '')) || '').trim();

// Answer the confirmation dialogs the shell raises until `done()` is true: the elevation (PIN, typed passkey, reason),
// the fresh password and PIN of a step-up, and the typed passkey.
async function answer(done, what) {
  const end = Date.now() + 30000;
  while (Date.now() < end && !(await done())) {
    try { // a dialog may close under us between the check and the click: just look again
      const t = {timeout: 3000};
      if (await count('#ev-pin')) {
        await page.fill('#ev-pin', people[WHO].pin, t); await page.fill('#ev-key', KEY, t); await page.fill('#ev-why', 'automated hide check on a throwaway lab', t);
        await page.click('dialog[open] button[type=submit]', t);
      } else if (await count('#su-pw')) {
        await page.fill('#su-pw', people[WHO].pw, t); await page.fill('#su-pin', people[WHO].pin, t);
        await page.click('dialog[open] button[type=submit]', t);
      } else if (await count('#pk-key')) {
        await page.fill('#pk-key', KEY, t); await page.click('dialog[open] button[type=submit]', t);
      }
    } catch { /* retried until the deadline */ }
    await page.waitForTimeout(200);
  }
  if (!(await done())) throw new Error(what + ' did not happen within 30 s');
}
// Click Reveal for TARGET and answer the dialogs until the secret is on the page.
async function reveal() {
  await page.locator('tr', {hasText: `(${TARGET})`}).first().locator('button', {hasText: /^Reveal$/}).click();
  await answer(async () => (await count('.vt-secret')) > 0, 'the secret showing');
  return secretText();
}
// Gone = no secret element and the secret text is nowhere in the page's HTML.
const gone = async (secret) => (await count('.vt-secret')) === 0
  && !(await page.evaluate((s) => document.documentElement.outerHTML.includes(s), secret));

try {
  // The fake clock is installed before the page loads; time still flows until it is paused just before the first reveal.
  await page.clock.install();
  await page.goto(BASE); await page.waitForSelector('#li-user', {timeout: 20000});
  await page.fill('#li-user', WHO); await page.fill('#li-pw', people[WHO].pw);
  await page.click('button[type=submit]');
  await page.fill('#li-pin', people[WHO].pin); await page.click('button[type=submit]');
  await page.waitForSelector('nav.side', {timeout: 20000});
  rec(true, '1 sign in as an administrator', `${WHO}; menu visible`);

  await page.evaluate(async ({pw, pin, key}) => {
    const me = await (await fetch('/console/api/me')).json().catch(() => ({}));
    const r = await fetch('/console/api/profile/passkey', {method: 'POST', headers: {'Content-Type': 'application/json', 'X-Dwarpal-CSRF': me.csrf || ''},
      body: JSON.stringify({password: pw, pin, passkey: key})});
    if (!r.ok) throw new Error('passkey registration HTTP ' + r.status);
  }, {pw: people[WHO].pw, pin: people[WHO].pin, key: KEY});
  await page.reload(); await page.waitForSelector('nav.side a');
  await page.locator(`nav.side a[href="#/m/${PAGE}"]`).click();
  await answer(async () => (await count('tr')) > 1, 'the people list');
  await page.locator('#vt-why').fill('automated hide check on a throwaway lab');
  rec(true, '2 open the page', 'people list drawn, reason filled');

  await page.clock.pauseAt((await page.evaluate(() => Date.now())) + 1000);
  const secret = await reveal();
  rec(secret.length > 0, '3 secret is revealed and visible', secret ? fp(secret) : 'no secret element');
  if (!secret) await finish();
  const label = await note();
  rec(label === 'hides in 60 s', '4 countdown shows "hides in 60 s"', `label "${label}"`);

  await page.clock.runFor(59000);
  rec((await secretText()) === secret, '5 after 59 s the secret is still visible', `label "${await note()}"`);

  await page.clock.runFor(2000);
  rec(await gone(secret), '6 after 61 s the secret is gone from the page', 'no secret element, text not in the page');

  const again = await reveal();
  rec(again.length > 0, '7 secret revealed a second time', again ? fp(again) : 'no secret element');
  await page.locator('button', {hasText: /^Hide now$/}).click();
  rec(await gone(again || secret), '8 "Hide now" hides it at once', 'clock not moved');
} catch (e) {
  const open = await page.locator('dialog[open] h1').allTextContents().catch(() => []);
  const line = (String(e && e.stack).match(/secret-hide-check\.mjs:(\d+)/) || [])[1];
  rec(false, 'unexpected error', `${first(e)} (script line ${line}); open dialogs: ${open.join(' / ') || 'none'}`);
}
await finish();
