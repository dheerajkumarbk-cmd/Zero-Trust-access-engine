// Helper of scripts/demo-smoke.sh. usage: node demo-smoke.mjs <port> <people.txt path> <counts-file>
// Env: DWARPAL_PW_DIR (folder with node_modules/playwright-core), PW_CHANNEL (default chrome).
// Signs in as each demo account (password + PIN read from the throwaway lab's own people.txt), registers a random typed
// passkey, then launches one scenario as an analyst. Prints PASS/FAIL lines only: no secret is ever printed.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {createRequire} from 'node:module';

const [port, peopleFile, countsFile] = process.argv.slice(2);
const pwDir = process.env.DWARPAL_PW_DIR;
if (!port || !peopleFile || !countsFile || !pwDir) { console.log('FAIL setup - usage or DWARPAL_PW_DIR missing'); process.exit(2); }
const {chromium} = createRequire(path.join(pwDir, 'x.js'))('playwright-core');

const base = `https://localhost:${port}/`;
const ACCOUNTS = ['dana', 'spector', 'cleo', 'ana', 'ben', 'hana'];
const SCENARIO_AS = 'ana';
const KEY = crypto.randomBytes(12).toString('hex'); // per-run typed passkey, never printed

// people.txt lines: id|display name|ROLES|password|PIN  ('#' comments). Values stay in memory only.
const people = {};
for (const l of fs.readFileSync(peopleFile, 'utf8').split(/\r?\n/)) {
  if (!l.trim() || l.startsWith('#')) continue;
  const f = l.split('|');
  if (f.length === 5) people[f[0]] = {pw: f[3], pin: f[4]};
}
const secrets = Object.values(people).flatMap((p) => [p.pw, p.pin]).concat([KEY]).filter(Boolean);
const clean = (e) => {
  let m = String(e && e.message || e).split('\n')[0];
  for (const s of secrets) m = m.split(s).join('***');
  return m.slice(0, 100);
};

let total = 0, fails = 0;
const rec = (ok, name, t0, why) => {
  total++; if (!ok) fails++;
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name} (${((Date.now() - t0) / 1000).toFixed(1)}s)${why ? ' - ' + why : ''}`);
};

const browser = await chromium.launch({channel: process.env.PW_CHANNEL || 'chrome', headless: true});

async function signIn(who) {
  const ctx = await browser.newContext({ignoreHTTPSErrors: true, viewport: {width: 1280, height: 900}});
  const page = await ctx.newPage();
  const c = people[who];
  if (!c) throw new Error('no credentials for this account in the lab people file');
  await page.goto(base);
  await page.waitForSelector('#li-user', {timeout: 20000});
  await page.fill('#li-user', who);
  await page.fill('#li-pw', c.pw);
  await page.click('button[type=submit]');
  await page.fill('#li-pin', c.pin);
  await page.click('button[type=submit]');
  await page.waitForSelector('nav.side', {timeout: 20000});
  const me = await page.evaluate(async () => (await fetch('/console/api/me')).json().catch(() => ({})));
  const id = me && me.person && me.person.id;
  const pk = await page.evaluate(async ({pw, pin, key}) => {
    const m = await (await fetch('/console/api/me')).json().catch(() => ({}));
    const r = await fetch('/console/api/profile/passkey', {method: 'POST', headers: {'Content-Type': 'application/json', 'X-Dwarpal-CSRF': m.csrf || ''}, body: JSON.stringify({password: pw, pin, passkey: key})});
    return r.status;
  }, {pw: c.pw, pin: c.pin, key: KEY});
  return {ctx, page, id, pk};
}

for (const who of ACCOUNTS) {
  const t0 = Date.now();
  let s;
  try {
    s = await signIn(who);
    const ok = s.id === who;
    rec(ok, `sign-in ${who}`, t0, ok ? `nav.side visible, /me=${s.id}, passkey HTTP ${s.pk}` : 'wrong or missing user in /console/api/me');
  } catch (e) { rec(false, `sign-in ${who}`, t0, clean(e)); }
  if (who === SCENARIO_AS) {
    const t1 = Date.now();
    let name = '';
    try {
      if (!s) throw new Error('sign-in failed, no session');
      const page = s.page;
      await page.reload(); await page.waitForSelector('nav.side a');
      const unlock = async () => {
        if (await page.locator('#pk-key').count()) {
          await page.fill('#pk-key', KEY); await page.click('dialog[open] button[type=submit]'); await page.waitForTimeout(1500);
        }
      };
      await page.locator('nav.side a', {hasText: /^Scenario lab$/}).first().click();
      await page.waitForTimeout(1200); await unlock();
      await page.waitForSelector('.lab-card button', {timeout: 15000});
      const card = page.locator('.lab-card').first();
      name = ((await card.locator('h3').first().textContent()) || '').trim();
      const resp = page.waitForResponse((r) => r.request().method() === 'POST' && /\/lab\/launch\//.test(r.url()), {timeout: 20000});
      await card.locator('button').first().click();
      await page.waitForTimeout(800); await unlock();
      const r = await resp;
      await page.waitForSelector('.lab-result h3', {timeout: 15000});
      const shown = ((await page.locator('.lab-result h3').first().textContent()) || '').trim();
      rec(r.status() >= 200 && r.status() < 300 && /^Launched/.test(shown), `scenario launch as ${SCENARIO_AS}`, t1, `${name.slice(0, 40)}; POST ${r.status()}; page shows "${shown.slice(0, 30)}"`);
    } catch (e) { rec(false, `scenario launch as ${SCENARIO_AS}`, t1, `${name.slice(0, 40)}; ${clean(e)}`); }
  }
  if (s) await s.ctx.close().catch(() => {});
}
await browser.close();
fs.writeFileSync(countsFile, `${total} ${fails}\n`);
process.exit(fails ? 1 : 0);
