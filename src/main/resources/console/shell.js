// The shell: login, navigation built from /console/api/modules, routing, the live feed, keyboard, step-up, status bar.
import {api, ApiError, setUnlocker} from './api.js';
import {h, fill, unavailable} from './dom.js';
import {lists} from './table.js';
import {toast} from './toast.js';
import {explain, glossary} from './glossary.js';
import './views/login.js';
import './views/statusbar.js';
import './views/overview.js';
import './views/queue.js';
import './views/case.js';
import './views/hunt.js';
import './views/entity.js';
import './views/response.js';
import './views/audit.js';
import './views/attack.js';
import './views/scans.js';
import './views/profile.js';
import './views/home.js';

const BUILT_IN = {
  overview: 'dw-overview', queue: 'dw-queue', cases: 'dw-cases', hunt: 'dw-hunt', entity: 'dw-entity',
  response: 'dw-response', audit: 'dw-audit', attack: 'dw-attack', scans: 'dw-scans', home: 'dw-home',
};

/** One opening of confidential data. Browsing Audit records or running Hunt searches stays one opening; anything else is a new one. */
function place(hash) {
  const path = hash.replace(/^#\/?/, '').split('?')[0];
  const first = path.split('/')[0];
  return first === 'audit' || first === 'hunt' ? first : path;
}

class DwApp extends HTMLElement {
  constructor() {
    super();
    this.events = new EventTarget();
    this.lab = {time: null, state: 'UNKNOWN', speed: null, feed: 'connecting'};
    this.unlockState = null;
    this.clockEl = null;
    this.me = null;
    this.modules = [];
    this.closeStream = null;
    this.timers = [];
    this.moduleCleanup = null;
    this.focusHuntNext = false;
  }

  connectedCallback() {
    setUnlocker(() => this.needUnlock());
    window.addEventListener('dw:unlock', (e) => this.needUnlock(e.detail && e.detail.scope).then(() => this.route()).catch(() => {}));
    window.addEventListener('dw:change-due', () => this.mustChange());
    window.addEventListener('hashchange', () => this.moved());
    window.addEventListener('keydown', (e) => this.key(e));
    window.addEventListener('dw:session-ended', () => this.ended('Your session ended. Sign in again.'));
    this.boot();
  }

  get me() {
    return this.meState;
  }

  set me(value) {
    this.meState = value;
    this.syncUnlock();
  }

  /** The seconds the server says are left in the passkey windows, counted down here in real time. */
  syncUnlock() {
    const m = this.meState;
    this.unlockState = m && m.passkeyNeeded ? {win: m.unlockedSeconds || 0, aud: m.auditSeconds || 0, at: performance.now()} : null;
    this.wasOpen = !!(this.unlockState && this.unlockState.win > 0);
    this.paintClock();
  }

  /** What is left, from the countdown (never below zero). */
  unlockLeft() {
    const s = this.unlockState;
    if (!s) return {win: 0, aud: 0};
    const gone = (performance.now() - s.at) / 1000;
    return {win: Math.max(0, Math.round(s.win - gone)), aud: Math.max(0, Math.round(s.aud - gone))};
  }

  paintClock() {
    const el = this.clockEl;
    if (!el || !el.isConnected) return;
    if (!this.unlockState) {
      fill(el);
      return;
    }
    const left = this.unlockLeft();
    const mmss = (n) => Math.floor(n / 60) + ':' + String(n % 60).padStart(2, '0');
    if (left.win === 0) {
      fill(el, 'Confidential views are locked.');
      return;
    }
    fill(el, 'Confidential views open for ' + mmss(left.win) + (left.aud > 0 ? ' (audit explorer ' + mmss(left.aud) + ')' : '') + '. ',
      h('button', {type: 'button', on: {click: () => this.lockNow()}}, 'Lock now'));
  }

  /** Once a second: the footer's countdown, and the data comes off the screen when the window ends. */
  tickUnlock() {
    this.paintClock();
    const open = this.unlockLeft().win > 0;
    if (this.wasOpen && !open && this.me) {
      this.me.unlocked = false;
      if (!document.querySelector('dialog[open]') && !document.activeElement?.closest('input,textarea')) this.route();
    }
    this.wasOpen = open;
  }

  async lockNow() {
    await this.lock();
    this.route();
  }

  /** The object views and modules get. */
  get shell() {
    const self = this;
    return {
      api, events: this.events, navigate: (hash) => self.navigate(hash), needStepUp: () => self.needStepUp(), lock: () => self.lock(), landing: () => self.landing(),
      spot: (name) => self.spot(name),
      refreshMe: async () => {
        self.me = await api.me({background: true});
      },
      get lab() { return self.lab; }, get me() { return self.me; },
    };
  }

  async boot() {
    try {
      this.me = await api.me();
      await this.start();
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) this.showLogin('');
      else this.showLogin('', e);
    }
  }

  showLogin(message, error) {
    this.stopLive();
    this.me = null;
    const el = document.createElement('dw-login');
    el.ctx = {shell: this.shell, message, error, onDone: () => this.boot()};
    fill(this, h('a', {class: 'skip', href: '#/overview'}, 'Skip'), el);
  }

  ended(message) {
    if (!this.me) return;
    this.showLogin(message);
  }

  async start() {
    const [mods, lab] = await Promise.all([api.modules(), api.lab()]);
    this.modules = mods.modules;
    Object.assign(this.lab, lab, {feed: 'connecting'});
    this.buildFrame();
    this.startLive();
    this.place = place(location.hash);
    if (this.me.changeDue) this.mustChange();
    else if (!location.hash || location.hash === '#' || location.hash === '#/') location.hash = this.landing();
    else this.route();
  }

  /** Where a person starts: the first thing their role may open. */
  landing() {
    const first = this.modules[0];
    if (!first) return '#/profile';
    return first.kind === 'module' ? '#/m/' + first.id : '#/' + first.id;
  }

  mustChange() {
    if (location.hash.startsWith('#/profile/')) this.route();
    else this.navigate('#/profile?at=password');
  }

  /** Like the search in a phone's settings: scroll to one box on the page, make it flash, and put the cursor in it. */
  spot(name) {
    clearTimeout(this.spotTimer);
    let tries = 0;
    const look = () => {
      const box = this.main.querySelector('[data-spot="' + CSS.escape(name) + '"]');
      // a page still loading moves its boxes, so wait until it has settled
      if ((!box || this.main.querySelector('[aria-busy]')) && ++tries < 40) {
        this.spotTimer = setTimeout(look, 100);
        return;
      }
      if (!box) return;
      const still = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      box.scrollIntoView({block: 'center', behavior: still ? 'auto' : 'smooth'});
      box.classList.remove('spot-on');
      box.getBoundingClientRect(); // starts the flash again if this box was the last one too
      box.classList.add('spot-on');
      box.querySelector('input, textarea')?.focus({preventScroll: true});
      setTimeout(() => box.classList.remove('spot-on'), 1600);
    };
    this.spotTimer = setTimeout(look, 60);
  }

  buildFrame() {
    this.nav = h('nav', {class: 'side', 'aria-label': 'Views'});
    this.main = h('main', {id: 'main', tabindex: -1});
    const status = document.createElement('dw-statusbar');
    status.ctx = {shell: this.shell};
    const keys = h('button', {type: 'button', title: 'Keyboard shortcuts', on: {click: () => this.help()}}, '?');
    const words = h('button', {type: 'button', title: 'What the short words mean', on: {click: () => glossary(this.me.passkeyNeeded)}}, 'Glossary');
    const out = h('button', {type: 'button', on: {click: () => this.logout()}}, 'Sign out');
    fill(this,
      h('a', {class: 'skip', href: '#main'}, 'Skip to content'),
      h('header', {class: 'topbar'}, h('span', {class: 'brand'}, 'Dwarpal'), h('span', {class: 'spacer'}),
        h('a', {class: 'who', href: '#/profile', title: 'Your profile'}, this.me.person.display),
        words, keys, out),
      h('div', {class: 'body'}, this.nav, this.main), status);
    this.renderNav();
    explain(this.main);
  }

  unlockClock() {
    this.clockEl = h('span', {class: 'unlock-clock', role: 'timer'});
    this.paintClock();
    return this.clockEl;
  }

  renderNav() {
    const builtIn = this.modules.filter((m) => m.kind === 'builtin');
    const extra = this.modules.filter((m) => m.kind !== 'builtin');
    fill(this.nav,
      builtIn.length ? h('h2', null, builtIn.some((m) => m.id === 'overview') ? 'SOC' : 'Your space') : null,
      builtIn.map((m) => h('a', {href: '#/' + m.id, 'data-id': m.id}, m.title)),
      extra.length ? h('h2', null, 'More') : null,
      extra.map((m) => h('a', {href: '#/m/' + m.id, 'data-id': 'm/' + m.id}, m.title)),
      h('h2', null, 'Account'), h('a', {href: '#/profile', 'data-id': 'profile'}, 'Profile'));
  }

  /** The foot of each page: only links this person's role can open, and the passkey countdown. */
  footer() {
    const can = (id) => this.modules.some((m) => m.id === id);
    const go = (id, text, hash) => (can(id) ? h('a', {href: hash || '#/' + id}, text) : null);
    const group = (title, ...links) => (links.some(Boolean) ? h('div', {class: 'foot-col'}, h('h2', null, title), links) : null);
    return h('footer', {class: 'foot'},
      h('div', {class: 'foot-top'},
        h('div', null, h('div', {class: 'brand'}, 'Dwarpal'), h('p', {class: 'foot-line'}, 'A Zero Trust gate and security operations centre, built on NIST SP 800-207. Every request is checked, every action is recorded.')),
        h('div', {class: 'foot-cols'},
          group('Work', go('queue', 'Alert queue'), go('cases', 'Cases'), go('response', 'Response'), go('scans', 'Scans')),
          group('Reports', go('overview', 'Daily report', '#/overview?at=report'), go('audit', 'Audit explorer'), go('attack', 'ATT&CK map'), go('hunt', 'Hunt')),
          group('Help', h('button', {type: 'button', on: {click: () => glossary(this.me.passkeyNeeded)}}, 'Glossary'), go('guide', 'Guide', '#/m/guide'), go('lab', 'Scenario lab', '#/m/lab'), h('a', {href: '#/profile'}, 'Profile')))),
      h('div', {class: 'foot-end'}, h('span', null, 'Dwarpal, a college project built at home.'), this.unlockClock(),
        h('span', null, 'Times are scenario time (UTC).')));
  }

  // ---- live feed ----------------------------------------------------------------------------------------
  startLive() {
    this.stopLive();
    this.closeStream = api.openStream((name, data) => {
      if (name === 'lab.tick' && data) Object.assign(this.lab, data);
      this.announce(name);
      this.events.dispatchEvent(new CustomEvent('live', {detail: {name, data}}));
    }, (state) => {
      this.lab.feed = state;
      this.events.dispatchEvent(new CustomEvent('live', {detail: {name: 'feed', data: state}}));
      if (state === 'closed') api.me({background: true}).catch(() => {});
    });
    const every = (ms, fn) => this.timers.push(setInterval(() => fn().catch(() => {}), ms));
    this.timers.push(setInterval(() => this.tickUnlock(), 1000));
    every(15000, async () => {
      Object.assign(this.lab, await api.lab({background: true}));
      this.events.dispatchEvent(new CustomEvent('live', {detail: {name: 'lab', data: this.lab}}));
    });
    every(60000, async () => {
      const open = this.me.unlocked;
      this.me = await api.me({background: true});
      // left open and unused: take the data off the screen, unless the person is typing
      if (open && !this.me.unlocked && !document.querySelector('dialog[open]') && !document.activeElement?.closest('input,textarea')) this.route();
    });
  }

  /** Live events the person should hear about, gathered so that a burst of alerts is one notice. */
  announce(name) {
    if (name === 'isolation.changed' && Date.now() - (this.isolationNotice || 0) > 30000) {
      this.isolationNotice = Date.now();
      toast('A device isolation changed.', '', {href: '#/response?at=isolations', text: 'See Response'});
    }
    if (name !== 'alert.new') return;
    this.newAlerts = (this.newAlerts || 0) + 1;
    clearTimeout(this.alertNotice);
    this.alertNotice = setTimeout(() => {
      toast(this.newAlerts === 1 ? 'A new alert was raised.' : this.newAlerts + ' new alerts were raised.', '', {href: '#/queue?at=queue', text: 'Open the queue'});
      this.newAlerts = 0;
    }, 1500);
  }

  stopLive() {
    if (this.closeStream) this.closeStream();
    this.closeStream = null;
    for (const t of this.timers.splice(0)) clearInterval(t);
  }

  async logout() {
    try {
      await api.logout();
    } catch (e) {
      // the cookie is cleared by the server even when this fails; either way the next load asks for a login
    }
    this.showLogin('You are signed out.');
  }

  // ---- routing ------------------------------------------------------------------------------------------
  /** Moving between pages keeps the passkey window open; it ends by itself, or at Lock now. */
  async moved() {
    const next = place(location.hash);
    this.place = next;
    this.route();
  }

  async lock() {
    if (!this.me || !this.me.passkeyNeeded) return;
    try {
      await api.lock();
      this.me.unlocked = false;
      this.me.unlockedSeconds = 0;
      this.me.auditSeconds = 0;
      this.syncUnlock();
    } catch (e) {
      // the server closes it by itself after a few minutes without use
    }
  }

  navigate(hash) {
    if (location.hash === hash) this.route();
    else location.hash = hash;
  }

  route() {
    if (!this.me || !this.main) return;
    lists.clear();
    if (this.moduleCleanup) {
      try {
        this.moduleCleanup();
      } catch (e) {
        // ignore a module's failing cleanup
      }
      this.moduleCleanup = null;
    }
    const raw = location.hash.replace(/^#\/?/, '');
    const [pathPart, query = ''] = raw.split('?');
    const parts = pathPart.split('/').map((p) => {
      try {
        return decodeURIComponent(p);
      } catch (e) {
        return '';
      }
    });
    const params = new URLSearchParams(query);
    const id = parts[0] || 'overview';
    clearTimeout(this.spotTimer);
    if (params.get('at')) this.spot(params.get('at'));
    for (const a of this.nav.querySelectorAll('a')) {
      const key = a.getAttribute('data-id');
      const cur = key === id || (id === 'case' && key === 'queue') || (id === 'm' && key === 'm/' + parts[1]);
      if (cur) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    }
    if (this.me.changeDue && id !== 'profile') {
      this.mustChange();
      return;
    }
    if (id === 'm') return this.mountModule(parts[1]);
    const tag = id === 'case' ? 'dw-case' : id === 'profile' ? 'dw-profile' : BUILT_IN[id];
    if (!tag || (id !== 'case' && id !== 'profile' && !this.modules.some((m) => m.id === id))) {
      fill(this.main, h('div', null, h('h1', null, 'Not found'), h('p', {class: 'note'}, 'There is no view called "' + id + '" for your role.')), this.footer());
      return;
    }
    const el = document.createElement(tag);
    el.ctx = {shell: this.shell, args: parts.slice(1), params};
    fill(this.main, el, this.footer());
    this.main.scrollTo(0, 0);
    if (this.focusHuntNext && id === 'hunt') {
      this.focusHuntNext = false;
      setTimeout(() => document.querySelector('[data-hunt-input]')?.focus(), 50);
    }
  }

  async mountModule(id) {
    const meta = this.modules.find((m) => m.id === id && m.kind === 'module');
    if (!meta || !/^[a-z][a-z0-9-]{1,31}$/.test(id)) {
      fill(this.main, h('div', null, h('h1', null, 'Not found')), this.footer());
      return;
    }
    const root = h('div', {class: 'module-root'});
    fill(this.main, h('div', null, h('p', {class: 'note'}, 'Loading ' + meta.title + '...')));
    try {
      const mod = await import('/console/modules/' + id + '/index.js');
      const def = mod.default;
      fill(this.main, root, this.footer());
      const self = this;
      const moduleShell = {
        api: api.module(id), needStepUp: () => self.needStepUp(), navigate: (hash) => self.navigate(hash),
        get me() { return self.me; }, get lab() { return self.lab; }, events: this.events,
      };
      const cleanup = await def.view(root, moduleShell);
      this.moduleCleanup = typeof cleanup === 'function' ? cleanup : null;
    } catch (e) {
      fill(this.main, h('div', null, unavailable(e)), this.footer());
    }
  }

  // ---- passkey ------------------------------------------------------------------------------------------
  /**
   * Resolves once the passkey is accepted. scope: 'window' opens cases, entities and hunt together for 15 minutes;
   * 'audit' is the audit explorer's own 5 minutes (and renews the window); 'once' confirms one risky action.
   * A person with no passkey yet is sent to make one.
   */
  needUnlock(scope) {
    scope = scope === 'audit' || scope === 'once' ? scope : 'window';
    if (this.unlocking) return this.unlocking;
    this.unlocking = new Promise((resolve, reject) => {
      const done = (ok) => {
        dlg.close();
        dlg.remove();
        this.unlocking = null;
        if (ok) resolve(true);
        else reject(new ApiError(423, 'passkey required'));
      };
      const dlg = h('dialog', {'aria-labelledby': 'pk-title'});
      dlg.addEventListener('cancel', () => done(false));
      if (!this.me.passkeySet) {
        dlg.append(h('h1', {id: 'pk-title'}, 'Set your passkey first'),
          h('p', {class: 'note'}, 'Confidential views need a passkey of your own. Set one now, then come back.'),
          h('div', {class: 'row'}, h('button', {type: 'button', class: 'primary', on: {click: () => {
            done(false);
            this.navigate('#/profile?at=passkey');
          }}}, 'Set my passkey'), h('button', {type: 'button', on: {click: () => done(false)}}, 'Cancel')));
      } else {
        const key = h('input', {type: 'password', id: 'pk-key', autocomplete: 'off', required: true, spellcheck: false});
        const msg = h('p', {class: 'note', role: 'alert'});
        const form = h('form', {class: 'stack', method: 'dialog'}, h('h1', {id: 'pk-title'}, scope === 'once' ? 'Confirm with your passkey' : 'Enter your passkey'),
          h('p', {class: 'note'}, scope === 'once' ? 'This action asks for your passkey every time.'
            : scope === 'audit' ? 'The audit explorer opens for 5 minutes, and the other confidential views for 15.'
              : 'Cases, entities and hunt open together for 15 minutes. The footer counts the time down.'),
          h('label', {for: 'pk-key'}, 'Passkey'), key, msg,
          h('div', {class: 'row'}, h('button', {type: 'submit', class: 'primary'}, 'Open'), h('button', {type: 'button', on: {click: () => done(false)}}, 'Cancel')));
        form.addEventListener('submit', async (e) => {
          e.preventDefault();
          msg.textContent = '';
          try {
            const r = await api.unlock(key.value, scope);
            if (scope !== 'once') {
              this.me.unlocked = true;
              this.me.unlockedSeconds = r.unlockedSeconds;
              this.me.auditSeconds = r.auditSeconds;
              this.syncUnlock();
            }
            done(true);
          } catch (err) {
            msg.textContent = err.status === 429 ? 'Too many attempts. Try again in ' + (err.retryAfter || 5) + ' s.' : 'That is not your passkey.';
            key.value = '';
          }
        });
        dlg.append(form);
      }
      document.body.append(dlg);
      dlg.showModal();
    });
    return this.unlocking;
  }

  // ---- step-up ------------------------------------------------------------------------------------------
  /** Resolves after a fresh second factor (password and key PIN again); rejects if the person gives up. */
  needStepUp() {
    return new Promise((resolve, reject) => {
      const pw = h('input', {type: 'password', id: 'su-pw', autocomplete: 'current-password', required: true});
      const pin = h('input', {type: 'password', id: 'su-pin', autocomplete: 'one-time-code', required: true});
      const msg = h('p', {class: 'note', role: 'alert'});
      const dlg = h('dialog', {'aria-labelledby': 'su-title'});
      const done = (ok, err) => {
        dlg.close();
        dlg.remove();
        if (ok) resolve(true);
        else reject(err || new Error('step-up cancelled'));
      };
      const form = h('form', {class: 'stack', method: 'dialog'},
        h('h1', {id: 'su-title'}, 'Confirm it is you'),
        h('p', {class: 'note'}, 'This action needs a fresh second factor. Enter your password and the PIN of your security key again.'),
        h('label', {for: 'su-pw'}, 'Password'), pw, h('label', {for: 'su-pin'}, 'Security key PIN'), pin, msg,
        h('div', {class: 'row'},
          h('button', {type: 'submit', class: 'primary'}, 'Confirm'),
          h('button', {type: 'button', on: {click: () => done(false)}}, 'Cancel')));
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        msg.textContent = '';
        try {
          await api.stepUp(pw.value, pin.value);
          this.me = await api.me({background: true});
          done(true);
        } catch (err) {
          msg.textContent = err.status === 429 ? 'Too many attempts. Try again in ' + (err.retryAfter || 5) + ' s.'
            : 'That did not work. Check the password and the PIN.';
          pw.value = '';
          pin.value = '';
        }
      });
      dlg.addEventListener('cancel', () => done(false));
      dlg.append(form);
      document.body.append(dlg);
      dlg.showModal();
      pw.focus();
    });
  }

  // ---- keyboard -----------------------------------------------------------------------------------------
  key(e) {
    if (e.ctrlKey || e.metaKey || e.altKey || !this.me) return;
    const t = e.target;
    const typing = t instanceof Element && t.closest('input,textarea,select,[contenteditable]');
    if (typing) return;
    if (document.querySelector('dialog[open]')) return;
    if (e.key === 'j') {
      if (lists.move(1)) e.preventDefault();
    } else if (e.key === 'k') {
      if (lists.move(-1)) e.preventDefault();
    } else if (e.key === 'Enter') {
      if (!(t instanceof Element && t.closest('a,button')) && lists.open()) e.preventDefault();
    } else if (e.key === '/') {
      e.preventDefault();
      this.focusHuntNext = true;
      this.navigate('#/hunt');
      setTimeout(() => document.querySelector('[data-hunt-input]')?.focus(), 50);
    } else if (e.key === '?') {
      this.help();
    }
  }

  help() {
    const dlg = h('dialog', {'aria-labelledby': 'help-title'});
    dlg.addEventListener('close', () => dlg.remove());
    dlg.append(h('h1', {id: 'help-title'}, 'Keyboard'), h('ul', {class: 'plain keys'},
      h('li', null, h('kbd', null, 'j'), ' / ', h('kbd', null, 'k'), '  next / previous row'),
      h('li', null, h('kbd', null, 'Enter'), '  open the selected row'),
      h('li', null, h('kbd', null, '/'), '  go to Hunt and type a query'),
      h('li', null, h('kbd', null, '?'), '  this help'),
      h('li', null, h('kbd', null, 'Esc'), '  close a dialog')),
      h('p', {class: 'note'}, 'Priority is always shown as a word and a shape, never as colour alone. Times are scenario time (UTC).'),
      h('div', {class: 'row'}, h('button', {type: 'button', class: 'primary', on: {click: () => dlg.close()}}, 'Close')));
    document.body.append(dlg);
    dlg.showModal();
  }
}

customElements.define('dw-app', DwApp);
