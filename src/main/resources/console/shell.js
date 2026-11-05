// The shell: login, navigation built from /console/api/modules, routing, the live feed, keyboard, step-up, status bar.
import {api, ApiError} from './api.js';
import {h, fill, unavailable} from './dom.js';
import {getPref, setPref} from './prefs.js';
import {lists} from './table.js';
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

const BUILT_IN = {
  overview: 'dw-overview', queue: 'dw-queue', cases: 'dw-cases', hunt: 'dw-hunt', entity: 'dw-entity',
  response: 'dw-response', audit: 'dw-audit', attack: 'dw-attack',
};

function applyTheme() {
  const t = getPref('theme', 'auto');
  if (t === 'dark' || t === 'light') document.documentElement.setAttribute('data-theme', t);
  else document.documentElement.removeAttribute('data-theme');
}

class DwApp extends HTMLElement {
  constructor() {
    super();
    this.events = new EventTarget();
    this.lab = {time: null, state: 'UNKNOWN', speed: null, feed: 'connecting'};
    this.me = null;
    this.modules = [];
    this.closeStream = null;
    this.timers = [];
    this.moduleCleanup = null;
    this.focusHuntNext = false;
  }

  connectedCallback() {
    applyTheme();
    window.addEventListener('hashchange', () => this.route());
    window.addEventListener('keydown', (e) => this.key(e));
    window.addEventListener('dw:session-ended', () => this.ended('Your session ended. Sign in again.'));
    this.boot();
  }

  /** The object views and modules get. */
  get shell() {
    const self = this;
    return {
      api, events: this.events, navigate: (hash) => self.navigate(hash), needStepUp: () => self.needStepUp(),
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
    if (!location.hash || location.hash === '#' || location.hash === '#/') location.hash = '#/' + (this.modules[0] ? this.modules[0].id : 'overview');
    else this.route();
  }

  buildFrame() {
    this.nav = h('nav', {class: 'side', 'aria-label': 'Views'});
    this.main = h('main', {id: 'main', tabindex: -1});
    const status = document.createElement('dw-statusbar');
    status.ctx = {shell: this.shell};
    const theme = h('button', {type: 'button', title: 'Theme: automatic, dark or light', on: {click: () => this.cycleTheme()}}, 'Theme');
    const keys = h('button', {type: 'button', title: 'Keyboard shortcuts', on: {click: () => this.help()}}, '?');
    const out = h('button', {type: 'button', on: {click: () => this.logout()}}, 'Sign out');
    fill(this,
      h('a', {class: 'skip', href: '#main'}, 'Skip to content'),
      h('header', {class: 'topbar'}, h('span', {class: 'brand'}, 'DWARPAL', h('small', null, 'lab console')), h('span', {class: 'spacer'}),
        h('span', null, this.me.person.display, ' ', h('span', {class: 'muted'}, '(' + this.me.person.roles.join(', ').toLowerCase() + ')')),
        theme, keys, out),
      h('div', {class: 'body'}, this.nav, this.main), status);
    this.renderNav();
  }

  renderNav() {
    const builtIn = this.modules.filter((m) => m.kind === 'builtin');
    const extra = this.modules.filter((m) => m.kind !== 'builtin');
    fill(this.nav,
      builtIn.length ? h('h2', null, 'SOC') : null,
      builtIn.map((m) => h('a', {href: '#/' + m.id, 'data-id': m.id}, m.title)),
      extra.length ? h('h2', null, 'More') : null,
      extra.map((m) => h('a', {href: '#/m/' + m.id, 'data-id': 'm/' + m.id}, m.title)));
  }

  cycleTheme() {
    const order = ['auto', 'dark', 'light'];
    const next = order[(order.indexOf(getPref('theme', 'auto')) + 1) % order.length];
    setPref('theme', next);
    applyTheme();
  }

  // ---- live feed ----------------------------------------------------------------------------------------
  startLive() {
    this.stopLive();
    this.closeStream = api.openStream((name, data) => {
      if (name === 'lab.tick' && data) Object.assign(this.lab, data);
      this.events.dispatchEvent(new CustomEvent('live', {detail: {name, data}}));
    }, (state) => {
      this.lab.feed = state;
      this.events.dispatchEvent(new CustomEvent('live', {detail: {name: 'feed', data: state}}));
      if (state === 'closed') api.me({background: true}).catch(() => {});
    });
    const every = (ms, fn) => this.timers.push(setInterval(() => fn().catch(() => {}), ms));
    every(15000, async () => {
      Object.assign(this.lab, await api.lab({background: true}));
      this.events.dispatchEvent(new CustomEvent('live', {detail: {name: 'lab', data: this.lab}}));
    });
    every(60000, async () => {
      this.me = await api.me({background: true});
    });
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
    for (const a of this.nav.querySelectorAll('a')) {
      const key = a.getAttribute('data-id');
      const cur = key === id || (id === 'case' && key === 'queue') || (id === 'm' && key === 'm/' + parts[1]);
      if (cur) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    }
    if (id === 'm') return this.mountModule(parts[1]);
    const tag = id === 'case' ? 'dw-case' : BUILT_IN[id];
    if (!tag || (id !== 'case' && !this.modules.some((m) => m.id === id))) {
      fill(this.main, h('h1', null, 'Not found'), h('p', {class: 'note'}, 'There is no view called "' + id + '" for your role.'));
      return;
    }
    const el = document.createElement(tag);
    el.ctx = {shell: this.shell, args: parts.slice(1), params};
    fill(this.main, el);
    this.main.scrollTo(0, 0);
    if (this.focusHuntNext && id === 'hunt') {
      this.focusHuntNext = false;
      setTimeout(() => document.querySelector('[data-hunt-input]')?.focus(), 50);
    }
  }

  async mountModule(id) {
    const meta = this.modules.find((m) => m.id === id && m.kind === 'module');
    if (!meta || !/^[a-z][a-z0-9-]{1,31}$/.test(id)) {
      fill(this.main, h('h1', null, 'Not found'));
      return;
    }
    const root = h('div', {class: 'module-root'});
    fill(this.main, h('p', {class: 'note'}, 'Loading ' + meta.title + '...'));
    try {
      const mod = await import('/console/modules/' + id + '/index.js');
      const def = mod.default;
      fill(this.main, root);
      const self = this;
      const moduleShell = {
        api: api.module(id), needStepUp: () => self.needStepUp(), navigate: (hash) => self.navigate(hash),
        get me() { return self.me; }, get lab() { return self.lab; }, events: this.events,
      };
      const cleanup = await def.view(root, moduleShell);
      this.moduleCleanup = typeof cleanup === 'function' ? cleanup : null;
    } catch (e) {
      fill(this.main, unavailable(e));
    }
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
