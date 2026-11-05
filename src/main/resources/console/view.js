// The base of every view: one custom element per view. A view gets its context (the shell, route arguments) from the shell
// before it is attached, loads its data through api.js, and shows "unavailable" when a load fails.
import {h, fill, unavailable} from './dom.js';

export class DwView extends HTMLElement {
  constructor() {
    super();
    this.ctx = null;
    this.cleanups = [];
    this.loadToken = 0;
  }

  connectedCallback() {
    if (!this.ctx) return;
    this.setAttribute('aria-busy', 'true');
    Promise.resolve(this.render()).catch((e) => this.fail(e)).finally(() => this.removeAttribute('aria-busy'));
  }

  disconnectedCallback() {
    for (const c of this.cleanups.splice(0)) {
      try {
        c();
      } catch (e) {
        // a cleanup that fails must not stop the others
      }
    }
  }

  /** Runs fn when the shell reports this live event (debounced), until the view goes away. */
  onLive(names, fn, ms = 800) {
    let timer = null;
    const handler = (e) => {
      if (!names.includes(e.detail.name)) return;
      clearTimeout(timer);
      timer = setTimeout(() => Promise.resolve(fn()).catch(() => {}), ms);
    };
    this.ctx.shell.events.addEventListener('live', handler);
    this.cleanups.push(() => {
      clearTimeout(timer);
      this.ctx.shell.events.removeEventListener('live', handler);
    });
  }

  /** Puts the error where the data would have been. */
  fail(e) {
    fill(this, unavailable(e));
  }

  get shell() {
    return this.ctx.shell;
  }

  get lab() {
    return this.ctx.shell.lab;
  }

  title(text, ...extra) {
    return h('div', {class: 'row'}, h('h1', null, text), h('span', {class: 'spacer'}), ...extra);
  }
}
