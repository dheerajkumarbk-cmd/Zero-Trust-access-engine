// The base of every view: one custom element per view. A view gets its context (the shell, route arguments) from the shell
// before it is attached, loads its data through api.js, and shows "unavailable" when a load fails.
import {h, fill, unavailable} from './dom.js';

/** The top of each page: label, title, the words of the title shown in the accent colour, and what the page is for. */
const PAGES = {
  Overview: ['Shift handover', 'Overview of ', 'this shift', 'What happened, what needs attention, and where to go next.'],
  'Alert queue': ['Open work', 'Alert ', 'queue', 'Open cases, highest priority first. This is what is waiting for an analyst.'],
  Cases: ['Every case', 'All ', 'cases', 'Open and closed together, for looking back.'],
  Hunt: ['Search the evidence', 'Hunt through ', 'the events', 'Ask the event trail a question. Results need your passkey; counts do not.'],
  Entities: ['People, devices, addresses', 'Entity ', 'risk', 'Look up anything risk is scored for, and see why.'],
  Response: ['Contain and recover', 'Response ', 'actions', 'Isolate a device, sign a verdict, and see what the playbooks did.'],
  'Audit explorer': ['Proof of what happened', 'Audit ', 'explorer', 'Every action is a linked record. Check that none was changed.'],
  'ATT&CK': ['Attacker techniques', 'ATT&CK ', 'map', 'Which known techniques your open cases show.'],
  Scans: ['Check everything', 'Run a ', 'scan', 'One button, then a plain answer: what is clean, and what needs a look.'],
  Profile: ['Your account', 'Your ', 'profile', 'Your sign-in details, in one place.'],
  'Backup codes': ['Your account', 'Backup ', 'codes', 'Spare keys for the day your password or PIN is forgotten or stolen.'],
  Home: ['Explore', 'Your ', 'Account', 'What your account can open, how safe it is, and what has happened on it.'],
};

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
    const page = PAGES[text];
    const words = text.split(' ');
    return h('header', {class: 'hero'}, h('span', {class: 'eyebrow'}, page ? page[0] : words[0]),
      page ? h('h1', null, page[1], h('em', null, page[2])) : h('h1', null, words.slice(1).join(' ') || text),
      page ? h('p', {class: 'lede'}, page[3]) : null, extra.length ? h('div', {class: 'row'}, ...extra) : null);
  }
}
