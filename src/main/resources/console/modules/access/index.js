// Access: your own access and requests, HR's joiner and leaver requests, and a lead's approvals.
import { el, clear, button, stylesheet } from './dom.js';
import { myAccess, hrPage, leadPage } from './ui.js';

function view(root, shell) {
  stylesheet('/console/modules/access/access.css');
  const api = shell.api;
  const msg = el('p', { class: 'acc-msg', role: 'status', 'aria-live': 'polite' });
  const body = el('div', {});
  const tabs = el('div', { class: 'acc-tabs', role: 'tablist' });
  const pages = new Map();

  function say(text, bad) {
    msg.textContent = text;
    msg.className = bad ? 'acc-msg acc-bad' : 'acc-msg';
  }

  async function call(promise) {
    try {
      return await promise;
    } catch (e) {
      if (e && e.status === 423) return null;
      say(e && e.message ? e.message : 'That did not work.', true);
      return null;
    }
  }

  // a change by HR or a lead needs a fresh password and PIN; the shell asks for them
  async function privileged(path, data) {
    const ok = await call(shell.needStepUp());
    if (ok === null) return null;
    return call(api.post(path, data || {}));
  }

  const ctx = { api, say, call, privileged };

  async function open(key) {
    for (const [k, p] of pages) p.tab.setAttribute('aria-selected', k === key ? 'true' : 'false');
    say('');
    clear(body);
    try {
      await pages.get(key).draw(body, ctx);
    } catch (e) {
      say(e && e.message ? e.message : 'This page is unavailable.', true);
    }
  }

  function addTab(key, label, draw) {
    const tab = button(label, () => open(key), { role: 'tab', 'aria-selected': 'false' });
    pages.set(key, { tab, draw });
    tabs.append(tab);
  }

  root.append(el('h2', {}, 'Access'), tabs, msg, body);
  (async () => {
    const mine = await call(api.get('mine'));
    if (!mine) return;
    addTab('mine', 'My access', myAccess);
    if (mine.roles.includes('HR')) addTab('hr', 'People requests', hrPage);
    if (mine.roles.includes('LEAD')) addTab('lead', 'Approvals', leadPage);
    open(mine.roles.includes('HR') ? 'hr' : 'mine');
  })();
}

export default { id: 'access', title: 'Access', requires: 'USER', view };
