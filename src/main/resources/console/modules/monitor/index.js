// Monitoring: what the other administrator did, and (for a lead) the limited vault log. Read only; everything the
// server sends is shown as text.
import { el, clear, button, stylesheet } from './dom.js';

function table(headers, rows, cls) {
  return el('table', { class: 'mon-table' },
    el('thead', {}, el('tr', {}, headers.map((h) => el('th', {}, h)))),
    el('tbody', {}, rows.map((r) => el('tr', {}, r.map((c, i) => el('td', cls && cls[i] ? { class: cls[i] } : {},
      c === undefined || c === null ? '' : String(c)))))));
}

function when(iso) {
  return String(iso).replace('T', ' ').replace(/\.\d+Z$/, 'Z').replace(/Z$/, ' UTC');
}

function view(root, shell) {
  stylesheet('/console/modules/monitor/monitor.css');
  const api = shell.api;
  const tabs = el('div', { class: 'mon-tabs', role: 'tablist' });
  const msg = el('p', { class: 'mon-note', role: 'status', 'aria-live': 'polite' });
  const body = el('div', {});
  const pages = new Map();

  function say(text, bad) {
    msg.textContent = text;
    msg.className = bad ? 'mon-note mon-bad' : 'mon-note';
  }

  async function admins(box) {
    const r = await api.get('admins');
    clear(box);
    box.append(el('p', { class: 'mon-note' }, 'What the other administrator did. Nobody can edit or delete these records, '
      + 'you included. Administrators watched: ' + (r.administrators.length ? r.administrators.join(', ') : 'none besides you') + '.'));
    box.append(r.actions.length
      ? table(['When', 'Who', 'What', 'Details'], r.actions.map((a) => [when(a.at), a.actor, a.type, a.what]), [null, null, null, 'mon-what'])
      : el('p', {}, 'Nothing yet.'));
  }

  async function vault(box) {
    const r = await api.get('vault');
    clear(box);
    box.append(el('p', { class: 'mon-note' }, 'Who opened the vault, when, and on whom. The secret itself is never recorded here or anywhere in the log.'));
    box.append(r.events.length
      ? table(['When', 'Who', 'Action', 'On whom'], r.events.map((e) => [when(e.at), e.who, e.action, e.target]))
      : el('p', {}, 'No vault events yet.'));
  }

  // Team activity: read only, filtered by person and type, paged with "Older" (the server's `next`). Everything is text.
  async function team(box) {
    let person = '';
    let type = '';
    const note = el('p', { class: 'mon-note' }, 'From the latest 2,000 records of the saved trail. Nobody can change these rows.');
    const bar = el('div', { class: 'mon-tabs' });
    const out = el('div', {});
    box.append(note, bar, out);

    function menu(label, values, current, onPick) {
      const s = el('select', { 'aria-label': label },
        el('option', { value: '' }, 'All (' + label.toLowerCase() + ')'),
        values.map((v) => el('option', { value: v }, v)));
      s.value = values.includes(current) ? current : '';
      s.addEventListener('change', () => onPick(s.value));
      return s;
    }

    async function load(before, append) {
      const q = [];
      if (person) q.push('person=' + encodeURIComponent(person));
      if (type) q.push('type=' + encodeURIComponent(type));
      if (before !== null && before !== undefined) q.push('before=' + encodeURIComponent(String(before)));
      const r = await api.get('team' + (q.length ? '?' + q.join('&') : ''));
      if (!append) {
        clear(bar);
        bar.append(menu('Person', r.persons, person, (v) => { person = v; reload(); }),
          menu('Type', r.types, type, (v) => { type = v; reload(); }));
        clear(out);
        out.append(el('div', {}));
      }
      const holder = out.lastChild;
      if (append) holder.querySelectorAll('button').forEach((b) => b.remove());
      if (!append && !r.rows.length) {
        holder.append(el('p', {}, 'Nothing yet.'));
        return;
      }
      if (r.rows.length) {
        const tbl = table(['When', 'Who', 'What', 'Details'], r.rows.map((a) => [when(a.at), a.actor, a.type, a.what]),
          [null, null, null, 'mon-what']);
        holder.append(tbl);
      }
      if (r.next !== null && r.next !== undefined) {
        holder.append(button('Older', async () => {
          try {
            say('');
            await load(r.next, true);
          } catch (e) {
            say(e && e.message ? e.message : 'That is unavailable.', true);
          }
        }));
      }
    }

    function reload() {
      load(null, false).catch((e) => say(e && e.message ? e.message : 'That is unavailable.', true));
    }

    await load(null, false);
  }

  async function open(key) {
    for (const [k, p] of pages) p.tab.setAttribute('aria-selected', k === key ? 'true' : 'false');
    say('');
    clear(body);
    const box = el('div', {});
    body.append(box);
    try {
      await pages.get(key).draw(box);
    } catch (e) {
      say(e && e.message ? e.message : 'That is unavailable.', true);
    }
  }

  function addTab(key, label, draw) {
    const tab = button(label, () => open(key), { role: 'tab', 'aria-selected': 'false' });
    pages.set(key, { tab, draw });
    tabs.append(tab);
  }

  root.append(el('h2', {}, 'Monitoring'), tabs, msg, body);
  (async () => {
    try {
      const me = await api.get('me');
      if (me.admin) addTab('admins', 'Administrators', admins);
      addTab('team', 'Team activity', team);
      if (me.lead) addTab('vault', 'Vault log', vault);
      const first = me.admin ? 'admins' : 'vault';
      open(first);
    } catch (e) {
      say(e && e.message ? e.message : 'Monitoring is unavailable.', true);
    }
  })();
}

export default { id: 'monitor', title: 'Monitoring', requires: 'LEAD', view };
