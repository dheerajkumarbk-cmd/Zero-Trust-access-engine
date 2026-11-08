// The vault: each person's emergency password, and the administrator's own entry. Everything the server sends is shown as
// text. A secret is kept in the page only while it is on show (it hides itself after a minute) and is never stored.
import { el, clear, button, stylesheet } from './dom.js';

const SHOWN_SECONDS = 60;

function table(headers, rows) {
  return el('table', { class: 'vt-table' },
    el('thead', {}, el('tr', {}, headers.map((h) => el('th', {}, h)))),
    el('tbody', {}, rows.map((r) => el('tr', {}, r.map((c) => el('td', {}, c === undefined || c === null ? '' : c))))));
}

function when(iso) {
  return iso ? String(iso).split('T').join(' ').split('.')[0].split('Z')[0] + ' UTC' : '';
}

function view(root, shell) {
  stylesheet('/console/modules/vault/vault.css');
  const api = shell.api;
  const tabs = el('div', { class: 'vt-tabs', role: 'tablist' });
  const msg = el('p', { class: 'vt-note', role: 'status', 'aria-live': 'polite' });
  const body = el('div', {});
  const pages = new Map();
  const why = el('input', { type: 'text', id: 'vt-why', maxlength: 200, placeholder: 'Why (5 to 200 characters), for the record',
    'aria-label': 'reason' });
  let hideTimer = null;

  function say(text, bad) {
    msg.textContent = text;
    msg.className = bad ? 'vt-note vt-bad' : 'vt-note';
  }

  async function call(promise) {
    try {
      return await promise;
    } catch (e) {
      say(e && e.message ? e.message : 'That did not work.', true);
      return null;
    }
  }

  /** A change or a view of one person: a fresh password and PIN, then the passkey, then the call (the shell asks for both). */
  async function privileged(path, data) {
    if (why.value.trim().length < 5) {
      say('Write the reason first (5 to 200 characters).', true);
      return null;
    }
    const ok = await call(shell.needStepUp());
    if (ok === null) return null;
    return call(api.post(path, Object.assign({ reason: why.value.trim() }, data || {})));
  }

  /** Shows a secret for a minute with a countdown, then removes it from the page. */
  function show(slot, label, lines) {
    clear(slot);
    if (hideTimer) clearInterval(hideTimer);
    let left = SHOWN_SECONDS;
    const clock = el('span', { class: 'vt-note' }, 'hides in ' + left + ' s');
    const hide = () => {
      clearInterval(hideTimer);
      hideTimer = null;
      clear(slot);
    };
    slot.append(el('p', {}, label), ...lines.map((l) => el('div', {}, el('span', { class: 'vt-note' }, l[0] + ': '), el('span', { class: 'vt-secret' }, l[1]))),
      el('div', { class: 'vt-row' }, clock, button('Hide now', hide)));
    hideTimer = setInterval(() => {
      left -= 1;
      if (left <= 0) hide();
      else clock.textContent = 'hides in ' + left + ' s';
    }, 1000);
  }

  async function people(box) {
    const r = await api.get('people');
    clear(box);
    const slot = el('div', { class: 'vt-shown', 'aria-live': 'polite' });
    box.append(el('p', { class: 'vt-note' }, 'Each person has an emergency password. It is switched off and does nothing until you switch it on. '
      + 'It then opens one thing only: the recovery page, where the person must set a new password and PIN, and it is used up. '
      + 'Every action here needs a reason, your password and PIN again, and your passkey, and the other administrator and the leads are told.'),
    el('div', { class: 'vt-row' }, why), slot,
    table(['Person', 'Department', 'Emergency password', 'Kept as typed', 'Changed', 'Actions'], r.people.map((p) => [
      p.name + ' (' + p.id + ')', p.department,
      el('span', { class: p.state === 'ACTIVE' ? 'vt-on' : 'vt-off' }, p.state === 'ACTIVE' ? 'ON since ' + when(p.activatedAt) + ' by ' + p.activatedBy : 'off'),
      p.typed ? 'yes' : 'no', when(p.changedAt),
      p.self ? el('span', { class: 'vt-note' }, 'The other administrator does this for you.')
        : el('div', { class: 'vt-row' },
          button('Reveal', async () => {
            const x = await privileged('people/' + p.id + '/reveal');
            if (x) show(slot, 'Emergency password of ' + p.name + ' (' + (x.state === 'ACTIVE' ? 'switched on' : 'switched off') + ')', [['Password', x.password]]);
          }),
          p.state === 'ACTIVE'
            ? button('Switch off', async () => {
              if (await privileged('people/' + p.id + '/off')) people(box);
            })
            : button('Switch on', async () => {
              const x = await privileged('people/' + p.id + '/activate');
              if (!x) return;
              await people(box);
              say('Switched on for ' + p.name + '. Give them the password in person; it works once, on the recovery page.');
              show(box.querySelector('.vt-shown'), 'Emergency password of ' + p.name + ' (now switched on)', [['Password', x.password]]);
            }),
          button('Choose my own…', () => {
            const field = el('input', { type: 'text', id: 'vt-typed', maxlength: 64, placeholder: 'Your own choice, 10 to 64 characters', 'aria-label': 'password' });
            clear(slot);
            slot.append(el('p', {}, 'A password of your own choice for ' + p.name + '. It stays readable here until it is used.'), field,
              button('Save it', async () => {
                const x = await privileged('people/' + p.id + '/set', { password: field.value });
                if (x) {
                  await people(box);
                  say('Saved for ' + p.name + '. It is still switched ' + (x.state === 'ACTIVE' ? 'on' : 'off') + '.');
                }
              }));
          })),
    ])));
  }

  async function own(box) {
    const s = await api.get('own');
    clear(box);
    const slot = el('div', { class: 'vt-shown', 'aria-live': 'polite' });
    const pw = el('input', { type: 'password', id: 'vt-own-pw', maxlength: 128, autocomplete: 'off', 'aria-label': 'your password' });
    const pin = el('input', { type: 'password', id: 'vt-own-pin', maxlength: 64, autocomplete: 'off', 'aria-label': 'your PIN' });
    box.append(el('p', { class: 'vt-note' }, 'Your own password and security PIN, kept sealed. Only you can read them, and only here. '
      + (s.saved ? 'Last saved ' + when(s.savedAt) + '.' : 'Nothing is kept yet.')),
    el('div', { class: 'vt-row' }, why), slot,
    el('div', { class: 'vt-row' }, el('label', { for: 'vt-own-pw' }, 'Password'), pw, el('label', { for: 'vt-own-pin' }, 'PIN'), pin,
      button('Save', async () => {
        const x = await privileged('own/save', { password: pw.value, pin: pin.value });
        pw.value = '';
        pin.value = '';
        if (x) own(box).then(() => say('Saved.'));
      }),
      s.saved ? button('Reveal', async () => {
        const x = await privileged('own/reveal');
        if (x) show(slot, 'Your own entry', [['Password', x.password], ['PIN', x.pin]]);
      }) : null));
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

  addTab('people', 'Emergency passwords', people);
  addTab('own', 'My own entry', own);
  root.append(el('h2', {}, 'Vault'), tabs, msg, body);
  open('people');
}

export default { id: 'vault', title: 'Vault', requires: 'ADMIN', view };
