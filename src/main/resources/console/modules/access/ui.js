// The access pages: a person's own access, HR's requests, a lead's approvals and the administrator's queue.
// Everything the server sends is shown as text; markup is only ever built from elements.
import { el, clear, button, stylesheet } from './dom.js';

// the administrator's section lives inside the admin module, so these styles are loaded wherever these pages are
stylesheet('/console/modules/access/access.css');

const STATE = { ACTIVE: 'Active', PENDING: 'Waiting for approval', REJECTED: 'Refused', REMOVED: 'Removed' };
const STATUS = { PENDING: 'Waiting', APPROVED: 'Approved, waiting for a second approver', REJECTED: 'Refused', DONE: 'Done', CANCELLED: 'Cancelled' };
const KIND = { JOINER: 'New joiner', LEAVER: 'Leaver', ACCESS: 'More access' };

export function when(iso) {
  return iso ? String(iso).replace('T', ' ').slice(0, 16) + ' UTC' : '';
}

function find(catalog, id) {
  return catalog.find((x) => x.id === id) || { id, label: id, description: '', sensitivity: 'SIMPLE' };
}

function table(headers, rows, empty) {
  if (!rows.length) return el('p', { class: 'acc-empty' }, empty || 'Nothing here.');
  return el('table', { class: 'acc-table' },
    el('thead', {}, el('tr', {}, headers.map((h) => el('th', {}, h)))),
    el('tbody', {}, rows.map((r) => el('tr', {}, r.map((c) => el('td', {}, c === undefined || c === null ? '' : c))))));
}

/** Who a hard grant still waits for, in words. */
function waiting(grant) {
  const need = (grant.approvals || []).filter((a) => a.decision === 'PENDING').map((a) => (a.role === 'ADMIN' ? 'the administrator' : 'a lead'));
  return need.length ? 'waiting for ' + need.join(' and ') : '';
}

function stateWords(grant) {
  if (grant.state === 'PENDING') return waiting(grant) || STATE.PENDING;
  return STATE[grant.state] || grant.state;
}

export function grantsTable(grants, catalog) {
  return table(['Access', 'Approval', 'Status', 'Since'], grants.map((g) => {
    const item = find(catalog, g.itemId);
    return [item.label, item.sensitivity === 'HARD' ? 'administrator and lead' : 'automatic', stateWords(g),
      when(g.removedAt || g.grantedAt || g.createdAt) + (g.removedReason ? ' (' + g.removedReason + ')' : '')];
  }), 'No access has been granted yet.');
}

export function requestsTable(requests, catalog) {
  return table(['Request', 'For', 'Status', 'Items', 'Raised', 'Answer'], requests.map((q) => [
    KIND[q.kind] || q.kind, q.subjectId, STATUS[q.status] || q.status,
    (q.items || []).map((i) => find(catalog, i).label).join(', '), when(q.createdAt), q.decisionReason || '']), 'No requests yet.');
}

/** Checkboxes for the items; only what is ticked when the person saves is granted. */
export function picker(items, ticked) {
  const boxes = new Map();
  const list = el('div', { class: 'acc-picker' });
  for (const item of items) {
    const box = el('input', { type: 'checkbox', id: 'acc-' + item.id });
    box.checked = ticked.has(item.id);
    boxes.set(item.id, box);
    list.append(el('div', { class: 'acc-item' }, box, el('div', { class: 'acc-body' },
      el('div', { class: 'acc-head' }, el('label', { for: 'acc-' + item.id }, item.label),
        el('span', { class: 'acc-tag ' + (item.sensitivity === 'HARD' ? 'acc-hard' : 'acc-simple') },
          item.sensitivity === 'HARD' ? 'needs the administrator and a lead' : 'automatic')),
      el('div', { class: 'acc-note' }, item.description))));
  }
  return { node: list, chosen: () => items.filter((i) => boxes.get(i.id).checked).map((i) => i.id) };
}

function field(label, input) {
  return el('div', { class: 'acc-field' }, el('label', { for: input.id }, label), input);
}

function reasonBox(id, placeholder) {
  return el('textarea', { id, rows: 2, maxlength: 300, placeholder: placeholder || 'A short reason', spellcheck: true });
}

// ---- a person's own access ---------------------------------------------------------------------------------------

export async function myAccess(box, ctx) {
  const m = await ctx.api.get('mine');
  clear(box);
  box.append(el('h3', {}, 'What you have'), grantsTable(m.grants, m.catalog),
    el('p', { class: 'acc-note' }, 'Your console roles: ' + (m.roles.length ? m.roles.join(', ') : 'none') + '. A change of role shows after your next sign-in.'));
  if (m.available.length) {
    const p = picker(m.available, new Set());
    const reason = reasonBox('acc-more-reason', 'Why you need it');
    const send = button('Send the request', async () => {
      const chosen = p.chosen();
      if (!chosen.length) return ctx.say('Tick what you would like.', true);
      const r = await ctx.call(ctx.api.post('request', { items: chosen, reason: reason.value }));
      if (r) {
        ctx.say('Your request is in. Items that need no approval are active now; the others wait for the administrator and a lead.');
        myAccess(box, ctx);
      }
    }, { class: 'primary' });
    box.append(el('h3', {}, 'Request more access'),
      el('p', { class: 'acc-note' }, 'Items marked automatic are granted at once because the directory shows you are active. The others need the administrator and a lead, and nobody approves their own request.'),
      p.node, field('Why you need it', reason), el('div', { class: 'acc-row' }, send));
  }
  box.append(el('h3', {}, 'Your requests'), requestsTable(m.requests, m.catalog));
}

// ---- HR ------------------------------------------------------------------------------------------------------------------

export async function hrPage(box, ctx) {
  const [o, c] = await Promise.all([ctx.api.get('hr'), ctx.api.get('catalog')]);
  clear(box);
  const id = el('input', { type: 'text', id: 'hr-id', maxlength: 32, spellcheck: false, placeholder: 'lower-case, e.g. priya' });
  const name = el('input', { type: 'text', id: 'hr-name', maxlength: 100, placeholder: 'Full name' });
  const dept = el('input', { type: 'text', id: 'hr-dept', maxlength: 60, placeholder: 'Department' });
  const role = el('input', { type: 'text', id: 'hr-role', maxlength: 60, list: 'hr-roles', placeholder: 'Business role' });
  const roles = el('datalist', { id: 'hr-roles' }, o.roles.map((r) => el('option', { value: r })));
  const reason = reasonBox('hr-why', 'For example: starts on Monday');
  const raise = button('Send to the administrator', async () => {
    const r = await ctx.privileged('hr/joiner', { id: id.value, name: name.value, department: dept.value, businessRole: role.value, reason: reason.value });
    if (r) {
      ctx.say('The request went to the administrator, who decides what the person gets.');
      hrPage(box, ctx);
    }
  }, { class: 'primary' });
  box.append(el('h3', {}, 'A new joiner'),
    el('p', { class: 'acc-note' }, 'Say who is joining. The administrator chooses the access; you do not see or approve it.'),
    el('div', { class: 'acc-form' }, field('Person id', id), field('Name', name), field('Department', dept), field('Business role', role), roles,
      field('Note', reason)), el('div', { class: 'acc-row' }, raise));

  const who = el('select', { id: 'hr-leaver' }, el('option', { value: '' }, 'Choose a person'),
    o.people.map((p) => el('option', { value: p.id }, p.name + ' (' + p.id + ', ' + p.department + ')')));
  const why = reasonBox('hr-leaver-why', 'For example: last day was Friday');
  let armed = false;
  const go = button('Remove all access', async () => {
    if (!who.value) return ctx.say('Choose the person who is leaving.', true);
    if (!armed) {
      armed = true;
      go.textContent = 'Click again to remove everything now';
      return undefined;
    }
    armed = false;
    go.textContent = 'Remove all access';
    const r = await ctx.privileged('hr/leaver', { id: who.value, reason: why.value });
    if (r) {
      ctx.say('Done. The account is switched off, the sessions are ended and every grant is removed.');
      hrPage(box, ctx);
    }
    return undefined;
  });
  box.append(el('h3', {}, 'Someone is leaving'),
    el('p', { class: 'acc-note' }, 'No approval is needed: removing access quickly matters more than granting it. Everything the person was ever given goes at once, and it cannot be undone from here.'),
    el('div', { class: 'acc-form' }, field('Person', who), field('Note', why)), el('div', { class: 'acc-row' }, go),
    el('h3', {}, 'Your requests'), requestsTable(o.requests, c.items));
}

// ---- approvals: a lead's and the administrator's ----------------------------------------------------------------

function decisionCard(w, catalog, asRole, ctx, again) {
  const item = find(catalog, w.grant.itemId);
  const reason = reasonBox('why-' + w.grant.id, 'A reason (needed to refuse)');
  const act = (approve) => async () => {
    const r = await ctx.privileged((asRole === 'ADMIN' ? 'access/' : '') + 'approvals/' + w.grant.id + '/decision', { approve, reason: reason.value });
    if (r) {
      ctx.say(approve ? 'Approved.' : 'Refused.');
      again();
    }
  };
  const left = w.grant.approvals.filter((a) => a.decision === 'PENDING').map((a) => (a.role === 'ADMIN' ? 'administrator' : 'lead'));
  return el('div', { class: 'acc-card' },
    el('strong', {}, item.label), ' for ', el('strong', {}, w.grant.personId),
    el('p', { class: 'acc-note' }, 'Asked by ' + w.request.requestedBy + ' on ' + when(w.request.createdAt) + '. Reason: ' + w.request.reason),
    el('p', { class: 'acc-note' }, 'Still needed: ' + left.join(' and ') + '.'),
    w.canDecide
      ? el('div', null, field('Reason', reason), el('div', { class: 'acc-row' }, button('Approve', act(true), { class: 'primary' }), button('Refuse', act(false))))
      : el('p', { class: 'acc-note' }, 'You cannot decide this one: nobody approves their own request.'));
}

export async function leadPage(box, ctx) {
  const a = await ctx.api.get('approvals');
  clear(box);
  box.append(el('h3', {}, 'Access waiting for a lead'),
    el('p', { class: 'acc-note' }, 'Sensitive access needs the administrator and a lead. Both must approve before anything is granted.'));
  if (!a.waiting.length) box.append(el('p', { class: 'acc-empty' }, 'Nothing is waiting for you.'));
  for (const w of a.waiting) box.append(decisionCard(w, a.catalog, 'LEAD', ctx, () => leadPage(box, ctx)));
}

// ---- the administrator --------------------------------------------------------------------------------------------------

export async function adminQueue(box, ctx) {
  const q = await ctx.api.get('access/queue');
  clear(box);
  box.append(el('h3', {}, 'New joiners'),
    el('p', { class: 'acc-note' }, 'HR sends the person; you choose the access. The role\'s usual items are ticked. Only what is ticked when you save is granted. Sensitive items then wait for a lead.'));
  if (!q.joiners.length) box.append(el('p', { class: 'acc-empty' }, 'No joiner is waiting.'));
  for (const j of q.joiners) {
    const ticked = new Set(q.templates[j.businessRole] || []);
    const p = picker(q.catalog, ticked);
    const reason = reasonBox('rej-' + j.id, 'A reason (needed to refuse)');
    const save = button('Save and grant', async () => {
      const r = await ctx.privileged('access/joiners/' + j.id + '/save', { items: p.chosen() });
      if (r) {
        ctx.say(j.displayName + ' now exists with ' + r.grants.length + ' access item(s). Sensitive ones wait for a lead.');
        adminQueue(box, ctx);
      }
    }, { class: 'primary' });
    const refuse = button('Refuse', async () => {
      const r = await ctx.privileged('access/joiners/' + j.id + '/reject', { reason: reason.value });
      if (r) {
        ctx.say('Refused. Nothing was created.');
        adminQueue(box, ctx);
      }
    });
    box.append(el('div', { class: 'acc-card' }, el('strong', {}, j.displayName), ' (' + j.subjectId + '), ' + j.department + ', ' + j.businessRole,
      el('p', { class: 'acc-note' }, 'Raised by ' + j.requestedBy + ' on ' + when(j.createdAt) + '. ' + j.reason),
      el('h4', {}, 'Access to grant'), p.node, field('Reason to refuse', reason), el('div', { class: 'acc-row' }, save, refuse)));
  }
  box.append(el('h3', {}, 'Sensitive access waiting for you'));
  if (!q.waiting.length) box.append(el('p', { class: 'acc-empty' }, 'Nothing is waiting for you.'));
  for (const w of q.waiting) box.append(decisionCard(w, q.catalog, 'ADMIN', ctx, () => adminQueue(box, ctx)));
  box.append(el('h3', {}, 'Recent requests'), requestsTable(q.recent, q.catalog));
}
