// The access pages: a person's own access, HR's requests, a lead's approvals and the administrator's queue.
// Everything the server sends is shown as text; markup is only ever built from elements.
import { el, clear, button, stylesheet } from './dom.js';

// the administrator's section lives inside the admin module, so these styles are loaded wherever these pages are
stylesheet('/console/modules/access/access.css');

const STATE = { ACTIVE: 'Active', PENDING: 'Waiting for approval', REJECTED: 'Refused', REMOVED: 'Removed' };
const STATUS = { PENDING: 'Waiting', APPROVED: 'Approved, waiting for a second approver', REJECTED: 'Refused', DONE: 'Done', CANCELLED: 'Cancelled' };
const KIND = { JOINER: 'New joiner', LEAVER: 'Leaver', ACCESS: 'More access', CREATE_ADMIN: 'New administrator', ADD_ADMIN: 'Give administrator role',
  REMOVE_ADMIN: 'Remove administrator role', OWN_ACCESS: 'Own access change' };

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
  if (m.canRequestMore === false) {
    box.append(el('h3', {}, 'Changes to your own access'),
      el('p', { class: 'acc-note' }, 'As an administrator you cannot approve your own request, so nothing you ask for here could ever be decided. '
        + 'Use Request a privileged change under Administration, Access requests: it goes to the other administrator.'));
  } else if (m.available.length) {
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
    const r = await ctx.elevated((asRole === 'ADMIN' ? 'access/' : '') + 'approvals/' + w.grant.id + '/decision', { approve, reason: reason.value });
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
      const r = await ctx.elevated('access/joiners/' + j.id + '/save', { items: p.chosen() });
      if (r) {
        ctx.say(j.displayName + ' now exists with ' + r.grants.length + ' access item(s). Sensitive ones wait for a lead.');
        adminQueue(box, ctx);
      }
    }, { class: 'primary' });
    const refuse = button('Refuse', async () => {
      const r = await ctx.elevated('access/joiners/' + j.id + '/reject', { reason: reason.value });
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
  privilegedChanges(box, q, ctx);
  box.append(el('h3', {}, 'Recent requests'), requestsTable(q.recent, q.catalog));
}

// ---- privileged changes: one administrator asks, the OTHER administrator decides ---------------------------------------------------

/** The change in plain words. */
export function changeWords(q, catalog) {
  const names = (q.items || []).map((i) => find(catalog, i).label).join(', ');
  switch (q.kind) {
    case 'CREATE_ADMIN': return 'Create the administrator account ' + q.subjectId + ' (' + q.displayName + ', ' + q.department + ')';
    case 'ADD_ADMIN': return 'Give ' + q.subjectId + ' the administrator role';
    case 'REMOVE_ADMIN': return 'Take the administrator role away from ' + q.subjectId;
    case 'OWN_ACCESS': return q.subjectId + ' asks for their own access to: ' + names;
    default: return q.kind;
  }
}

function privilegedChanges(box, q, ctx) {
  const people = q.people || [];
  const kinds = [['ADD_ADMIN', 'Give a person the administrator role'], ['REMOVE_ADMIN', 'Take the administrator role away'],
    ['CREATE_ADMIN', 'Create a new administrator account'], ['OWN_ACCESS', 'Change my own access']];
  const change = el('select', { id: 'pc-change' }, kinds.map(([v, t]) => el('option', { value: v }, t)));
  const part = el('div', { class: 'acc-form' });
  const picked = { person: null, id: null, name: null, dept: null, job: null, items: null };
  const reason = reasonBox('pc-why', 'Why this change is needed');

  function drawPart() {
    clear(part);
    const kind = change.value;
    if (kind === 'ADD_ADMIN' || kind === 'REMOVE_ADMIN') {
      const wantAdmin = kind === 'REMOVE_ADMIN';
      const list = people.filter((p) => p.roles.includes('ADMIN') === wantAdmin);
      picked.person = el('select', { id: 'pc-person' }, el('option', { value: '' }, 'Choose a person'),
        list.map((p) => el('option', { value: p.id }, p.name + ' (' + p.id + ', ' + p.department + ')')));
      part.append(field('Person', picked.person));
    } else if (kind === 'CREATE_ADMIN') {
      picked.id = el('input', { type: 'text', id: 'pc-id', maxlength: 32, spellcheck: false, placeholder: 'lower-case, e.g. morgan' });
      picked.name = el('input', { type: 'text', id: 'pc-name', maxlength: 100, placeholder: 'Full name' });
      picked.dept = el('input', { type: 'text', id: 'pc-dept', maxlength: 60, placeholder: 'Department', value: 'Administration' });
      picked.job = el('input', { type: 'text', id: 'pc-job', maxlength: 60, placeholder: 'Business role', value: 'Administrator' });
      part.append(field('Person id', picked.id), field('Name', picked.name), field('Department', picked.dept), field('Business role', picked.job));
    } else {
      // the console roles change through the administrator changes above, so they are not offered here
      picked.items = picker(q.catalog.filter((i) => !i.consoleRole), new Set());
      part.append(picked.items.node);
    }
  }
  change.addEventListener('change', drawPart);
  drawPart();

  const send = button('Send to the other administrator', async () => {
    const kind = change.value;
    const body = { change: kind, reason: reason.value };
    if (kind === 'ADD_ADMIN' || kind === 'REMOVE_ADMIN') {
      if (!picked.person.value) return ctx.say('Choose the person.', true);
      body.target = picked.person.value;
    } else if (kind === 'CREATE_ADMIN') {
      body.target = picked.id.value;
      body.name = picked.name.value;
      body.department = picked.dept.value;
      body.businessRole = picked.job.value;
    } else {
      const chosen = picked.items.chosen();
      if (!chosen.length) return ctx.say('Tick what you would like.', true);
      body.items = chosen;
    }
    const r = await ctx.elevated('access/privileged', body);
    if (r) {
      ctx.say('Sent. The other administrator decides it; you cannot, and nothing changes until they approve.');
      adminQueue(box, ctx);
    }
    return undefined;
  }, { class: 'primary' });

  box.append(el('h3', {}, 'Request a privileged change'),
    el('p', { class: 'acc-note' }, 'Changes to an administrator, or to your own access, go to the OTHER administrator. You cannot approve your own request, and the lead is not asked. '
      + 'You need an elevation (PIN, passkey and a reason) to send one.'),
    el('div', { class: 'acc-card' }, field('What', change), part, field('Reason', reason), el('div', { class: 'acc-row' }, send)));

  box.append(el('h3', {}, 'Privileged changes waiting'));
  if (!(q.privileged || []).length) box.append(el('p', { class: 'acc-empty' }, 'Nothing is waiting.'));
  for (const w of q.privileged || []) {
    const why = reasonBox('pcw-' + w.request.id, 'A reason (needed to refuse)');
    const act = (approve) => async () => {
      const r = await ctx.elevated('access/privileged/' + w.request.id + '/decision', { approve, reason: why.value });
      if (r) {
        ctx.say(approve ? 'Approved and done.' : 'Refused. Nothing changed.');
        adminQueue(box, ctx);
      }
    };
    box.append(el('div', { class: 'acc-card' }, el('strong', {}, changeWords(w.request, q.catalog)),
      el('p', { class: 'acc-note' }, 'Asked by ' + w.request.requestedBy + ' on ' + when(w.request.createdAt) + '. Reason: ' + w.request.reason),
      w.canDecide
        ? el('div', null, field('Reason', why), el('div', { class: 'acc-row' }, button('Approve', act(true), { class: 'primary' }), button('Refuse', act(false))))
        : el('p', { class: 'acc-note' }, 'Waiting for the other administrator. You cannot decide your own request.')));
  }
}
