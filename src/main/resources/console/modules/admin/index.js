// Administration and the requester's own page. Everything the server sends is shown as text.
import { el, clear, button, stylesheet } from './dom.js';

function table(headers, rows) {
  return el('table', { class: 'adm-table' },
    el('thead', {}, el('tr', {}, headers.map((h) => el('th', {}, h)))),
    el('tbody', {}, rows.map((r) => el('tr', {}, r.map((c) => el('td', {}, c === undefined || c === null ? '' : String(c)))))));
}

function view(root, shell) {
  stylesheet('/console/modules/admin/admin.css');
  const api = shell.api;
  const msg = el('p', { class: 'adm-msg', role: 'status', 'aria-live': 'polite' });
  const body = el('div', {});
  const tabs = el('div', { class: 'adm-tabs', role: 'tablist' });
  const pages = new Map();
  let me = null;

  function say(text, bad) {
    msg.textContent = text;
    msg.className = bad ? 'adm-msg adm-bad' : 'adm-msg';
  }

  async function call(promise) {
    try {
      return await promise;
    } catch (e) {
      say(e && e.message ? e.message : 'That did not work.', true);
      return null;
    }
  }

  async function privileged(path, data) {
    // a privileged write needs a fresh second factor; the shell asks for it
    const ok = await call(shell.needStepUp());
    if (ok === null) return null;
    return call(api.post(path, data || {}));
  }

  // ---- the requester's page -----------------------------------------------------------------------
  async function whyDenied(box) {
    const r = await call(api.get('me/decisions'));
    if (!r) return;
    box.append(el('p', {}, r.note));
    if (!r.decisions.length) {
      box.append(el('p', {}, 'There are no recent requests from you.'));
      return;
    }
    for (const d of r.decisions) {
      box.append(el('article', { class: 'adm-card' },
        el('h3', {}, d.outcome),
        el('p', {}, d.message),
        el('p', {}, 'Reason: ' + d.reason),
        el('p', {}, 'When: ' + d.at + '   Resource: ' + d.resource + '   Action: ' + d.action),
        el('p', { class: 'adm-ref' }, 'Reference: ' + d.reference),
        el('ul', {}, d.whatToDo.map((t) => el('li', {}, t)))));
    }
  }

  // ---- policy ------------------------------------------------------------------------------------
  async function policy(box) {
    const r = await call(api.get('policy'));
    if (!r) return;
    box.append(el('p', {}, 'Active policy ' + r.version + ' (change number ' + r.sequence + '), combined by ' + r.algorithm
      + '; when nothing grants access the answer is ' + r.defaultEffect + '. A change needs ' + r.approversRequired
      + ' different administrators.'));
    box.append(table(['Policy', 'Effect', 'When', 'What it is for'],
      r.policies.map((p) => [p.id, p.effect, p.when, p.description])));
    box.append(el('h3', {}, 'History of changes'));
    box.append(r.history.length
      ? table(['Seq', 'When', 'What', 'By', 'Details'], r.history.map((h) => [h.sequence, h.at, h.type, h.actor,
        Object.entries(h.details).map(([k, v]) => k + '=' + v).join('; ')]))
      : el('p', {}, 'No change since the lab started.'));
    box.append(proposalForm('policy/propose', 'Propose a policy change (YAML)'), el('div', { class: 'adm-open' }));
    openProposals(box.querySelector('.adm-open'), 'policy');
  }

  async function playbooks(box) {
    const r = await call(api.get('playbooks'));
    if (!r) return;
    box.append(el('p', {}, 'Active playbooks (change number ' + r.sequence + '). A change needs ' + r.approversRequired
      + ' different administrators, and the linter refuses a destructive step on evidence anyone could forge.'));
    box.append(table(['Rule', 'What it does'], r.plays.map((p) => [p.rule, p.steps.join('; ') || 'nothing (people decide)'])));
    box.append(proposalForm('playbooks/propose', 'Propose a playbook change (YAML)'), el('div', { class: 'adm-open' }));
    openProposals(box.querySelector('.adm-open'), 'playbook');
  }

  function proposalForm(path, label) {
    const yaml = el('textarea', { class: 'adm-yaml', rows: 12, spellcheck: false, 'aria-label': label });
    const out = el('div', {});
    return el('div', {}, el('h3', {}, label), yaml,
      el('div', { class: 'adm-row' }, button('Lint and open a proposal', async () => {
        const r = await call(api.post(path, { yaml: yaml.value }));
        if (!r) return;
        clear(out);
        out.append(el('p', { class: r.linted ? 'adm-good' : 'adm-bad' }, r.linted ? 'Proposal ' + r.id + ' opened.' : 'Refused by the linter.'),
          el('ul', {}, r.findings.map((f) => el('li', {}, f))));
        if (r.linted) say('Proposal ' + r.id + ' is open; collect two signatures below.');
      })), out);
  }

  async function openProposals(box, kind) {
    const r = await call(api.get('proposals'));
    if (!r || !box) return;
    clear(box);
    box.append(el('h3', {}, 'Open proposals'));
    const mine = r.proposals.filter((p) => p.kind === kind);
    if (!mine.length) {
      box.append(el('p', {}, 'None.'));
      return;
    }
    for (const p of mine) {
      const out = el('div', {});
      box.append(el('article', { class: 'adm-card' },
        el('h4', {}, 'Proposal ' + p.id + ', change number ' + p.sequence),
        el('p', {}, 'By ' + p.proposedBy + '. Signed by: ' + (p.approvedBy.join(', ') || 'nobody yet') + ' (needs ' + p.required + ' different people). Lapses ' + p.lapsesAt + '.'),
        el('p', { class: 'adm-ref' }, 'SHA-256 ' + p.sha256),
        el('div', { class: 'adm-row' },
          kind === 'policy' ? button('What-if on recent requests', async () => {
            const w = await call(api.post('proposals/' + p.id + '/whatif', {}));
            if (!w) return;
            clear(out);
            const x = w.result;
            out.append(el('p', {}, 'Replayed ' + x.replayed + ' recent requests: ' + x.gains + ' gain access, ' + x.losses
              + ' lose access, ' + x.unchanged + ' unchanged.' + (x.valid ? '' : ' (The replay could not measure this edit.)')));
            out.append(el('p', {}, w.note));
            if (x.changes.length) {
              out.append(table(['Who', 'Resource', 'Action', 'Before', 'After', 'Direction'], x.changes.slice(0, 50).map((c) =>
                [c.subject, c.resource, c.action, c.before, c.after, c.direction])));
            }
          }) : null,
          button('Sign (approve)', async () => {
            const r2 = await privileged('proposals/' + p.id + '/approve');
            if (r2) {
              say('Signed by you. Signed so far: ' + r2.approvedBy.join(', '));
              openProposals(box, kind);
            }
          }),
          button('Install', async () => {
            const r2 = await privileged('proposals/' + p.id + '/install');
            if (!r2) return;
            say(r2.installed ? 'Installed.' : 'Not installed: ' + r2.reason, !r2.installed);
            if (r2.installed) shell.reload && shell.reload();
          }),
          button('Withdraw', async () => {
            if (await call(api.post('proposals/' + p.id + '/withdraw', {}))) openProposals(box, kind);
          })),
        el('details', {}, el('summary', {}, 'Show the text'), el('pre', {}, p.yaml)), out));
    }
  }

  // ---- privileged access --------------------------------------------------------------------------
  async function pam(box) {
    const r = await call(api.get('pam'));
    if (!r) return;
    const role = el('input', { type: 'text', value: 'prod-admin', 'aria-label': 'role' });
    const minutes = el('input', { type: 'number', min: 1, max: 480, value: 30, 'aria-label': 'minutes' });
    const why = el('input', { type: 'text', placeholder: 'why you need it (at least 10 characters)', 'aria-label': 'justification' });
    box.append(el('h3', {}, 'Ask for elevated access'),
      el('div', { class: 'adm-row' }, role, minutes, why, button('Request', async () => {
        const x = await privileged('pam/request', { role: role.value, minutes: Number(minutes.value), justification: why.value });
        if (x) {
          say(x.reason, !x.ok);
          refresh();
        }
      })),
      el('h3', {}, 'Waiting for an approver'),
      r.pending.length ? table(['Request', 'Who', 'Role', 'Minutes', 'Why', ''], r.pending.map((q) => [q.requestId, q.subjectId, q.role,
        Math.round(q.duration ? parseDuration(q.duration) : 0), q.justification, button('Approve', async () => {
          const x = await privileged('pam/approve/' + q.requestId);
          if (x) {
            say(x.reason, !x.ok);
            refresh();
          }
        })])) : el('p', {}, 'None.'),
      el('h3', {}, 'Grants'),
      r.grants.length ? table(['Grant', 'Who', 'Role', 'From', 'Until', 'Approved by', 'Break-glass', ''], r.grants.map((g) => [g.grantId, g.subjectId, g.role,
        g.from, g.until, g.approvedBy || '-', g.breakGlass ? 'yes' : 'no', button('Revoke', async () => {
          const x = await privileged('pam/revoke/' + g.grantId, { reason: 'revoked from the console' });
          if (x) {
            say('Revoked.');
            refresh();
          }
        })])) : el('p', {}, 'None.'),
      el('h3', {}, 'Emergency (break-glass) uses waiting for review'),
      r.breakGlassAwaitingReview.length ? table(['Grant', 'Who', 'Role', 'Why', '', ''], r.breakGlassAwaitingReview.map((g) => [g.grantId, g.subjectId, g.role,
        g.justification, button('Justified', async () => {
          const x = await privileged('pam/review/' + g.grantId, { verdict: 'justified' });
          if (x) {
            say(x.reason, !x.ok);
            refresh();
          }
        }), button('Misuse', async () => {
          const x = await privileged('pam/review/' + g.grantId, { verdict: 'misuse' });
          if (x) {
            say(x.reason, !x.ok);
            refresh();
          }
        })])) : el('p', {}, 'None.'));
  }

  function parseDuration(iso) {
    const m = /^PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$/.exec(String(iso));
    return m ? (Number(m[1] || 0) * 60 + Number(m[2] || 0) + Number(m[3] || 0) / 60) : 0;
  }

  // ---- sessions and devices -----------------------------------------------------------------------
  async function sessions(box) {
    const s = await call(api.get('sessions'));
    const d = await call(api.get('devices'));
    if (!s || !d) return;
    box.append(el('p', {}, s.note),
      table(['Person', 'Device', 'Address', 'Decision', 'When', 'Device verified', 'Policy'], s.sessions.map((x) =>
        [x.subject, x.device, x.sourceIp, x.outcome, x.at, x.deviceVerified ? 'yes' : 'no', x.policy])),
      el('h3', {}, 'What the SOC revoked'),
      s.revocations.length ? table(['Kind', 'Id', 'By', 'When'], s.revocations.map((x) => [x.kind, x.id, x.actor, x.at])) : el('p', {}, 'Nothing.'),
      el('h3', {}, 'Devices and posture'), el('p', {}, d.note),
      table(['Device', 'Managed', 'Verified at last request', 'Last seen', 'Last used by', 'Isolation'], d.devices.map((x) =>
        [x.device, x.managed ? 'yes' : 'no', x.verifiedLastTime ? 'yes' : 'no', x.lastSeen, x.lastBy, x.isolation])));
  }

  function labBox(box) {
    box.append(el('p', {}, 'Put the lab back at day zero. All cases, risk and launched scenarios are forgotten.'),
      button('Reset the lab', async () => {
        if (!window.confirm('Reset the lab?')) return;
        say('Resetting; this takes a few seconds...');
        const r = await privileged('lab/reset');
        if (r) say('The lab is back at day zero.');
      }));
  }

  // ---- shell --------------------------------------------------------------------------------------
  function refresh() {
    const current = [...pages.keys()].find((k) => tabs.querySelector('[data-open="true"]') === pages.get(k).tab);
    open(current || 'denied');
  }

  async function open(key) {
    for (const [k, v] of pages) v.tab.setAttribute('aria-selected', k === key ? 'true' : 'false');
    for (const [k, v] of pages) v.tab.removeAttribute('data-open');
    pages.get(key).tab.setAttribute('data-open', 'true');
    clear(body);
    await pages.get(key).draw(body);
  }

  function addTab(key, label, draw) {
    const tab = button(label, () => open(key), { role: 'tab', 'aria-selected': 'false' });
    pages.set(key, { tab, draw });
    tabs.append(tab);
  }

  root.append(el('h2', {}, 'Administration'), tabs, msg, body);
  (async () => {
    me = await call(api.get('whoami'));
    if (!me) return;
    addTab('denied', 'Why was I denied?', whyDenied);
    if (me.roles.includes('ADMIN')) {
      addTab('policy', 'Policy', policy);
      addTab('playbooks', 'Playbooks', playbooks);
      addTab('pam', 'Privileged access', pam);
      addTab('sessions', 'Sessions and devices', sessions);
      addTab('lab', 'Lab', labBox);
    }
    open('denied');
  })();
}

export default { id: 'admin', title: 'Administration', requires: 'USER', view };
