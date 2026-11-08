// What the short words mean: the Glossary dialog, and the same meanings when the mouse rests on a word in a view.
import {h, fill} from './dom.js';

const GROUPS = [
  ['Priorities', [
    ['P1', 'Critical. Act first; the shortest deadline.'],
    ['P2', 'High. Act soon.'],
    ['P3', 'Medium. Look at it today.'],
    ['P4', 'Low. A note, usually no action.'],
  ]],
  ['Scenarios', [
    ['A1', 'Credential stuffing: a leaked password tried from abroad.'],
    ['A2', 'Login from a cloud server in the same country.'],
    ['A3', 'Residential proxy in the person\'s own city.'],
    ['A4', 'Impossible travel: two logins too far apart for the time between them.'],
    ['A5', 'Login through Tor.'],
    ['A6', 'Stolen laptop used from the owner\'s network.'],
    ['A7', 'Password spray: one address tries many accounts.'],
    ['A8', 'Beaconing: malware calling its command server on a rhythm.'],
    ['A9', 'Mass download, then a share with an outside address.'],
    ['A10', 'Endpoint sensor switched off, so its heartbeat stops.'],
    ['L5', 'Harmless look-alike: a quarter-end download.'],
    ['L6', 'Harmless look-alike: an administrator\'s signed PowerShell.'],
    ['QUIET', 'A normal day with no attack, to show what quiet looks like.'],
  ]],
  ['Decisions', [
    ['ALLOW', 'The access engine lets the request through.'],
    ['DENY', 'The access engine refuses the request.'],
    ['STEP_UP', 'The access engine asks for a second factor first.'],
  ]],
  ['Security terms', [
    ['SOC', 'Security Operations Centre: the team that watches for and handles attacks.'],
    ['SLA', 'Service Level Agreement: the deadline for responding to a case.'],
    ['UEBA', 'User and Entity Behaviour Analytics: flags activity unusual for that person or device.'],
    ['MITRE', 'The organisation that publishes ATT&CK.'],
    ['ATT&CK', 'MITRE\'s public catalogue of attacker tactics and techniques.'],
    ['PDP', 'Policy Decision Point: the part that decides allow or deny.'],
    ['ZTNA', 'Zero Trust Network Access: reach one app after a check, never the whole network.'],
    ['PAM', 'Privileged Access Management: admin rights granted only when needed.'],
    ['MFA', 'Multi-Factor Authentication: a second proof beyond the password.'],
    ['DLP', 'Data Loss Prevention: stops sensitive data leaving.'],
    ['IP', 'Internet Protocol address: a device\'s network address.'],
    ['MAC', 'Message Authentication Code: a keyed checksum that shows a record was not changed.'],
    ['SOAR', 'Security Orchestration, Automation and Response: playbooks that act on alerts.'],
    ['SIEM', 'Security Information and Event Management: collects and searches security events.'],
    ['YAML', 'A plain-text format for settings; rules and playbooks are written in it.'],
  ]],
  ['Dwarpal words', [
    ['entity', 'Something risk is scored for: a person, device, address, session or resource.'],
    ['playbook', 'A reviewed list of response steps that runs on a signed verdict.'],
    ['verdict', 'An analyst\'s signed decision on an alert: true positive, false positive or benign.'],
    ['step-up', 'Proving your password and PIN again before a sensitive action.'],
    ['isolation', 'Cutting a device off from the network until a human lifts it.'],
    ['anchor', 'A protected copy of the audit trail\'s end, used to show nothing was rewritten.'],
    ['passkey', 'A secret of your own. One entry opens cases, entities and hunt together for 15 minutes (the footer counts the time down). The audit explorer needs a fresher entry, valid for 5 minutes. A response action, an export or a policy change asks every time.'],
    ['elevation', 'A short, reasoned period for privileged changes (a decision on access, a change to an administrator). You give your PIN, your passkey and a reason; it lasts 10 minutes, the footer counts them down, and everything you do inside it is recorded under it. A request made by an administrator always goes to the other administrator.'],
    ['backup code', 'A one-use code that sets a new password and PIN if yours are stolen or lost.'],
    ['scan', 'A read-only check of the audit trail, sensors, refused access, firewall, logs, cases and risk.'],
  ]],
];

const TEAM_ONLY = ['Priorities', 'Scenarios', 'Decisions'];
const MEANING = new Map(GROUPS.flatMap(([, list]) => list));
const WORD = /(?<![\w-])(ATT&CK|STEP_UP|QUIET|ALLOW|DENY|MITRE|UEBA|SOAR|SIEM|YAML|ZTNA|SOC|SLA|PDP|PAM|MFA|DLP|MAC|IP|P[1-4]|A10|A[1-9]|L[56])(?![\w-])/g;
const SKIP = 'input, textarea, select, option, pre, code, kbd, script, style, canvas, .term, td.mono, dialog';

function decorateText(node) {
  const text = node.nodeValue;
  if (text.search(WORD) < 0) return;
  const out = document.createDocumentFragment();
  let last = 0;
  for (const m of text.matchAll(WORD)) {
    out.append(text.slice(last, m.index));
    out.append(h('span', {class: 'term', 'data-tip': MEANING.get(m[1])}, m[1]));
    last = m.index + m[1].length;
  }
  out.append(text.slice(last));
  node.replaceWith(out);
}

function decorate(root) {
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  const found = [];
  while (walker.nextNode()) {
    const n = walker.currentNode;
    if (n.parentElement && !n.parentElement.closest(SKIP)) found.push(n);
  }
  found.forEach(decorateText);
}

/** Keeps root's words explained as views draw themselves. Text only ever moves into spans; nothing is parsed. */
export function explain(root) {
  let pending = false;
  const seen = new MutationObserver(() => {
    if (pending) return;
    pending = true;
    requestAnimationFrame(() => {
      pending = false;
      decorate(root);
      seen.takeRecords();
    });
  });
  seen.observe(root, {childList: true, subtree: true, characterData: true});
  root.addEventListener('mouseover', (e) => {
    const t = e.target;
    if (!(t instanceof Element) || !t.classList.contains('term')) return;
    t.classList.toggle('tip-left', e.clientX > window.innerWidth - 340);
    t.classList.toggle('tip-up', e.clientY > window.innerHeight - 120);
  });
}

/** full: the whole list. Without it, only what a person outside the security team needs. */
export function glossary(full) {
  const groups = GROUPS.filter(([title]) => full || !TEAM_ONLY.includes(title));
  const dlg = h('dialog', {class: 'glossary', 'aria-labelledby': 'gl-title'});
  dlg.addEventListener('close', () => dlg.remove());
  const list = h('div');
  const find = h('input', {type: 'text', placeholder: full ? 'Search, for example SLA or A6' : 'Search, for example MFA', 'aria-label': 'Search the glossary', spellcheck: false});
  const draw = () => {
    const q = find.value.trim().toLowerCase();
    fill(list, h('dl', null, groups.flatMap(([title, items]) => {
      const hit = items.filter(([k, v]) => !q || k.toLowerCase().includes(q) || v.toLowerCase().includes(q));
      return hit.length ? [h('h2', null, title), hit.flatMap(([k, v]) => [h('dt', null, k), h('dd', null, v)])] : [];
    })));
  };
  find.addEventListener('input', draw);
  draw();
  dlg.append(h('h1', {id: 'gl-title'}, 'Glossary'), find, list,
    h('div', {class: 'row'}, h('button', {type: 'button', class: 'primary', on: {click: () => dlg.close()}}, 'Close')));
  document.body.append(dlg);
  dlg.showModal();
}
