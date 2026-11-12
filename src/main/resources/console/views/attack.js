// MITRE ATT&CK grid: techniques the open cases rest on, by tactic, shaded by how many alerts hit them. Colour is never the
// only signal: every technique shows its count as text.
import {api} from '../api.js';
import {h, fill, link, panel, note} from '../dom.js';
import {DwView} from '../view.js';
import {priority, caseDetail, pool} from '../parts.js';

const TACTICS = ['reconnaissance', 'resource-development', 'initial-access', 'execution', 'persistence', 'privilege-escalation',
  'defense-evasion', 'credential-access', 'discovery', 'lateral-movement', 'collection', 'command-and-control', 'exfiltration', 'impact'];
const ORDER = {P1: 1, P2: 2, P3: 3, P4: 4};
const MAX_CASES = 80;

class DwAttack extends DwView {
  async render() {
    const q = await api.queue();
    const rows = q.queue.slice().sort((a, b) => ORDER[a.priority] - ORDER[b.priority] || b.score - a.score);
    const used = rows.slice(0, MAX_CASES);
    fill(this, this.title('ATT&CK'), note('Reading ' + used.length + ' of ' + rows.length + ' open cases...'));
    const cells = new Map();
    let failed = 0;
    await pool(used, 4, async (row) => {
      try {
        const d = await caseDetail(row, {background: true});
        for (const a of d.rankedAlerts) {
          for (const t of a.techniques) {
            const key = t.tactic + '|' + t.id;
            const c = cells.get(key) || {tactic: t.tactic, id: t.id, name: t.name, alerts: 0, cases: new Map()};
            c.alerts++;
            c.cases.set(row.id, row);
            cells.set(key, c);
          }
        }
      } catch (e) {
        failed++;
        throw e;
      }
    });
    const tactics = [...new Set([...TACTICS.filter((t) => [...cells.values()].some((c) => c.tactic === t)),
      ...[...cells.values()].map((c) => c.tactic)])];
    this.detail = h('div');
    fill(this, this.title('ATT&CK', h('span', {class: 'muted'}, cells.size + ' techniques seen')),
      failed ? h('div', {class: 'unavailable', role: 'alert'}, h('b', null, 'Incomplete. '), failed + ' cases could not be read, so some techniques may be missing.') : null,
      note('Detections only: techniques named by the alerts of the ' + used.length + ' highest-priority open cases' +
        (rows.length > used.length ? ' (of ' + rows.length + ')' : '') + '. What the rules could catch but have not (coverage) is not exposed by the SOC API yet. Shade and the "x" count both show how many alerts hit a technique.'),
      cells.size ? h('div', {class: 'attack'}, tactics.map((tac) => h('div', {class: 'tactic'}, h('h3', null, tac.replace(/-/g, ' ')),
        [...cells.values()].filter((c) => c.tactic === tac).sort((a, b) => b.alerts - a.alerts).map((c) => this.tech(c))))) : h('p', {class: 'empty'}, 'No open case names a technique.'),
      this.detail);
  }

  tech(c) {
    const lvl = c.alerts >= 8 ? 4 : c.alerts >= 4 ? 3 : c.alerts >= 2 ? 2 : 1;
    const b = h('button', {type: 'button', class: 'tech l' + lvl, title: c.name + ': ' + c.alerts + ' alerts in ' + c.cases.size + ' cases'},
      h('b', null, c.id + '  x' + c.alerts), c.name);
    b.addEventListener('click', () => fill(this.detail, panel(c.id + ' ' + c.name + ' (' + c.tactic + ')',
      h('ul', {class: 'plain'}, [...c.cases.values()].map((r) => h('li', null, priority(r.priority), ' ', link('#/case/' + encodeURIComponent(r.id), r.id), ' ',
        h('span', {class: 'muted'}, r.key.kind + ':' + r.key.id)))))));
    return b;
  }
}
customElements.define('dw-attack', DwAttack);
