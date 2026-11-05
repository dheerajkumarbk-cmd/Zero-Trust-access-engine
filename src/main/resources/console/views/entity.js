// The entity page: a person, device, address, session or resource, with its risk as a list of contributions.
import {api} from '../api.js';
import {h, fill, link, panel, note} from '../dom.js';
import {DwView} from '../view.js';
import {table} from '../table.js';
import {priority, flag, entityLink, evidence, provenance} from '../parts.js';
import {when, ago, num, whenSec} from '../format.js';

const KINDS = ['subject', 'device', 'ip', 'session', 'resource'];

class DwEntity extends DwView {
  async render() {
    const [kind, id] = this.ctx.args;
    if (kind && id) await this.page(kind, id);
    else await this.landing();
  }

  lookup(kind, id) {
    const k = h('select', {id: 'ek', 'aria-label': 'Kind'}, KINDS.map((x) => h('option', {value: x, selected: x === kind}, x)));
    const i = h('input', {type: 'text', id: 'ei', value: id || '', placeholder: 'id, e.g. u-014 or laptop-14', 'aria-label': 'Identifier', spellcheck: false});
    const form = h('form', {method: 'dialog'}, h('div', {class: 'row'}, k, h('div', {class: 'grow'}, i), h('button', {type: 'submit', class: 'primary'}, 'Look up')));
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      if (i.value.trim()) this.shell.navigate('#/entity/' + encodeURIComponent(k.value) + '/' + encodeURIComponent(i.value.trim()));
    });
    return form;
  }

  async landing() {
    const top = await api.riskTop();
    const t = table([
      {head: 'Entity', cell: (r) => entityLink(r.entity)},
      {head: 'Level', cell: (r) => flag(r.level.toLowerCase(), r.level === 'HIGH' || r.level === 'CRITICAL' ? 'bad' : '')},
      {head: 'Score', cls: 'num', cell: (r) => num(r.score)},
      {head: 'Why', cls: 'wrap', cell: (r) => (r.contributions[0] ? r.contributions[0].reason : '')},
    ], top.top, {onOpen: (r) => this.shell.navigate('#/entity/' + r.entity.kind + '/' + encodeURIComponent(r.entity.id))});
    fill(this, this.title('Entities'), panel('Look up', this.lookup()),
      panel('Highest risk now', top.top.length ? t.el : h('p', {class: 'empty'}, 'The SOC API shows no entity with risk that you may see.'),
        note('Entities about analysts are hidden from analysts by the SOC API, and the count of what is hidden is not shown either.')));
  }

  async page(kind, id) {
    const [risk, cases] = await Promise.all([api.risk(kind, id), api.cases({background: true})]);
    const mine = cases.cases.filter((c) => c.key.kind === kind && c.key.id === id);
    const asOf = risk.asOf;
    const list = risk.contributions.slice().sort((a, b) => b.weight - a.weight);
    const max = Math.max(0.0001, ...list.map((c) => Math.abs(c.weight)));
    const t = table([
      {head: 'Source', cell: (c) => c.source},
      {head: 'Weight now', cls: 'num', cell: (c) => num(c.weight, 2)},
      {head: '', cell: (c) => h('meter', {min: 0, max, value: Math.max(0, c.weight), 'aria-label': 'weight ' + num(c.weight, 2)}, num(c.weight, 2))},
      {head: 'Happened', cell: (c) => when(c.at) + ' (' + ago(c.at, asOf) + ')'},
      {head: 'Reason', cls: 'wrap', cell: (c) => c.reason},
      {head: 'Evidence', cell: (c) => evidence(c.evidence)},
    ], list, {});
    fill(this, this.title(kind + ': ' + id, flag('risk ' + risk.level.toLowerCase(), risk.level === 'HIGH' || risk.level === 'CRITICAL' ? 'bad' : ''),
      h('span', {class: 'muted'}, 'score ' + num(risk.score) + ' as of ' + whenSec(asOf))),
      panel('Look up another', this.lookup(kind, id)),
      panel('Where the risk comes from',
        list.length ? t.el : h('p', {class: 'empty'}, 'Nothing contributes to this entity\'s risk right now.'),
        note('Each contribution decays by half every fixed half-life (a different one per source), so the weight shown is the weight today. The half-life itself is not yet returned by the SOC API.')),
      panel('Cases about this entity', mine.length ? h('ul', {class: 'plain'}, mine.map((c) => h('li', null, priority(c.priority), ' ',
        link('#/case/' + encodeURIComponent(c.id), c.id), ' ', c.state.toLowerCase()))) : h('p', {class: 'empty'}, 'No case you may see is about this entity.')),
      await this.events(kind, id));
  }

  async events(kind, id) {
    const to = new Date(new Date(this.lab.time).getTime() + 1000);
    const from = new Date(to.getTime() - 86400 * 1000);
    try {
      const r = await api.search(kind + ' = "' + id.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"', from.toISOString(), to.toISOString(), 15);
      if (r.problem) return panel('Recent events', note('The search was refused: ' + r.problem));
      return panel('Recent events (last 24 hours, newest first)', r.events.length ? table([
        {head: 'Time', cell: (e) => whenSec(e.at)}, {head: 'Dataset', cell: (e) => e.dataset}, {head: 'Action', cell: (e) => e.action},
        {head: 'Outcome', cell: (e) => e.outcome.toLowerCase()}, {head: 'Class', cell: (e) => provenance(e.provenance)},
        {head: 'Audit #', cls: 'num', cell: (e) => link('#/audit/' + e.sequence, String(e.sequence))},
      ], r.events, {}).el : h('p', {class: 'empty'}, 'No event in the last 24 hours.'),
      h('div', {class: 'row'}, link('#/hunt?q=' + encodeURIComponent(kind + ' = "' + id + '"'), 'Open in Hunt')));
    } catch (e) {
      return panel('Recent events', h('div', {class: 'unavailable'}, 'Recent events are unavailable (' + e.message + ').'));
    }
  }
}
customElements.define('dw-entity', DwEntity);
