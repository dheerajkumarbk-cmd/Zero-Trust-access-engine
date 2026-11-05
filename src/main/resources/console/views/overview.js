// Overview: what needs attention now. Every panel loads on its own; one that fails says "unavailable" and the rest stay.
import {api} from '../api.js';
import {h, fill, link, panel, note, unavailable} from '../dom.js';
import {DwView} from '../view.js';
import {table} from '../table.js';
import {priority, flag, entityLink} from '../parts.js';
import {untilDeadline, num, whenSec} from '../format.js';

const ORDER = {P1: 1, P2: 2, P3: 3, P4: 4};

class DwOverview extends DwView {
  async render() {
    this.slots = {};
    const slot = (name) => (this.slots[name] = h('div', null, note('Loading...')));
    fill(this, this.title('Overview'), slot('cards'),
      h('div', {class: 'grid'},
        panel('Needs attention', slot('attention')), panel('Risk leaders', slot('risk')),
        panel('Sources (events in the last 24 hours)', slot('sources')), panel('Daily report', slot('report'))));
    await this.refresh();
    this.onLive(['case.changed', 'alert.new', 'isolation.changed'], () => this.refresh(true), 3000);
  }

  async refresh(quiet) {
    const o = {background: quiet === true};
    await Promise.all([this.part('cards', () => this.cards(o)), this.part('attention', () => this.attention(o)),
      this.part('risk', () => this.risk(o)), this.part('sources', () => this.sources()), quiet ? null : this.part('report', () => this.report())]);
  }

  async part(name, fn) {
    try {
      fill(this.slots[name], await fn());
    } catch (e) {
      fill(this.slots[name], unavailable(e));
    }
  }

  async cards(o) {
    const m = await api.metrics(o);
    const open = m.cases.open;
    const card = (n, l, bad) => h('div', {class: 'card'}, h('div', {class: 'n'}, String(n), bad && n > 0 ? h('span', {class: 'flag bad'}, ' needs action') : null), h('div', {class: 'l'}, l));
    return h('div', {class: 'cards'}, card(open.P1, 'open P1 critical', true), card(open.P2, 'open P2 high', true), card(open.P3 + open.P4, 'open P3 / P4'),
      card(m.cases.breached, 'SLA breached', true), card(m.cases.unassigned, 'unassigned cases'),
      card(m.isolation.isolated, 'devices isolated'), card(m.isolation.overdue, 'isolation acknowledgements overdue', true),
      card(m.response.awaitingSecondAnalyst, 'verdicts awaiting a second analyst'));
  }

  async attention(o) {
    const q = await api.queue(o);
    const rows = q.queue.filter((r) => r.priority === 'P1' || r.priority === 'P2')
      .sort((a, b) => ORDER[a.priority] - ORDER[b.priority] || b.score - a.score).slice(0, 8);
    if (!rows.length) return h('div', null, h('p', {class: 'empty'}, 'No open P1 or P2 case that you may see.'), link('#/queue', 'Open the queue'));
    const t = table([
      {head: 'Priority', cell: (r) => priority(r.priority)}, {head: 'Entity', cell: (r) => entityLink(r.key)},
      {head: 'SLA', cell: (r) => h('span', null, untilDeadline(r.deadline, this.lab.time || r.openedAt), r.breached ? ' ' : null, r.breached ? flag('BREACHED', 'bad') : null)},
      {head: '', cell: (r) => link('#/case/' + encodeURIComponent(r.id), 'Open')},
    ], rows, {onOpen: (r) => this.shell.navigate('#/case/' + encodeURIComponent(r.id))});
    return h('div', null, t.el, h('div', {class: 'row'}, link('#/queue', 'The whole queue (' + q.queue.length + ')')));
  }

  async risk(o) {
    const r = await api.riskTop(o);
    const top = r.top.slice(0, 8);
    if (!top.length) return h('p', {class: 'empty'}, 'No entity with risk that you may see.');
    return table([
      {head: 'Entity', cell: (x) => entityLink(x.entity)}, {head: 'Level', cell: (x) => flag(x.level.toLowerCase(), x.level === 'HIGH' || x.level === 'CRITICAL' ? 'bad' : '')},
      {head: 'Score', cls: 'num', cell: (x) => num(x.score)},
    ], top, {onOpen: (x) => this.shell.navigate('#/entity/' + x.entity.kind + '/' + encodeURIComponent(x.entity.id))}).el;
  }

  async sources() {
    const to = new Date(new Date(this.lab.time).getTime() + 1000);
    const from = new Date(to.getTime() - 86400000);
    const r = await api.counts('* | count by dataset', from.toISOString(), to.toISOString());
    if (r.problem) return h('div', {class: 'unavailable'}, 'The count was refused: ' + r.problem);
    const wanted = ['firewall', 'endpoint', 'cloud'];
    const seen = new Map(r.groups.map((g) => [g.values[0], g.count]));
    return h('ul', {class: 'plain'}, wanted.concat([...seen.keys()].filter((k) => !wanted.includes(k))).map((d) => h('li', null,
      seen.has(d) ? flag('reporting', 'ok') : flag('SILENT', 'bad'), ' ', h('b', null, d), ' ', String(seen.get(d) || 0) + ' events')),
    h('li', null, note('A source with no event in 24 hours may be down: treat silence as a finding, not as quiet.')));
  }

  async report() {
    try {
      const r = await api.report('daily');
      return h('div', null, h('pre', null, r.text), note('Daily report for scenario day ' + whenSec(this.lab.time).slice(0, 10) + '.'));
    } catch (e) {
      if (e.status === 404) return note('Reports are for SOC leads.');
      throw e;
    }
  }
}
customElements.define('dw-overview', DwOverview);
