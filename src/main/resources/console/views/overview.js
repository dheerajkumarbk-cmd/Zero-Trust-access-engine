// Overview: what needs attention now. Every panel loads on its own; one that fails says "unavailable" and the rest stay.
import {api} from '../api.js';
import {h, fill, link, panel, note, unavailable} from '../dom.js';
import {DwView} from '../view.js';
import {table} from '../table.js';
import {priority, flag, entityLink} from '../parts.js';
import {untilDeadline, num, when, whenSec} from '../format.js';
import {hbars, columns} from '../chart.js';

const ORDER = {P1: 1, P2: 2, P3: 3, P4: 4};
const HOUR = 3600000;
const BARS = 12;

class DwOverview extends DwView {
  async render() {
    this.slots = {};
    const slot = (name) => (this.slots[name] = h('div', null, note('Loading...')));
    const report = panel('Daily report', slot('report'));
    report.classList.add('wide');
    fill(this, this.title('Overview'), slot('cards'),
      h('div', {class: 'grid charts'},
        panel('Alerts over time', note('Alerts in open cases, by when the case opened'), slot('overTime')),
        panel('Open alerts by priority', note('Open cases at each priority'), slot('byPriority')),
        panel('Events by source', note('Last 24 hours'), slot('bySource')),
        panel('Top entities by risk', note('Bars are relative to the highest score'), slot('byRisk'))),
      h('div', {class: 'grid'},
        panel('Needs attention', slot('attention')), panel('Risk leaders', slot('risk')),
        panel('Sources (events in the last 24 hours)', slot('sources')), report));
    await this.refresh();
    this.onLive(['case.changed', 'alert.new', 'isolation.changed'], () => this.refresh(true), 3000);
  }

  async refresh(quiet) {
    const o = {background: quiet === true};
    // one request per kind of data, shared by the panel and its chart: the charts add no read to the audit trail
    const metrics = api.metrics(o);
    const queue = api.queue(o);
    const risk = api.riskTop(o);
    const counts = this.counts();
    await Promise.all([this.part('cards', () => this.cards(metrics)), this.part('attention', () => this.attention(queue)),
      this.part('risk', () => this.risk(risk)), this.part('sources', () => this.sources(counts)),
      this.part('overTime', () => this.overTime(queue)), this.part('byPriority', () => this.byPriority(metrics)),
      this.part('bySource', () => this.bySource(counts)), this.part('byRisk', () => this.byRisk(risk)),
      quiet ? null : this.part('report', () => this.report())]);
  }

  async part(name, fn) {
    try {
      fill(this.slots[name], await fn());
    } catch (e) {
      fill(this.slots[name], unavailable(e));
    }
  }

  async cards(metrics) {
    const m = await metrics;
    const open = m.cases.open;
    const card = (n, l, bad) => h('div', {class: 'card'}, h('div', {class: 'n'}, String(n), bad && n > 0 ? h('span', {class: 'flag bad'}, ' needs action') : null), h('div', {class: 'l'}, l));
    return h('div', {class: 'cards overview'}, card(open.P1, 'open P1 critical', true), card(open.P2, 'open P2 high', true), card(open.P3 + open.P4, 'open P3 / P4'),
      card(m.cases.breached, 'SLA breached', true), card(m.cases.unassigned, 'unassigned cases'),
      card(m.isolation.isolated, 'devices isolated'), card(m.isolation.overdue, 'isolation acknowledgements overdue', true),
      card(m.response.awaitingSecondAnalyst, 'verdicts awaiting a second analyst'));
  }

  async attention(queue) {
    const q = await queue;
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

  async risk(risk) {
    const r = await risk;
    const top = r.top.slice(0, 8);
    if (!top.length) return h('p', {class: 'empty'}, 'No entity with risk that you may see.');
    return table([
      {head: 'Entity', cell: (x) => entityLink(x.entity)}, {head: 'Level', cell: (x) => flag(x.level.toLowerCase(), x.level === 'HIGH' || x.level === 'CRITICAL' ? 'bad' : '')},
      {head: 'Score', cls: 'num', cell: (x) => num(x.score)},
    ], top, {onOpen: (x) => this.shell.navigate('#/entity/' + x.entity.kind + '/' + encodeURIComponent(x.entity.id))}).el;
  }

  async counts() {
    const to = new Date(new Date(this.lab.time).getTime() + 1000);
    const from = new Date(to.getTime() - 86400000);
    return api.counts('* | count by dataset', from.toISOString(), to.toISOString());
  }

  async sources(counts) {
    const r = await counts;
    if (r.problem) return h('div', {class: 'unavailable'}, 'The count was refused: ' + r.problem);
    const seen = new Map(r.groups.map((g) => [g.values[0], g.count]));
    return h('ul', {class: 'plain'}, this.datasets(seen).map((d) => h('li', null,
      seen.has(d) ? flag('reporting', 'ok') : flag('SILENT', 'bad'), ' ', h('b', null, d), ' ', String(seen.get(d) || 0) + ' events')),
    h('li', null, note('A source with no event in 24 hours may be down: treat silence as a finding, not as quiet.')));
  }

  datasets(seen) {
    const wanted = ['firewall', 'endpoint', 'cloud'];
    return wanted.concat([...seen.keys()].filter((k) => !wanted.includes(k)));
  }

  /** Twelve bars ending now, each 1 to 24 hours wide or more, whichever first covers the oldest open case. */
  async overTime(queue) {
    const rows = (await queue).queue;
    if (!rows.length) return h('p', {class: 'empty'}, 'No open case that you may see.');
    const opened = rows.map((r) => new Date(r.openedAt).getTime());
    const now = new Date(this.lab.time).getTime();
    const age = Math.max(HOUR, now - Math.min(...opened));
    const hours = [1, 2, 4, 6, 12, 24].find((x) => age / (x * HOUR) <= BARS - 1) || 24 * Math.ceil(age / (24 * HOUR * (BARS - 1)));
    const width = hours * HOUR;
    const end = Math.ceil(now / width) * width;
    const start = end - BARS * width;
    const bars = Array.from({length: BARS}, () => 0);
    rows.forEach((r, i) => {
      bars[Math.min(BARS - 1, Math.max(0, Math.floor((opened[i] - start) / width)))] += r.alerts;
    });
    return columns(bars.map((value, i) => ({value, title: when(new Date(start + i * width).toISOString()) + ': ' + value + ' alerts'})),
      when(new Date(start).toISOString()), when(new Date(end).toISOString()), 'Alerts in open cases over time');
  }

  async byPriority(metrics) {
    const open = (await metrics).cases.open;
    return hbars(['P1', 'P2', 'P3', 'P4'].map((p) => ({label: priority(p), value: open[p], tone: p.toLowerCase()})), 'Open cases by priority');
  }

  async bySource(counts) {
    const r = await counts;
    if (r.problem) return h('div', {class: 'unavailable'}, 'The count was refused: ' + r.problem);
    const seen = new Map(r.groups.map((g) => [g.values[0], g.count]));
    const rows = this.datasets(seen).map((d) => ({label: d, value: seen.get(d) || 0})).sort((a, b) => b.value - a.value);
    return hbars(rows, 'Events by source');
  }

  async byRisk(risk) {
    const top = (await risk).top.slice(0, 5);
    if (!top.length) return h('p', {class: 'empty'}, 'No entity with risk that you may see.');
    return hbars(top.map((x) => ({label: entityLink(x.entity), value: Number(x.score), text: num(x.score)})), 'Top entities by risk score');
  }

  async report() {
    try {
      const r = await api.report('daily');
      return h('div', null, h('pre', {class: 'report', tabindex: 0}, r.text), note('Daily report for scenario day ' + whenSec(this.lab.time).slice(0, 10) + '.'));
    } catch (e) {
      if (e.status === 404 || e.status === 403) return note('Reports are for SOC leads. Sign in as cleo to see the daily report.');
      throw e;
    }
  }
}
customElements.define('dw-overview', DwOverview);
