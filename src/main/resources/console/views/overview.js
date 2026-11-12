// Overview: the shift handover. Numbers first, then a few plain sentences on what needs attention, then how alerts are
// moving, then the cases and risk behind them. Every panel loads on its own; one that fails says "unavailable" and the
// rest stay. Everything here is worked out from data the console already has.
import {api} from '../api.js';
import {h, fill, link, panel, cream, spot, note, unavailable} from '../dom.js';
import {DwView} from '../view.js';
import {table} from '../table.js';
import {priority, flag, entityLink} from '../parts.js';
import {untilDeadline, num, count, span, when, whenSec} from '../format.js';
import {hbars, stacked, funnel} from '../chart.js';

const ORDER = {P1: 1, P2: 2, P3: 3, P4: 4};
const PRIORITIES = ['P1', 'P2', 'P3', 'P4'];
const HOUR = 3600000;
const BARS = 12;

const section = (n, text) => h('div', {class: 'section-head'}, h('span', {class: 'eyebrow'}, 'Part ' + n), h('h2', null, text));

class DwOverview extends DwView {
  async render() {
    this.slots = {};
    const slot = (name) => (this.slots[name] = h('div', null, note('Loading...')));
    this.stamp = h('span', {class: 'muted'});
    const again = h('button', {type: 'button', on: {click: () => this.refresh()}}, 'Refresh');
    const report = spot('report', cream('Daily report', slot('report')));
    report.classList.add('wide');
    fill(this, this.title('Overview'),
      section(1, 'Shift handover at a glance'), slot('cards'),
      h('section', {class: 'panel cream'}, h('div', {class: 'panel-head'}, h('h2', null, 'What needs attention'), h('span', {class: 'spacer'}), this.stamp, again), slot('brief')),
      h('div', {class: 'quick'}, link('#/scans', 'Run a scan', 'button-link'), link('#/queue', 'Open the queue', 'button-link'),
        link('#/hunt', 'Start a hunt', 'button-link'), link('#/response', 'Respond to a case', 'button-link')),
      section(2, 'Alert flow and triage'),
      h('div', {class: 'grid charts'},
        panel('Alerts by priority over time', note('By when the case opened, closed cases included'), slot('overTime')),
        panel('Events by source', note('Last 24 hours of scenario time'), slot('bySource')),
        panel('From alert to closed case', note('How far the work has got so far'), slot('funnel')),
        panel('Open cases by priority', note('What is still waiting'), slot('byPriority'))),
      section(3, 'Cases, risk and reporting'),
      h('div', {class: 'grid two'},
        panel('Most urgent cases', slot('attention')), panel('Top entities by risk', note('Bars are relative to the highest score'), slot('byRisk')), report));
    await this.refresh();
    this.onLive(['case.changed', 'alert.new', 'isolation.changed'], () => this.refresh(true), 3000);
  }

  async refresh(quiet) {
    const o = {background: quiet === true};
    // one request per kind of data, shared by the panels: the charts add no read to the audit trail
    const metrics = api.metrics(o);
    const queue = api.queue(o);
    const cases = api.cases(o);
    const risk = api.riskTop(o);
    const counts = this.counts();
    await Promise.all([this.part('cards', () => this.cards(metrics, queue)), this.part('brief', () => this.brief(metrics, queue, risk, counts)),
      this.part('attention', () => this.attention(queue)), this.part('overTime', () => this.overTime(cases)),
      this.part('byPriority', () => this.byPriority(metrics)), this.part('bySource', () => this.bySource(counts)),
      this.part('funnel', () => this.funnel(metrics)), this.part('byRisk', () => this.byRisk(risk)),
      quiet ? null : this.part('report', () => this.report())]);
    fill(this.stamp, 'Updated ' + whenSec(this.lab.time).slice(11, 19) + ' scenario time');
  }

  async part(name, fn) {
    try {
      fill(this.slots[name], await fn());
    } catch (e) {
      fill(this.slots[name], unavailable(e));
    }
  }

  async cards(metrics, queue) {
    const m = await metrics;
    const open = m.cases.open;
    const rows = (await queue).queue;
    const total = open.P1 + open.P2 + open.P3 + open.P4;
    const now = new Date(this.lab.time).getTime();
    const ages = rows.map((r) => now - new Date(r.openedAt).getTime()).sort((a, b) => a - b);
    const median = ages.length ? span(ages[Math.floor(ages.length / 2)]) : '-';
    const raised = this.lab.counts ? this.lab.counts.alertsRaised : '-';
    const card = (n, l, what, href, alarm) => h('a', {class: 'card' + (alarm ? ' alarm' : ''), href}, h('div', {class: 'n'}, String(n)), h('div', {class: 'l'}, l), h('div', {class: 'd'}, what));
    return h('div', {class: 'cards overview'}, card(raised, 'Alerts raised', 'Since this lab began', '#/cases'),
      card(total, 'Open cases', m.cases.unassigned + ' with no owner', '#/queue'),
      card(open.P1 + open.P2, 'Critical and high', open.P1 + ' P1, ' + open.P2 + ' P2', '#/queue', open.P1 > 0),
      card(m.cases.breached, 'SLA breached', 'Past their response deadline', '#/queue', m.cases.breached > 0),
      card(median, 'Median open age', 'How long open cases have waited', '#/queue'));
  }

  /** Plain sentences, most important first, each worked out from the live figures. */
  async brief(metrics, queue, risk, counts) {
    const [m, q, r, c] = await Promise.all([metrics, queue, risk, counts]);
    const open = m.cases.open;
    const lines = [];
    const say = (lead, rest) => lines.push(h('li', null, h('b', null, lead), rest));
    if (open.P1 > 0) {
      const first = q.queue.slice().sort((a, b) => ORDER[a.priority] - ORDER[b.priority] || b.score - a.score)[0];
      say(open.P1 + (open.P1 === 1 ? ' critical case is open.' : ' critical cases are open.'), first ? ' Start with ' + first.key.kind + ':' + first.key.id + ', score ' + num(first.score) + '.' : '');
    }
    if (m.cases.breached > 0) say(m.cases.breached + (m.cases.breached === 1 ? ' case is' : ' cases are') + ' past the response deadline', m.cases.unassigned > 0 ? ', and ' + m.cases.unassigned + ' have no owner.' : '.');
    else if (m.cases.unassigned > 0) say(m.cases.unassigned + ' cases have no owner.', ' Assign them before a deadline passes.');
    if (!c.problem && c.groups.length) {
      const total = c.groups.reduce((a, g) => a + g.count, 0);
      const noisy = c.groups.slice().sort((a, b) => b.count - a.count)[0];
      const silent = ['firewall', 'endpoint', 'cloud'].filter((d) => !c.groups.some((g) => g.values[0] === d));
      if (silent.length) say(silent.join(', ') + ' sent nothing in 24 hours.', ' A silent source may be down, so treat it as a finding.');
      else say(noisy.values[0] + ' is the busiest source:', ' ' + count(noisy.count) + ' of ' + count(total) + ' events (' + Math.round((noisy.count / total) * 100) + '%) in the last 24 hours.');
    }
    const lead = r.top[0];
    if (lead && (lead.level === 'HIGH' || lead.level === 'CRITICAL')) say(lead.entity.kind + ':' + lead.entity.id + ' has the highest risk,', ' at ' + num(lead.score) + ' (' + lead.level.toLowerCase() + ').');
    if (m.isolation.overdue > 0) say(m.isolation.overdue + ' device isolations are unconfirmed.', ' The sensor has not acknowledged them in time.');
    if (m.response.awaitingSecondAnalyst > 0) say(m.response.awaitingSecondAnalyst + ' verdicts are waiting for a second analyst.', '');
    if (!lines.length) return h('p', {class: 'empty'}, 'Nothing needs attention right now: no critical case, no breach, no unowned work.');
    return h('ul', {class: 'brief'}, lines.slice(0, 5));
  }

  async attention(queue) {
    const q = await queue;
    const rows = q.queue.filter((r) => r.priority === 'P1' || r.priority === 'P2')
      .sort((a, b) => ORDER[a.priority] - ORDER[b.priority] || b.score - a.score).slice(0, 6);
    if (!rows.length) return h('div', null, h('p', {class: 'empty'}, 'No open P1 or P2 case that you may see.'), link('#/queue', 'Open the queue'));
    const t = table([
      {head: 'Priority', cell: (r) => priority(r.priority)}, {head: 'Entity', cell: (r) => entityLink(r.key)},
      {head: 'SLA', cell: (r) => h('span', null, untilDeadline(r.deadline, this.lab.time || r.openedAt), r.breached ? ' ' : null, r.breached ? flag('BREACHED', 'bad') : null)},
      {head: '', cell: (r) => link('#/case/' + encodeURIComponent(r.id), 'Open')},
    ], rows, {onOpen: (r) => this.shell.navigate('#/case/' + encodeURIComponent(r.id))});
    return h('div', null, t.el, h('div', {class: 'row'}, link('#/queue', 'The whole queue (' + q.queue.length + ')')));
  }

  async counts() {
    const to = new Date(new Date(this.lab.time).getTime() + 1000);
    const from = new Date(to.getTime() - 86400000);
    return api.counts('* | count by dataset', from.toISOString(), to.toISOString());
  }

  datasets(seen) {
    const wanted = ['firewall', 'endpoint', 'cloud'];
    return wanted.concat([...seen.keys()].filter((k) => !wanted.includes(k)));
  }

  /** Twelve bars ending now, each wide enough that together they cover the oldest case. */
  async overTime(cases) {
    const rows = (await cases).cases;
    if (!rows.length) return h('p', {class: 'empty'}, 'No case that you may see.');
    const opened = rows.map((r) => new Date(r.openedAt).getTime());
    const now = new Date(this.lab.time).getTime();
    const age = Math.max(HOUR, now - Math.min(...opened));
    const hours = [1, 2, 4, 6, 12, 24].find((x) => age / (x * HOUR) <= BARS - 1) || 24 * Math.ceil(age / (24 * HOUR * (BARS - 1)));
    const width = hours * HOUR;
    const end = Math.ceil(now / width) * width;
    const start = end - BARS * width;
    const bars = Array.from({length: BARS}, (_, i) => ({P1: 0, P2: 0, P3: 0, P4: 0, at: start + i * width}));
    rows.forEach((r, i) => {
      bars[Math.min(BARS - 1, Math.max(0, Math.floor((opened[i] - start) / width)))][r.priority] += r.alerts;
    });
    const stamp = (t) => (hours >= 24 ? when(new Date(t).toISOString()).slice(5, 10) : when(new Date(t).toISOString()).slice(5, 16));
    return stacked(bars.map((b) => ({parts: PRIORITIES.map((p) => ({tone: p.toLowerCase(), value: b[p]})),
      title: when(new Date(b.at).toISOString()) + ': ' + PRIORITIES.map((p) => p + ' ' + b[p]).join(', ')})),
    PRIORITIES.map((p) => ({tone: p.toLowerCase(), label: p})), [0, 1 / 3, 2 / 3, 1].map((f) => stamp(start + f * BARS * width)), 'Alerts by priority over time');
  }

  async byPriority(metrics) {
    const open = (await metrics).cases.open;
    return hbars(PRIORITIES.map((p) => ({label: priority(p), value: open[p], tone: p.toLowerCase()})), 'Open cases by priority');
  }

  async funnel(metrics) {
    const m = (await metrics).cases;
    const open = PRIORITIES.reduce((a, p) => a + m.open[p], 0);
    const raised = this.lab.counts ? this.lab.counts.alertsRaised : 0;
    return funnel([{label: 'Alerts raised', value: raised}, {label: 'Cases opened', value: m.tracked},
      {label: 'Picked up', value: m.tracked - m.unassigned}, {label: 'Closed', value: m.tracked - open}], 'From alert to closed case');
  }

  async bySource(counts) {
    const r = await counts;
    if (r.problem) return h('div', {class: 'unavailable'}, 'The count was refused: ' + r.problem);
    const seen = new Map(r.groups.map((g) => [g.values[0], g.count]));
    const rows = this.datasets(seen).map((d) => ({label: seen.has(d) ? d : h('span', null, d, ' ', flag('SILENT', 'bad')), value: seen.get(d) || 0})).sort((a, b) => b.value - a.value);
    return hbars(rows, 'Events by source');
  }

  async byRisk(risk) {
    const top = (await risk).top.slice(0, 6);
    if (!top.length) return h('p', {class: 'empty'}, 'No entity with risk that you may see.');
    return hbars(top.map((x) => ({label: entityLink(x.entity), value: Number(x.score), text: num(x.score)})), 'Top entities by risk score');
  }

  /** The report in brief and in full. Closing hides it; opening it asks for the passkey every time. */
  reportSummary(text) {
    const lines = text.split('\n');
    const counts = lines.find((l) => l.startsWith('Alerts by priority'));
    const verdicts = lines.find((l) => l.startsWith('Verdicts:'));
    const top = lines[lines.findIndex((l) => l.startsWith('Top risky entities')) + 1];
    const risk = top && top.trim() ? 'Highest risk: ' + top.trim().replace(/\s+\S+ alert .*$/, '').replace(/\s+/g, ' ') : null;
    const full = h('pre', {class: 'report', tabindex: 0}, text);
    const close = h('button', {type: 'button', on: {click: () => fill(this.slots.report, this.reportPrompt())}}, 'Close');
    return h('div', null, note('Daily report for scenario day ' + whenSec(this.lab.time).slice(0, 10) + ', in brief:'),
      h('ul', {class: 'brief'}, [counts, verdicts, risk].filter(Boolean).map((l) => h('li', null, l))),
      full, h('div', {class: 'row'}, close));
  }

  /** The report is an export: it is never loaded by itself, only when the person opens it, and each opening asks for the passkey. */
  async report() {
    return this.reportPrompt();
  }

  reportPrompt() {
    const out = h('div');
    const open = h('button', {type: 'button', class: 'primary', on: {click: async () => {
      try {
        const r = await api.report('daily');
        fill(out, this.reportSummary(r.text));
      } catch (e) {
        if (e.status === 404 || e.status === 403) fill(out, note('Reports are for SOC leads. Sign in as a lead to see the daily report.'));
        else if (e.status !== 423) fill(out, unavailable(e));
      }
    }}}, 'Open the daily report');
    fill(out, note('The daily report asks for your passkey every time you open it.'), h('div', {class: 'row'}, open));
    return out;
  }
}
customElements.define('dw-overview', DwOverview);
