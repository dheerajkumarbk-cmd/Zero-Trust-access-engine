// Scans: one button that checks the evidence the console already holds, then says what is clean and what needs a look.
// A scan reads only: it changes nothing, and each finding links to where it can be followed up.
import {api} from '../api.js';
import {h, fill, link, panel, note} from '../dom.js';
import {DwView} from '../view.js';
import {table} from '../table.js';
import {flag} from '../parts.js';
import {num, count, whenSec} from '../format.js';
import {getPref, setPref} from '../prefs.js';
import {toast} from '../toast.js';

const WINDOWS = [['last hour', 3600], ['last 24 hours', 86400], ['last 7 days', 7 * 86400]];
const QUIET_HOURS = 2;
const REFUSED_LIMIT = 5;
const DENY_LIMIT = 20;
const KEPT = 6;
const LABEL = {clean: ['clean', 'ok'], review: ['review', 'warn'], problem: ['problem', 'bad'], failed: ['could not run', 'bad']};

const hunt = (q) => '#/hunt?q=' + encodeURIComponent(q);
const top = (groups, n = 3) => groups.slice().sort((a, b) => b.count - a.count).slice(0, n).map((g) => g.values[0] + ' (' + count(g.count) + ')').join(', ');

class DwScans extends DwView {
  async render() {
    this.bar = h('i', {class: 'v0'});
    this.step = h('p', {class: 'note'}, 'Nothing has been run yet on this page.');
    this.out = h('div', {'aria-live': 'polite'});
    this.past = h('div');
    this.window = h('select', {'aria-label': 'What to scan'}, WINDOWS.map(([l, s], i) => h('option', {value: s, selected: i === 1}, l)));
    this.go = h('button', {type: 'button', class: 'primary', on: {click: () => this.run()}}, 'Run full scan');
    fill(this, this.title('Scans'),
      h('div', {class: 'grid'},
        panel('Run a scan', note('Checks the audit trail, the sensors, refused access, the firewall, unreadable logs, cases and risk. It only reads, so it is safe at any time.'),
          h('div', {class: 'row'}, this.go, this.window), h('div', {class: 'scan-bar'}, this.bar), this.step),
        panel('Earlier scans', this.past, note('Kept in this browser only.'),
          h('div', {class: 'row'}, link('#/m/lab', 'Launch an attack scenario, then scan again')))),
      panel('Results', this.out));
    fill(this.out, note('Press Run full scan to see results here.'));
    this.drawPast();
  }

  checks() {
    const metrics = api.metrics();
    return [
      {name: 'Audit chain', what: 'No record was changed or removed', run: () => this.auditChain()},
      {name: 'Log sources', what: 'Firewall, endpoint and cloud are all reporting', run: () => this.sources()},
      {name: 'Endpoint sensors', what: 'No sensor has gone quiet', run: () => this.sensors()},
      {name: 'Refused access', what: 'No address keeps being refused by the access engine', run: () => this.refused()},
      {name: 'Firewall denials', what: 'No address keeps being blocked by the firewall', run: () => this.denials()},
      {name: 'Unreadable log lines', what: 'Every log line could be read', run: () => this.unreadable()},
      {name: 'Response deadlines', what: 'No case is past its deadline or unowned', run: () => this.backlog(metrics)},
      {name: 'High-risk entities', what: 'No person or device is at high risk', run: () => this.risk()},
      {name: 'Device isolation', what: 'Every isolation was confirmed by its sensor', run: () => this.isolation(metrics)},
    ];
  }

  counts(query, seconds) {
    const to = new Date(new Date(this.lab.time).getTime() + 1000);
    const from = new Date(to.getTime() - (seconds === undefined ? this.seconds : seconds) * 1000);
    return api.counts(query, from.toISOString(), to.toISOString()).then((r) => {
      if (r.problem) throw new Error(r.problem);
      return r;
    });
  }

  async auditChain() {
    const v = await api.auditVerify();
    if (!v.intact) return {state: 'problem', found: 'The chain is broken: ' + v.reason, href: '#/audit'};
    if (v.anchoredSeq !== null && !v.anchorAgrees) return {state: 'problem', found: 'The chain does not agree with its anchored head.', href: '#/audit'};
    return {state: 'clean', found: count(v.records) + ' records checked, all linked.', href: '#/audit'};
  }

  async sources() {
    const r = await this.counts('* | count by dataset');
    const seen = new Set(r.groups.map((g) => g.values[0]));
    const silent = ['firewall', 'endpoint', 'cloud'].filter((d) => !seen.has(d));
    return silent.length ? {state: 'problem', found: 'Silent: ' + silent.join(', ') + '. Treat silence as a finding.', href: hunt('* | count by dataset')}
      : {state: 'clean', found: count(r.matched) + ' events from ' + seen.size + ' sources.', href: hunt('* | count by dataset')};
  }

  async sensors() {
    const beats = 'action = sensor.heartbeat | count by device';
    // every device that did anything today is expected to be alive, so a sensor that stopped early is not missed
    const [seen, recent] = await Promise.all([this.counts('dataset = endpoint | count by device', 86400), this.counts(beats, QUIET_HOURS * 3600)]);
    if (!recent.groups.length) return {state: 'clean', found: 'No heartbeat has been due yet, so there is nothing to compare.', href: hunt(beats)};
    const live = new Set(recent.groups.map((g) => g.values[0]));
    const quiet = seen.groups.map((g) => g.values[0]).filter((d) => d !== '-' && !live.has(d));
    return quiet.length ? {state: 'review', found: quiet.length + ' quiet for ' + QUIET_HOURS + ' hours: ' + quiet.slice(0, 4).join(', '), href: hunt(beats)}
      : {state: 'clean', found: live.size + ' sensors, all heard from in the last ' + QUIET_HOURS + ' hours.', href: hunt(beats)};
  }

  async refused() {
    const q = 'action = access.decision and outcome = FAILURE | count by ip';
    const r = await this.counts(q);
    const many = r.groups.filter((g) => g.values[0] !== '-' && g.count >= REFUSED_LIMIT);
    return many.length ? {state: 'review', found: many.length + (many.length === 1 ? ' address' : ' addresses') + ' refused ' + REFUSED_LIMIT + ' or more times: ' + top(many), href: hunt(q)}
      : {state: 'clean', found: count(r.matched) + (r.matched === 1 ? ' refused request.' : ' refused requests, none concentrated on one address.'), href: hunt(q)};
  }

  async denials() {
    const q = 'dataset = firewall and action = network.flow and outcome = FAILURE | count by ip';
    const r = await this.counts(q);
    const many = r.groups.filter((g) => g.count >= DENY_LIMIT);
    return many.length ? {state: 'review', found: many.length + ' addresses refused ' + DENY_LIMIT + ' or more times: ' + top(many), href: hunt(q)}
      : {state: 'clean', found: count(r.matched) + (r.matched === 1 ? ' denial.' : ' denials, none concentrated on one address.'), href: hunt(q)};
  }

  async unreadable() {
    const q = 'action = parse.failure | count by dataset';
    const r = await this.counts(q);
    return r.matched > 0 ? {state: 'review', found: count(r.matched) + ' lines could not be read: ' + top(r.groups) + '.', href: hunt(q)}
      : {state: 'clean', found: 'Every log line was read.', href: hunt(q)};
  }

  async backlog(metrics) {
    const m = await metrics;
    const late = m.cases.breached;
    const free = m.cases.unassigned;
    if (late > 0) return {state: 'problem', found: late + ' past their deadline, ' + free + ' with no owner.', href: '#/queue'};
    return free > 0 ? {state: 'review', found: free + ' cases with no owner.', href: '#/queue'}
      : {state: 'clean', found: 'Every open case is owned and inside its deadline.', href: '#/queue'};
  }

  async risk() {
    const high = (await api.riskTop()).top.filter((x) => x.level === 'HIGH' || x.level === 'CRITICAL');
    return high.length ? {state: 'review', found: high.length + ' at high risk, led by ' + high[0].entity.kind + ':' + high[0].entity.id + ' (' + num(high[0].score) + ').', href: '#/entity'}
      : {state: 'clean', found: 'Nothing above medium risk.', href: '#/entity'};
  }

  async isolation(metrics) {
    const i = (await metrics).isolation;
    return i.overdue > 0 ? {state: 'problem', found: i.overdue + ' isolations not confirmed in time.', href: '#/response'}
      : {state: 'clean', found: i.isolated + ' devices isolated, none overdue.', href: '#/response'};
  }

  async run() {
    this.seconds = Number(this.window.value);
    this.go.disabled = true;
    const checks = this.checks();
    const rows = [];
    for (const [i, c] of checks.entries()) {
      this.step.textContent = 'Checking ' + c.name.toLowerCase() + '... (' + (i + 1) + ' of ' + checks.length + ')';
      this.bar.className = 'v' + Math.round((i / checks.length) * 20) * 5;
      try {
        rows.push({...c, ...(await c.run())});
      } catch (e) {
        rows.push({...c, state: 'failed', found: e.message, href: null});
      }
    }
    this.bar.className = 'v100';
    this.go.disabled = false;
    this.show(rows);
  }

  show(rows) {
    const clean = rows.filter((r) => r.state === 'clean').length;
    const review = rows.filter((r) => r.state === 'review').length;
    const bad = rows.length - clean - review;
    const line = bad ? bad + ' need action, ' + review + ' to review, ' + clean + ' clean.'
      : review ? review + ' to review, ' + clean + ' clean.' : 'All ' + clean + ' checks are clean.';
    this.step.textContent = 'Finished at ' + whenSec(this.lab.time) + ' scenario time.';
    toast('Scan finished: ' + line, bad ? 'bad' : 'ok');
    fill(this.out, h('p', {class: 'scan-sum'}, line), table([
      {head: 'Result', cell: (r) => flag(...LABEL[r.state])},
      {head: 'Check', cell: (r) => h('span', null, h('b', null, r.name), h('div', {class: 'why'}, r.what))},
      {head: 'Found', cls: 'wrap', cell: (r) => r.found},
      {head: '', cell: (r) => (r.href ? link(r.href, 'Look into it') : null)},
    ], rows).el);
    const past = getPref('scans', []);
    past.unshift({at: this.lab.time, line, wide: this.window.selectedOptions[0].textContent});
    setPref('scans', past.slice(0, KEPT));
    this.drawPast();
  }

  drawPast() {
    const past = getPref('scans', []);
    fill(this.past, past.length ? h('ul', {class: 'plain'}, past.map((p) => h('li', null, h('b', null, whenSec(p.at)), ' ', p.wide + ': ' + p.line)))
      : note('No scan has been run in this browser yet.'));
  }
}
customElements.define('dw-scans', DwScans);
