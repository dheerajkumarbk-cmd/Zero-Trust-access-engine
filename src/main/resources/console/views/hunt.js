// Hunt: the SIEM search language over the event trail. Results are a table; "| count by" gives a bar list.
import {api} from '../api.js';
import {h, fill, link, panel, note} from '../dom.js';
import {DwView} from '../view.js';
import {table} from '../table.js';
import {entityLink, provenance} from '../parts.js';
import {whenSec} from '../format.js';
import {getPref, setPref} from '../prefs.js';

const WINDOWS = [['1 hour', 3600], ['6 hours', 6 * 3600], ['24 hours', 86400], ['3 days', 3 * 86400], ['7 days', 7 * 86400], ['31 days', 31 * 86400]];
const EXAMPLES = [
  ['Firewall denials', 'dataset = firewall and action = network.flow and outcome = FAILURE'],
  ['Everything from one address', 'ip = 185.220.101.4'],
  ['Refused access by user', 'action = access.decision and outcome = FAILURE | count by subject'],
  ['Events by dataset', '* | count by dataset'],
  ['Endpoint events on a device', 'dataset = endpoint and device = laptop-1'],
  ['Outcomes by action', 'dataset = firewall | count by action, outcome'],
];

class DwHunt extends DwView {
  async render() {
    const q0 = this.ctx.params.get('q') || '';
    const input = h('input', {type: 'text', id: 'hq', 'data-hunt-input': 'yes', value: q0.slice(0, 2000), spellcheck: false, autocomplete: 'off',
      'aria-label': 'Search query', placeholder: 'e.g. dataset = firewall and outcome = FAILURE | count by action'});
    const win = h('select', {id: 'hw', 'aria-label': 'Time window'}, WINDOWS.map(([l, s], i) => h('option', {value: s, selected: i === 2}, 'last ' + l)));
    const limit = h('select', {id: 'hl', 'aria-label': 'Result limit'}, [50, 100, 500, 1000].map((n, i) => h('option', {value: n, selected: i === 1}, 'show ' + n)));
    const out = h('div', {'aria-live': 'polite'});
    const run = async () => {
      const q = input.value.trim();
      if (!q) {
        fill(out, note('Type a query first. Examples are on the right.'));
        return;
      }
      fill(out, note('Searching...'));
      const to = new Date(new Date(this.lab.time).getTime() + 1000);
      const from = new Date(to.getTime() - Number(win.value) * 1000);
      try {
        if (/\|\s*count\s+by\b/i.test(q)) fill(out, this.showCounts(await api.counts(q, from.toISOString(), to.toISOString()), q));
        else fill(out, this.showEvents(await api.search(q, from.toISOString(), to.toISOString(), Number(limit.value))));
      } catch (e) {
        fill(out, h('div', {class: 'unavailable', role: 'alert'}, h('b', null, 'Search failed. '), e.message));
      }
    };
    const form = h('form', {method: 'dialog'}, h('div', {class: 'row'}, h('div', {class: 'grow'}, input), win, limit,
      h('button', {type: 'submit', class: 'primary'}, 'Run'),
      h('button', {type: 'button', title: 'Keep this query in this browser', on: {click: () => this.save(input.value)}}, 'Save query')));
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      run();
    });
    this.saved = h('div');
    fill(this, this.title('Hunt'), h('div', {class: 'grid'},
      panel('Search', form, out),
      h('div', null, panel('Examples', h('ul', {class: 'plain'}, EXAMPLES.map(([l, q]) =>
        h('li', null, h('button', {type: 'button', title: q, on: {click: () => { input.value = q; input.focus(); }}}, l))))),
      panel('Saved queries', this.saved), this.help())));
    this.input = input;
    this.drawSaved(input);
    if (q0) run();
  }

  save(q) {
    const t = q.trim();
    if (!t) return;
    const list = getPref('savedQueries', []).filter((x) => x !== t);
    list.unshift(t);
    setPref('savedQueries', list.slice(0, 12));
    this.drawSaved(this.input);
  }

  drawSaved(input) {
    const list = getPref('savedQueries', []);
    fill(this.saved, list.length ? h('ul', {class: 'plain'}, list.map((q) => h('li', null,
      h('button', {type: 'button', on: {click: () => { input.value = q; input.focus(); }}}, 'Use'), ' ', h('code', null, q))))
      : note('Nothing saved. Queries are kept only in this browser.'));
  }

  help() {
    return panel('Query language',
      h('pre', null, 'query := expr [ | count by field {, field} ]\nexpr  := a and b | a or b | not a | ( a ) | *\ncomp  := field op value | field in (v, v)\nop    := =  !=  >  >=  <  <=  ~ (contains)'),
      note('Fields: id, dataset, category, action, outcome, provenance, at, subject, device, ip, session, resource, or any event field (f.name). Values: bare words or "quoted strings". The same language the correlation rules use.'));
  }

  showEvents(r) {
    if (r.problem) return h('div', {class: 'unavailable', role: 'alert'}, h('b', null, 'The query was refused: '), r.problem);
    const t = table([
      {head: 'Time', cell: (e) => whenSec(e.at)},
      {head: 'Dataset', cell: (e) => e.dataset},
      {head: 'Action', cell: (e) => e.action},
      {head: 'Outcome', cell: (e) => e.outcome.toLowerCase()},
      {head: 'Evidence class', cell: (e) => provenance(e.provenance)},
      {head: 'Entities', cls: 'wrap', cell: (e) => h('span', null, e.entities.flatMap((x, i) => [i ? ' ' : null, entityLink(x)]))},
      {head: 'Fields', cls: 'wrap mono', cell: (e) => h('details', null, h('summary', null, Object.keys(e.fields).length + ' fields'),
        h('pre', null, Object.entries(e.fields).map(([k, v]) => k + ' = ' + v).join('\n')))},
      {head: 'Audit #', cls: 'num', cell: (e) => link('#/audit/' + e.sequence, String(e.sequence))},
    ], r.events, {});
    return h('div', null, note(r.events.length + ' shown of ' + r.matched + ' matched' + (r.truncated ? ' (more exist: narrow the window or the query)' : '') + '.'),
      r.events.length ? t.el : h('p', {class: 'empty'}, 'No event matched.'));
  }

  showCounts(r, q) {
    if (r.problem) return h('div', {class: 'unavailable', role: 'alert'}, h('b', null, 'The query was refused: '), r.problem);
    const max = Math.max(1, ...r.groups.map((g) => g.count));
    const fields = q.split(/count\s+by/i)[1].split(',').map((s) => s.trim());
    const t = table([
      ...fields.map((f, i) => ({head: f, cell: (g) => g.values[i] === undefined ? '' : g.values[i]})),
      {head: 'Count', cls: 'num', cell: (g) => String(g.count)},
      {head: 'Share', cell: (g) => h('meter', {min: 0, max, value: g.count, 'aria-label': g.count + ' events'}, String(g.count))},
    ], r.groups, {});
    return h('div', null, note(r.groups.length + ' groups over ' + r.matched + ' events you may see' + (r.truncated ? ' (truncated)' : '') + '.'),
      r.groups.length ? t.el : h('p', {class: 'empty'}, 'No event matched.'));
  }
}
customElements.define('dw-hunt', DwHunt);
