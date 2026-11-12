// The alert queue (open cases ranked P1 to P4) and the case list (all cases). Every row says why it has its rank.
import {api} from '../api.js';
import {h, fill, link, panel, spot, note} from '../dom.js';
import {DwView} from '../view.js';
import {table} from '../table.js';
import {priority, flag, entityLink, caseDetail, reasons, pool} from '../parts.js';
import {when, untilDeadline, num} from '../format.js';

const ORDER = {P1: 1, P2: 2, P3: 3, P4: 4};
const AUTO_WHY = 15;

export class DwQueue extends DwView {
  all = false;

  async render() {
    const data = this.all ? await api.cases() : await api.queue();
    const rows = (this.all ? data.cases : data.queue).slice().sort((a, b) =>
      (ORDER[a.priority] - ORDER[b.priority]) || (b.score - a.score) || a.openedAt.localeCompare(b.openedAt));
    this.rows = rows;
    this.filter = this.filter || '';
    this.draw();
    this.onLive(['case.changed', 'alert.new'], async () => {
      const fresh = this.all ? await api.cases({background: true}) : await api.queue({background: true});
      this.rows = (this.all ? fresh.cases : fresh.queue).slice().sort((a, b) =>
        (ORDER[a.priority] - ORDER[b.priority]) || (b.score - a.score) || a.openedAt.localeCompare(b.openedAt));
      this.draw();
    }, 1500);
  }

  draw() {
    const needle = this.filter.toLowerCase();
    const shown = this.rows.filter((r) => !needle || (r.key.kind + ':' + r.key.id + ' ' + r.id + ' ' + (r.assignee || '') +
      ' ' + r.priority + ' ' + r.state).toLowerCase().includes(needle));
    const counts = {P1: 0, P2: 0, P3: 0, P4: 0};
    this.rows.forEach((r) => counts[r.priority]++);
    const search = h('input', {type: 'text', id: 'qfilter', placeholder: 'Filter: entity, assignee, state, priority', value: this.filter,
      'aria-label': 'Filter the queue', spellcheck: false});
    search.addEventListener('input', () => {
      this.filter = search.value;
      this.draw();
      const again = document.getElementById('qfilter');
      if (again) {
        again.focus();
        again.setSelectionRange(again.value.length, again.value.length);
      }
    });
    const t = table([
      {head: 'Priority', cell: (r) => priority(r.priority)},
      {head: 'Entity', cell: (r) => h('span', null, entityLink(r.key))},
      {head: 'Score', cls: 'num', cell: (r) => num(r.score)},
      {head: 'State', cell: (r) => h('span', null, r.state.toLowerCase(), ' ',
        r.awaitingSecondAnalyst ? flag('needs 2nd analyst', 'warn') : null, r.holdsActions ? flag('actions held', 'warn') : null)},
      {head: 'SLA', cell: (r) => h('span', null, untilDeadline(r.deadline, this.lab.time || r.openedAt),
        r.breached ? ' ' : null, r.breached ? flag('SLA BREACHED', 'bad') : null)},
      {head: 'Assigned', cell: (r) => r.assignee || h('span', {class: 'muted'}, 'unassigned')},
      {head: 'Alerts', cls: 'num', cell: (r) => String(r.alerts)},
      {head: 'Why this rank', cls: 'wrap', cell: (r) => this.why(r)},
      {head: 'Opened', cell: (r) => when(r.openedAt)},
      {head: '', cell: (r) => link('#/case/' + encodeURIComponent(r.id), 'Open')},
    ], shown, {
      onOpen: (r) => this.shell.navigate('#/case/' + encodeURIComponent(r.id)),
      onSelect: (r) => this.loadWhy(r),
    });
    this.tbl = t;
    fill(this,
      this.title(this.all ? 'Cases' : 'Alert queue', h('span', {class: 'muted'}, 'P1 ' + counts.P1 + ' / P2 ' + counts.P2 + ' / P3 ' + counts.P3 + ' / P4 ' + counts.P4)),
      note(this.all ? 'Every case, open and closed: use this to look back. ' + this.rows.filter((r) => r.state.toLowerCase() !== 'open').length + ' of ' + this.rows.length + ' are no longer open; until a case is closed, this list matches the Alert queue.'
        : 'The work to do now: open cases only. A closed case leaves this list and stays in Cases.'),
      note('Ranked by priority, then score. Keys: j / k move, Enter opens. Reasons load for the first ' + AUTO_WHY + ' rows and for the row you select (each case read is recorded in the audit trail).'),
      h('div', {class: 'row'}, h('div', {class: 'grow'}, search)),
      shown.length ? spot('queue', t.el) : h('p', {class: 'empty'}, this.rows.length ? 'No case matches the filter.'
        : this.all ? 'The SOC API reports no cases you may see.' : 'The SOC API reports an empty queue for you.'));
    this.fillWhy(shown, t);
  }

  why(r) {
    const cached = this.whyCache && this.whyCache.get(r.id);
    if (!cached) return h('span', {class: 'why', 'data-why': r.id}, 'select the row to see why');
    return this.whyNode(cached, r.id);
  }

  whyNode(list, id) {
    if (!list.length) return h('span', {class: 'why', 'data-why': id}, 'no reason recorded');
    return h('ul', {class: 'plain why', 'data-why': id}, list.slice(0, 3).map((x) => h('li', null, x)));
  }

  async fillWhy(shown, t) {
    this.whyCache = this.whyCache || new Map();
    const first = shown.filter((r) => !this.whyCache.has(r.id)).slice(0, AUTO_WHY);
    await pool(first, 3, (r) => this.loadWhy(r, true));
  }

  async loadWhy(r, quiet) {
    this.whyCache = this.whyCache || new Map();
    if (!this.whyCache.has(r.id)) {
      const d = await caseDetail(r, {background: quiet === true});
      this.whyCache.set(r.id, reasons(d.rankedAlerts));
    }
    const cell = this.querySelector('[data-why="' + CSS.escape(r.id) + '"]');
    if (cell) cell.replaceWith(this.whyNode(this.whyCache.get(r.id), r.id));
  }
}

class DwQueueEl extends DwQueue {}
class DwCases extends DwQueue {
  all = true;
}
customElements.define('dw-queue', DwQueueEl);
customElements.define('dw-cases', DwCases);
