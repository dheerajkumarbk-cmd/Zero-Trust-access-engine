// The audit explorer: page the chain, open one record, and verify the whole chain from the page.
import {api} from '../api.js';
import {h, fill, link, panel, note} from '../dom.js';
import {DwView} from '../view.js';
import {table} from '../table.js';
import {flag} from '../parts.js';
import {whenSec} from '../format.js';

const PAGE = 50;

class DwAudit extends DwView {
  async render() {
    const seq = this.ctx.args[0];
    this.source = this.ctx.args[1] === 'console' ? 'console' : 'lab';
    this.sources = ['lab'];
    try {
      this.sources = (await api.auditHead(this.source)).sources || ['lab'];
    } catch (e) {
      // the page below shows what is wrong
    }
    this.type = '';
    this.out = h('div');
    this.detail = h('div');
    fill(this, this.title('Audit explorer'), this.controls(), this.detail, this.out);
    if (seq) await this.record(Number(seq));
    await this.tail();
  }

  controls() {
    const src = h('select', {id: 'asource', 'aria-label': 'Which trail'},
      h('option', {value: 'lab'}, 'Simulated organisation (scenario time)'),
      h('option', {value: 'console'}, 'Console activity (real time, kept across restarts)'));
    src.value = this.source;
    src.addEventListener('change', () => {
      this.source = src.value;
      fill(this.detail);
      this.tail();
    });
    const type = h('input', {type: 'text', id: 'atype', placeholder: 'record type, e.g. CONSOLE_LOGIN', 'aria-label': 'Filter by type', spellcheck: false});
    const verifyOut = h('div', {role: 'status', 'aria-live': 'polite'});
    const form = h('form', {method: 'dialog'}, h('div', {class: 'row'}, this.sources.length > 1 ? h('div', null, src) : null, h('div', {class: 'grow'}, type),
      h('button', {type: 'submit'}, 'Filter'),
      h('button', {type: 'button', class: 'primary', on: {click: () => this.verify(verifyOut)}}, 'Verify the whole chain')));
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      this.type = type.value.trim();
      this.tail();
    });
    return panel(null, form, verifyOut,
      note('Every record is chained to the one before it with a keyed MAC. Verify recomputes every link from the first record and compares the end with the anchored head. Analysts see the details of the console\'s and the SOC API\'s own records; the rest show only who and when (details are for leads).'));
  }

  suffix() {
    return this.source === 'console' ? '/console' : '';
  }

  async verify(out) {
    fill(out, note('Verifying...'));
    try {
      const v = await api.auditVerify(this.source);
      fill(out, h('div', {class: 'result' + (v.intact ? '' : ' bad')},
        h('b', null, v.intact ? 'The chain is intact' : 'THE CHAIN IS BROKEN'), ' - ' + v.records + ' records checked. ' + v.reason,
        h('div', null, v.anchoredSeq === null ? 'No anchored head to compare with.' : 'Anchored head at record ' + v.anchoredSeq + ': ' + (v.anchorAgrees ? 'the chain agrees with it.' : 'THE CHAIN DOES NOT AGREE.')),
        v.firstBad >= 0 ? h('div', null, 'First bad record: ', link('#/audit/' + v.firstBad + this.suffix(), '#' + v.firstBad)) : null));
    } catch (e) {
      fill(out, h('div', {class: 'unavailable'}, 'Verification could not run (' + e.message + ').'));
    }
  }

  async tail() {
    const head = (await api.auditHead(this.source)).head;
    this.after = Math.max(0, head - (this.type ? 500 : PAGE));
    this.map = new Map();
    await this.loadPage();
  }

  async loadPage() {
    const page = await api.auditPage(this.after, PAGE, this.type, this.source);
    for (const e of page.entries) this.map.set(e.sequence, e);
    this.head = page.head;
    this.draw();
  }

  draw() {
    const entries = [...this.map.values()].sort((x, y) => y.sequence - x.sequence);
    const t = table([
      {head: '#', cls: 'num', cell: (e) => link('#/audit/' + e.sequence + this.suffix(), String(e.sequence))},
      {head: this.source === 'console' ? 'Time (real, UTC)' : 'Time (scenario)', cell: (e) => whenSec(e.at)},
      {head: 'Type', cell: (e) => e.type},
      {head: 'Actor', cell: (e) => e.actor},
      {head: 'Summary', cls: 'wrap mono', cell: (e) => e.summary},
    ], entries, {onOpen: (e) => this.shell.navigate('#/audit/' + e.sequence + this.suffix())});
    const earlier = h('button', {type: 'button', on: {click: async () => {
      this.after = Math.max(0, this.after - PAGE);
      await this.loadPage();
    }}}, 'Load earlier records');
    fill(this.out, note('Newest first. Chain head: record ' + this.head + '.' + (this.type ? ' Showing matches among the last 500 records and earlier ones you load.' : '')),
      entries.length ? t.el : h('p', {class: 'empty'}, 'No record matches.'),
      this.after > 0 ? h('div', {class: 'row'}, earlier) : null);
  }

  async record(seq) {
    try {
      const r = await api.auditRecord(seq, this.source);
      let pretty = r.payload;
      try {
        pretty = JSON.stringify(JSON.parse(r.payload), null, 2);
      } catch (e) {
        // not JSON (withheld text): show as it is
      }
      fill(this.detail, panel('Record ' + seq,
        h('table', {class: 'dense'}, h('tbody', null,
          tr('Type', r.entry.type), tr('Actor', r.entry.actor), tr(this.source === 'console' ? 'Time (real, UTC)' : 'Time (scenario)', whenSec(r.entry.at)),
          tr('MAC', h('code', null, r.entry.mac)), tr('Previous MAC', h('code', null, r.previousMac)))),
        h('h3', null, 'Payload'), h('pre', null, pretty),
        h('div', {class: 'row'}, link('#/audit', 'Close'), seq > 1 ? link('#/audit/' + (seq - 1) + this.suffix(), 'Previous record') : null, link('#/audit/' + (seq + 1) + this.suffix(), 'Next record'))));
    } catch (e) {
      fill(this.detail, panel('Record ' + seq, h('div', {class: 'unavailable'}, e.status === 404 ? 'There is no record ' + seq + '.' : 'The record is unavailable (' + e.message + ').')));
    }
  }
}

function tr(label, value) {
  return h('tr', null, h('th', {scope: 'row'}, label), h('td', null, value));
}

customElements.define('dw-audit', DwAudit);
