// Response: isolated devices and their acknowledgements, and what the playbooks have held back.
import {api} from '../api.js';
import {h, fill, link, cream, spot, note} from '../dom.js';
import {DwView} from '../view.js';
import {table} from '../table.js';
import {flag} from '../parts.js';
import {when, ago} from '../format.js';

class DwResponse extends DwView {
  async render() {
    await this.load();
    this.onLive(['isolation.changed', 'case.changed'], () => this.load(true), 1500);
  }

  async load(quiet) {
    const opts = {background: quiet === true};
    const [iso, metrics] = await Promise.all([api.isolations(opts), api.metrics(opts)]);
    const now = this.lab.time || new Date().toISOString();
    const r = metrics.response;
    const t = table([
      {head: 'Device', cell: (i) => link('#/entity/device/' + encodeURIComponent(i.device), i.device)},
      {head: 'State', cell: (i) => flag(i.state.toLowerCase(), i.state === 'ISOLATED' ? 'warn' : '')},
      {head: 'Since', cell: (i) => when(i.since) + ' (' + ago(i.since, now) + ')'},
      {head: 'Sensor acknowledged', cell: (i) => i.delivered ? flag('acknowledged', 'ok') : flag(i.overdue ? 'NO ACKNOWLEDGEMENT, OVERDUE' : 'waiting for the sensor', i.overdue ? 'bad' : 'warn')},
      {head: 'Cases', cell: (i) => h('span', null, i.cases.flatMap((c, k) => [k ? ', ' : null, link('#/case/' + encodeURIComponent(c), c)]))},
    ], iso.isolations, {onOpen: (i) => this.shell.navigate('#/entity/device/' + encodeURIComponent(i.device))});
    fill(this, this.title('Response'),
      cream('How to respond', h('ol', {class: 'steps'},
        h('li', null, 'Open the ', link('#/queue', 'Alert queue'), ' and open a case.'),
        h('li', null, 'Under Alerts and evidence, read Why this rank and check the evidence links.'),
        h('li', null, 'Under Decide, choose True positive, False positive or Benign, then sign it. You cannot decide a case about yourself.'),
        h('li', null, 'A true positive on an alert marked "the SOC may act on this" starts its playbook, which may isolate the device. Some actions wait for a second analyst.'),
        h('li', null, 'Come back here to watch the isolation and the sensor\'s acknowledgement.')),
        note('Alerts backed only by collected evidence never trigger a destructive action: the decision and any action stay with you.')),
      h('div', {class: 'cards'},
        card(metrics.isolation.isolated, 'devices isolated'), card(metrics.isolation.overdue, 'acknowledgements overdue'),
        card(r.awaitingSecondAnalyst, 'verdicts awaiting a second analyst'), card(r.heldBack, 'actions held back by guard rails'),
        card(r.refusedVerdicts, 'verdicts refused'), card(r.notifyFailures, 'notification failures')),
      spot('isolations', cream('Isolations', iso.isolations.length ? t.el : h('p', {class: 'empty'}, 'No isolation involves a case you may see.'),
        note('An isolation is only done on a signed verdict and takes effect when the device\'s sensor acknowledges it with its own signature; unacknowledged commands are sent again.'))),
      cream('Playbooks', h('p', null, 'Version ', h('code', null, r.playbookVersion), ' (sequence ' + r.playbookSequence + '). Whether the playbooks ran in watch-only or full mode is reported with each verdict, on the case page.')));
  }
}

function card(n, label) {
  return h('div', {class: 'card'}, h('div', {class: 'n'}, String(n)), h('div', {class: 'l'}, label));
}

customElements.define('dw-response', DwResponse);
