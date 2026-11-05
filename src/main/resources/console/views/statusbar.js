// The live status bar: scenario time and speed, the clock's state, the live feed, console health, step-up freshness.
import {h, fill} from '../dom.js';
import {whenSec, span} from '../format.js';

class DwStatusbar extends HTMLElement {
  connectedCallback() {
    this.classList.add('statusbar');
    this.setAttribute('role', 'status');
    this.setAttribute('aria-live', 'off');
    const shell = this.ctx.shell;
    const redraw = () => this.draw();
    shell.events.addEventListener('live', redraw);
    this.timer = setInterval(redraw, 1000);
    this.stop = () => {
      clearInterval(this.timer);
      shell.events.removeEventListener('live', redraw);
    };
    this.draw();
  }

  disconnectedCallback() {
    if (this.stop) this.stop();
  }

  draw() {
    const {lab, me} = this.ctx.shell;
    const feed = lab.feed || 'connecting';
    const state = lab.state || 'UNKNOWN';
    const stateKind = state === 'RUNNING' ? 'live' : state === 'FAILED' ? 'bad' : 'warn';
    const stepUntil = me && me.stepUpUntil ? new Date(me.stepUpUntil).getTime() - Date.now() : -1;
    const auditFail = lab.console ? lab.console.auditFailures : 0;
    fill(this,
      h('span', null, h('span', {class: 'dot ' + (feed === 'live' ? 'live' : 'warn')}), 'feed ', h('b', null, feed)),
      h('span', null, h('span', {class: 'dot ' + stateKind}), 'scenario ', h('b', null, state.toLowerCase()),
        lab.speed ? ' at ' + Number(lab.speed) + 'x' : ''),
      h('span', null, 'scenario time ', h('b', null, lab.time ? whenSec(lab.time) : '-')),
      lab.counts ? h('span', null, 'alerts raised ', h('b', null, lab.counts.alertsRaised)) : null,
      lab.failure ? h('span', null, h('span', {class: 'dot bad'}), h('b', null, 'clock stopped: ' + lab.failure)) : null,
      auditFail > 0 ? h('span', null, h('span', {class: 'dot bad'}), h('b', null, 'AUDIT WRITE FAILURES: ' + auditFail)) : null,
      h('span', {class: 'spacer'}),
      h('span', null, 'step-up ', h('b', null, stepUntil > 0 ? 'fresh for ' + span(stepUntil) : 'needed for privileged actions')),
      me ? h('span', null, 'session ends (idle) ', h('b', null, whenSec(me.idleExpiresAt))) : null);
  }
}
customElements.define('dw-statusbar', DwStatusbar);
