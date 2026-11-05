// The case workspace: timeline, evidence linked to audit sequence numbers, notes, assignment, SLA, and signing a verdict.
import {api} from '../api.js';
import {h, fill, link, panel, note, unavailable} from '../dom.js';
import {DwView} from '../view.js';
import {priority, flag, entityLink, entities, evidence, techniques, provenance, forgetCase} from '../parts.js';
import {when, whenSec, untilDeadline, num} from '../format.js';

const OUTCOMES = [
  ['TRUE_POSITIVE', 'True positive', 'The alert is right: act (the playbooks may revoke, deny or isolate).'],
  ['FALSE_POSITIVE', 'False positive', 'The alert is wrong: undo what was done on its account.'],
  ['BENIGN', 'Benign', 'Real, but expected: close without action.'],
];

class DwCase extends DwView {
  async render() {
    this.id = this.ctx.args[0];
    if (!this.id) {
      fill(this, note('No case chosen. Open one from the queue.'));
      return;
    }
    await this.load();
    this.onLive(['case.changed'], async () => {
      const keep = this.querySelector('textarea');
      if (keep && keep.value) return; // do not redraw under someone who is typing a note
      await this.load(true);
    }, 2000);
  }

  async load(quiet) {
    const opts = {background: quiet === true};
    const [detail, timeline] = await Promise.all([api.caseDetail(this.id, opts), api.timeline(this.id, opts)]);
    this.detail = detail;
    this.timeline = timeline;
    this.draw();
  }

  draw() {
    const d = this.detail;
    const c = d.case;
    const now = this.lab.time || c.openedAt;
    const mine = this.shell.me.person.id;
    fill(this,
      this.title('Case ' + c.id, priority(c.priority), flag(c.state.toLowerCase()),
        c.awaitingSecondAnalyst ? flag('needs a second analyst', 'warn') : null, c.holdsActions ? flag('actions held', 'warn') : null),
      h('div', {class: 'grid'},
        panel('Summary',
          h('table', {class: 'dense'}, h('tbody', null,
            row('Entity', entityLink(c.key)),
            row('Also involved', entities(d.entities.filter((e) => e.kind !== c.key.kind || e.id !== c.key.id))),
            row('Score', num(c.score)),
            row('Opened', when(c.openedAt)),
            row('SLA', h('span', null, when(c.deadline) + ' - ' + untilDeadline(c.deadline, now), ' ',
              c.breached ? flag('SLA BREACHED', 'bad') : flag('within SLA', 'ok'))),
            row('Acknowledged', c.acknowledgedAt ? when(c.acknowledgedAt) : 'not yet'),
            row('Assigned to', c.assignee || 'nobody')))),
        this.assignment(c, mine),
        d.links.length ? panel('Linked cases', h('ul', {class: 'plain'}, d.links.map((l) => h('li', null, link('#/case/' + encodeURIComponent(l), l))))) : null),
      this.result ? this.result : null,
      panel('Alerts and evidence', d.rankedAlerts.map((a) => this.alert(a))),
      h('div', {class: 'grid'}, this.timelinePanel(), this.notesPanel(c)));
  }

  assignment(c, mine) {
    const who = h('input', {type: 'text', id: 'assignee', placeholder: 'analyst id', 'aria-label': 'Assign to', spellcheck: false});
    const msg = h('p', {class: 'note', role: 'alert'});
    const go = async (assignee) => {
      msg.textContent = '';
      try {
        await api.assign(c.id, assignee);
        forgetCase(c.id);
        await this.load(true);
      } catch (e) {
        msg.textContent = 'Not assigned: ' + e.message;
      }
    };
    return panel('Assignment',
      h('div', {class: 'row'}, h('button', {type: 'button', class: 'primary', on: {click: () => go(mine)}}, 'Assign to me'),
        h('div', {class: 'grow'}, who), h('button', {type: 'button', on: {click: () => who.value.trim() && go(who.value.trim())}}, 'Assign')),
      msg, note('The SOC API refuses a case about the analyst themselves, and says "not found" for cases you may not see.'));
  }

  alert(a) {
    return h('div', {class: 'panel'},
      h('div', {class: 'row'}, priority(a.priority), h('b', null, a.rule), h('span', {class: 'muted'}, 'severity ' + a.severity.toLowerCase()),
        h('span', {class: 'muted'}, 'score ' + num(a.score)), h('span', {class: 'muted'}, a.count + ' event' + (a.count === 1 ? '' : 's')),
        a.actionable ? flag('the SOC may act on this', 'ok') : flag('watch only: no automatic action', 'warn'),
        h('span', {class: 'spacer'}), h('span', {class: 'muted'}, when(a.raisedAt))),
      h('p', null, a.summary),
      h('div', null, 'Entities: ', entities(a.entities)),
      h('div', null, 'Techniques: ', a.techniques.length ? techniques(a.techniques) : h('span', {class: 'muted'}, 'none mapped')),
      h('div', null, 'Evidence (audit sequence numbers): ', evidence(a.evidence)),
      h('h3', null, 'Why this rank'),
      a.reasons.length ? h('ul', {class: 'tight'}, a.reasons.map((r) => h('li', null, r))) : h('p', {class: 'muted'}, 'The ranker recorded no reason.'),
      h('div', {class: 'row'}, h('b', null, 'Decide:'), OUTCOMES.map(([o, label, help]) =>
        h('button', {type: 'button', title: help, on: {click: () => this.decide(a, o, label, help)}}, label))));
  }

  /** Confirm, ask for a fresh step-up if needed, sign (the server signs with the lab's analyst key) and show what happened. */
  decide(a, outcome, label, help) {
    const dlg = h('dialog', {'aria-labelledby': 'dv-title'});
    dlg.addEventListener('close', () => dlg.remove());
    const msg = h('p', {class: 'note', role: 'alert'});
    const go = h('button', {type: 'button', class: 'primary'}, 'Sign and submit');
    go.addEventListener('click', async () => {
      go.disabled = true;
      msg.textContent = '';
      try {
        let r;
        try {
          r = await api.verdict(a.id, outcome);
        } catch (e) {
          if (e.message !== 'step-up required') throw e;
          dlg.close();
          await this.shell.needStepUp();
          r = await api.verdict(a.id, outcome);
        }
        dlg.open && dlg.close();
        forgetCase(this.id);
        this.result = this.verdictResult(r, a, label);
        await this.load(true);
      } catch (e) {
        go.disabled = false;
        if (!dlg.open) document.body.append(dlg);
        if (!dlg.open) dlg.showModal();
        msg.textContent = 'Not signed: ' + e.message;
      }
    });
    dlg.append(h('h1', {id: 'dv-title'}, 'Sign verdict: ' + label),
      h('p', null, 'Alert ' + a.id + ' (' + a.rule + ')'), h('p', {class: 'note'}, help),
      h('p', {class: 'note'}, 'The verdict is signed with the lab\'s analyst key for you, held by the console server as a stand-in for your own hardware-bound key. It can make the playbooks act. You may be asked for a fresh second factor.'),
      msg, h('div', {class: 'row'}, go, h('button', {type: 'button', on: {click: () => dlg.close()}}, 'Cancel')));
    document.body.append(dlg);
    dlg.showModal();
  }

  verdictResult(r, a, label) {
    const res = r.result || {};
    const sig = r.signature || {};
    const bad = r.socStatus !== 200;
    return h('div', {class: 'result' + (bad ? ' bad' : ''), role: 'status'},
      h('b', null, bad ? 'The SOC API refused the verdict (' + r.socStatus + ').' : 'Verdict "' + label + '" recorded for alert ' + a.id + '.'),
      h('div', null, 'Result: ', res.status || res.error || '-', res.mode ? ' (' + String(res.mode).toLowerCase() + ' mode)' : '',
        typeof res.actions === 'number' ? ', ' + res.actions + ' action' + (res.actions === 1 ? '' : 's') : ''),
      res.message ? h('div', null, res.message) : null,
      res.isolated && res.isolated.length ? h('div', null, 'Isolating: ', res.isolated.map((d) => link('#/entity/device/' + encodeURIComponent(d), d)).flatMap((x, i) => [i ? ', ' : null, x])) : null,
      h('div', {class: 'muted'}, 'Signed by ' + (sig.signedBy || '?') + ' with key ' + (sig.keyId || '?') + ' at ' + whenSec(sig.signedAt) + '. ' + (sig.notice || '')));
  }

  timelinePanel() {
    const entries = this.timeline.entries;
    return panel('Timeline',
      entries.length ? h('ul', {class: 'timeline'}, entries.map((t) => h('li', null, h('span', {class: 'muted mono'}, when(t.at) + ' '),
        h('b', null, t.kind), ' ', h('span', {class: 'muted'}, t.actor), ' ', t.detail)))
        : h('p', {class: 'empty'}, 'No timeline entries.'),
      this.timeline.dropped ? note(this.timeline.dropped + ' older entries were dropped by the case book.') : null);
  }

  notesPanel(c) {
    const text = h('textarea', {rows: 3, maxlength: 2000, id: 'newnote', 'aria-label': 'New note', placeholder: 'Add a note (plain text, up to 2,000 characters)'});
    const msg = h('p', {class: 'note', role: 'alert'});
    const add = h('button', {type: 'button', class: 'primary'}, 'Add note');
    add.addEventListener('click', async () => {
      const t = text.value.trim();
      if (!t) return;
      add.disabled = true;
      try {
        await api.addNote(c.id, t);
        forgetCase(c.id);
        await this.load(true);
      } catch (e) {
        msg.textContent = 'Note not saved: ' + e.message;
        add.disabled = false;
      }
    });
    const notes = this.detail.notes;
    return panel('Notes',
      notes.length ? h('ul', {class: 'plain'}, notes.map((n) => h('li', {class: 'panel'}, h('div', {class: 'muted'}, n.author + ' - ' + when(n.at)),
        h('pre', null, n.text)))) : h('p', {class: 'empty'}, 'No notes yet.'),
      text, msg, h('div', {class: 'row'}, add));
  }
}

function row(label, value) {
  return h('tr', null, h('th', {scope: 'row'}, label), h('td', null, value));
}

customElements.define('dw-case', DwCase);
