// Profile: who you are signed in as, and your own password, PIN, passkey and open sessions. Backup codes have a page of
// their own below it (#/profile/backup), which explains itself before asking for anything.
// Secrets are typed here and sent once; the server keeps only one-way hashes and the page keeps nothing.
import {api} from '../api.js';
import {h, fill, link, panel, cream, spot, note} from '../dom.js';
import {DwView} from '../view.js';
import {table} from '../table.js';
import {flag} from '../parts.js';
import {whenSec} from '../format.js';

const field = (id, text, auto) => {
  const input = h('input', {type: 'password', id, autocomplete: auto, required: true, spellcheck: false});
  return {input, nodes: [h('label', {for: id}, text), input]};
};

/** A small form: its fields are cleared whatever happens, so no secret stays on the page. */
function secretForm(fields, button, send) {
  const msg = h('p', {class: 'note', role: 'alert'});
  const go = h('button', {type: 'submit', class: 'primary'}, button);
  const form = h('form', {class: 'stack', method: 'dialog'}, fields.map((f) => f.nodes), msg, h('div', {class: 'row'}, go));
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    msg.textContent = '';
    go.disabled = true;
    try {
      const said = await send(fields.map((f) => f.input.value));
      msg.textContent = said || 'Done.';
    } catch (err) {
      msg.textContent = err.status === 429 ? 'Too many attempts. Try again in ' + (err.retryAfter || 5) + ' seconds.' : err.message;
    } finally {
      fields.forEach((f) => {
        f.input.value = '';
      });
      go.disabled = false;
    }
  });
  return form;
}

function same(a, b) {
  if (a !== b) throw new Error('The two new values do not match.');
}

const card = (l, n, d, href) => h(href ? 'a' : 'div', {class: 'card', href}, h('div', {class: 'n small'}, n), h('div', {class: 'l'}, l), h('div', {class: 'd'}, d));

class DwProfile extends DwView {
  async render() {
    if (this.ctx.args[0] === 'backup') await this.backupPage();
    else await this.draw();
  }

  async draw() {
    const p = await api.profile();
    const person = p.person;
    this.sessions = h('div');
    fill(this, this.title('Profile'),
      p.changeDue ? h('div', {class: 'must-change', role: 'alert'}, h('b', null, 'Your password or PIN has reached its ' + p.rotationDays + ' day limit. '),
        'Change both below. Nothing else opens until you do.') : null,
      h('div', {class: 'cards'},
        card('Signed in as', person.id, person.display),
        card('Role', person.roles.join(', ').toLowerCase(), 'Decides which views open'),
        card('Change by', whenSec(p.changeBy).slice(0, 10), 'Password and PIN last ' + p.rotationDays + ' days', '#/profile?at=password'),
        p.passkeyNeeded ? card('Passkey', p.passkeySet ? 'Set' : 'Not set', p.passkeySet ? 'Opens confidential views' : 'Needed for confidential views', '#/profile?at=passkey') : null,
        h('a', {class: 'card', href: '#/profile/backup'}, h('div', {class: 'n small'}, String(p.backupCodesLeft)), h('div', {class: 'l'}, 'Backup codes'), h('div', {class: 'd'}, 'One-use codes left'))),
      h('div', {class: 'grid two'}, this.passwordPanel(p), this.pinPanel(p), p.passkeyNeeded ? this.passkeyPanel(p) : null, this.codesLink(p)),
      spot('sessions', cream('Your open sessions', note('Signed in somewhere you do not recognise? End that session, then change your password.'), this.sessions)));
    await this.drawSessions();
  }

  passwordPanel(p) {
    const cur = field('pf-pw', 'Current password', 'current-password');
    const pin = field('pf-pin', 'Security key PIN', 'one-time-code');
    const next = field('pf-new', 'New password (12 characters or more)', 'new-password');
    const again = field('pf-again', 'New password again', 'new-password');
    return spot('password', panel('Change password', note('Last changed ' + whenSec(p.passwordChanged) + '. Your other sessions end when it changes.'),
      secretForm([cur, pin, next, again], 'Change password', async ([a, b, c, d]) => {
        same(c, d);
        await api.changePassword(a, b, c);
        await this.after('pin');
        return 'Password changed.';
      })));
  }

  pinPanel(p) {
    const pw = field('pn-pw', 'Password', 'current-password');
    const cur = field('pn-pin', 'Current PIN', 'one-time-code');
    const next = field('pn-new', 'New PIN (6 characters or more)', 'off');
    const again = field('pn-again', 'New PIN again', 'off');
    return spot('pin', panel('Change security PIN', note('Last changed ' + whenSec(p.pinChanged) + '. Your other sessions end when it changes.'),
      secretForm([pw, cur, next, again], 'Change PIN', async ([a, b, c, d]) => {
        same(c, d);
        await api.changePin(a, b, c);
        await this.after('password');
        return 'PIN changed.';
      })));
  }

  passkeyPanel(p) {
    const pw = field('pk-pw', 'Password', 'current-password');
    const pin = field('pk-pin', 'Security key PIN', 'one-time-code');
    const next = field('pk-new', 'New passkey (10 characters or more)', 'new-password');
    const again = field('pk-again', 'New passkey again', 'new-password');
    return spot('passkey', panel(p.passkeySet ? 'Replace passkey' : 'Set a passkey',
      note('Case details, entity risk, Hunt results, reports and audit records stay closed until you enter this, and lock again when you close them. It is not your password. Only a one-way hash of it is stored.'),
      secretForm([pw, pin, next, again], p.passkeySet ? 'Replace passkey' : 'Set passkey', async ([a, b, c, d]) => {
        same(c, d);
        await api.setPasskey(a, b, c);
        await this.after();
        return 'Passkey saved.';
      })));
  }

  codesLink(p) {
    return panel('Backup codes', note('Spare keys for the day your password or PIN is forgotten or stolen. ' + (p.backupCodesLeft ? 'You have ' + p.backupCodesLeft + ' left.' : 'You have none yet.')),
      link('#/profile/backup', p.backupCodesLeft ? 'Open backup codes' : 'Create backup codes', 'button-link'));
  }

  // ---- the backup codes page ---------------------------------------------------------------------------------------
  async backupPage() {
    const p = await api.profile();
    const place = h('div');
    fill(this, this.title('Backup codes', link('#/profile', 'Back to Profile', 'button-link')),
      h('div', {class: 'grid two'},
        panel('Why you need them', h('ul', {class: 'brief'},
          h('li', null, h('b', null, 'You forgot your password or PIN. '), 'One code lets you set both again without anyone\'s help.'),
          h('li', null, h('b', null, 'Someone stole them. '), 'One code replaces both and signs that person out everywhere.'))),
        panel('What the letters and numbers mean', note('Nothing. Each code is 15 random letters and digits, split into three groups of five so it is easy to copy. It holds nothing about you or your password. Its only job is that nobody can guess it. Look-alike characters such as 0, O, 1, I and L are left out, so you cannot misread one.'))),
      place);
    this.instructions(() => this.codesForm(place, p), () => this.shell.navigate('#/profile'));
  }

  /** Shown each time the page opens, before anything is asked for. */
  instructions(accept, decline) {
    const dlg = h('dialog', {'aria-labelledby': 'bc-title'});
    const done = (fn) => {
      dlg.close();
      dlg.remove();
      fn();
    };
    dlg.addEventListener('cancel', (e) => {
      e.preventDefault();
      done(decline);
    });
    dlg.append(h('h1', {id: 'bc-title'}, 'Before you make backup codes'),
      h('p', {class: 'note'}, 'A backup code is a spare key to your account, for the day you forget your password or PIN, or someone steals them.'),
      h('ol', {class: 'steps'},
        h('li', null, 'Making codes needs your password and PIN, so do it now, while you still have them.'),
        h('li', null, 'You get 10 codes, shown once only. Write them on paper before you leave the page.'),
        h('li', null, 'Keep the paper away from this computer. Never photograph the codes or send them in a chat or email.'),
        h('li', null, 'Each code works once. Making new codes cancels all your older ones.'),
        h('li', null, 'To use one, choose "Use a backup code" on the sign-in page.')),
      h('div', {class: 'row'}, h('button', {type: 'button', class: 'primary', on: {click: () => done(accept)}}, 'I understand, continue'),
        h('button', {type: 'button', on: {click: () => done(decline)}}, 'Not now')));
    document.body.append(dlg);
    dlg.showModal();
    this.cleanups.push(() => {
      if (dlg.isConnected) dlg.remove();
    });
  }

  codesForm(place, p) {
    const pw = field('bc-pw', 'Password', 'current-password');
    const pin = field('bc-pin', 'Security key PIN', 'one-time-code');
    const left = p.backupCodesLeft;
    fill(place, spot('make', panel(left ? 'Make new codes' : 'Make your codes',
      note(left ? 'You have ' + left + ' left. Making new codes cancels those ' + left + '.' : 'You have none yet.'),
      secretForm([pw, pin], left ? 'Make new codes' : 'Make codes', async ([a, b]) => {
        const r = await api.backupCodes(a, b);
        fill(place, panel('Your new codes', note('Write these down now. They are never shown again, and any older codes have stopped working.'),
          h('ul', {class: 'backup-codes'}, r.codes.map((c) => h('li', null, c))),
          h('div', {class: 'row'}, h('button', {type: 'button', class: 'primary', on: {click: () => this.shell.navigate('#/profile')}}, 'I have written them down'))));
        return 'New codes made.';
      }))));
    this.shell.spot('make');
  }

  /** Redraws the cards. A person who has finished the required change goes back to work; one who has not is shown what is left. */
  async after(next) {
    const was = this.shell.me && this.shell.me.changeDue;
    await this.shell.refreshMe();
    if (was && !this.shell.me.changeDue) {
      this.shell.navigate(this.shell.landing());
      return;
    }
    await this.draw();
    if (this.shell.me.changeDue && next) this.shell.spot(next);
  }

  async drawSessions() {
    const r = await api.sessions();
    fill(this.sessions, table([
      {head: 'Started', cell: (s) => whenSec(s.createdAt)},
      {head: 'Last seen', cell: (s) => whenSec(s.lastSeen)},
      {head: 'From', cell: (s) => s.source},
      {head: '', cell: (s) => (s.current ? flag('this session', 'ok') : h('button', {type: 'button', on: {click: async () => {
        await api.revokeSession(s.id);
        await this.drawSessions();
      }}}, 'End session'))},
    ], r.sessions).el);
  }
}
customElements.define('dw-profile', DwProfile);
