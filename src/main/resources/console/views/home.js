// Home: for a person whose role opens no SOC view. What their account can open, how safe it is, and what happened on it.
// Everything here is about the person themself; the server sends nothing about anyone else.
import {api} from '../api.js';
import {h, fill, link, panel, note} from '../dom.js';
import {DwView} from '../view.js';
import {table} from '../table.js';
import {whenSec} from '../format.js';

const WORDS = {
  CONSOLE_LOGIN: 'Signed in',
  CONSOLE_LOGIN_FAILED: 'A failed sign-in with your user name',
  CONSOLE_LOGOUT: 'Signed out',
  CONSOLE_RECOVERED: 'A backup code set a new password and PIN',
  CONSOLE_SESSION_REVOKED: 'Ended another session',
  'profile/password': 'Changed password',
  'profile/pin': 'Changed PIN',
  'profile/backup-codes': 'Made new backup codes',
};

class DwHome extends DwView {
  async render() {
    const [p, s, a] = await Promise.all([api.profile(), api.sessions(), api.activity()]);
    const now = new Date(this.lab.time).getTime();
    const days = Math.max(0, Math.ceil((new Date(p.changeBy).getTime() - now) / 86400000));
    const card = (href, n, l, d) => h('a', {class: 'card', href}, h('div', {class: 'n small'}, n), h('div', {class: 'l'}, l), h('div', {class: 'd'}, d));
    const todo = [];
    if (!p.backupCodesLeft) todo.push(h('li', null, h('b', null, 'You have no backup codes. '), 'Make some, so a forgotten or stolen password cannot lock you out. ', link('#/profile/backup', 'Create backup codes')));
    else if (p.backupCodesLeft <= 3) todo.push(h('li', null, h('b', null, 'Only ' + p.backupCodesLeft + ' backup codes left. '), link('#/profile/backup', 'Make new ones')));
    if (days <= 2) todo.push(h('li', null, h('b', null, 'Your password and PIN must change in ' + days + (days === 1 ? ' day. ' : ' days. ')), link('#/profile?at=password', 'Change them')));
    if (s.sessions.length > 1) todo.push(h('li', null, h('b', null, 'You are signed in ' + s.sessions.length + ' times. '), 'If one is not you, end it in ', link('#/profile?at=sessions', 'Profile'), '.'));
    fill(this, this.title('Home'),
      h('div', {class: 'cards'},
        card('#/profile', p.person.display, 'Signed in as', p.person.roles.join(', ').toLowerCase()),
        card('#/profile?at=password', whenSec(p.changeBy).slice(0, 10), 'Change by', 'Password and PIN last ' + p.rotationDays + ' days'),
        card('#/profile/backup', String(p.backupCodesLeft), 'Backup codes', 'One-use codes left'),
        card('#/profile?at=sessions', String(s.sessions.length), 'Open sessions', 'Places you are signed in')),
      panel('What needs doing', todo.length ? h('ul', {class: 'brief'}, todo) : h('p', {class: 'empty'}, 'Nothing. Your account is in good order.')),
      h('div', {class: 'grid two'},
        panel('What your account can open', h('ul', {class: 'brief'},
          h('li', null, link('#/m/admin', 'Why was I denied?'), ': the reason behind any request of yours that was refused.'),
          h('li', null, link('#/profile', 'Profile'), ': your password, PIN and open sessions.'),
          h('li', null, link('#/profile/backup', 'Backup codes'), ': your spare keys.')),
        note('Alerts, cases and reports are for the security team. Your account opens nothing confidential, so it needs no passkey.')),
        panel('Recent activity on your account', a.activity.length ? table([
          {head: 'When', cell: (x) => whenSec(x.at)},
          {head: 'What happened', cell: (x) => WORDS[x.what] || 'Account change'},
        ], a.activity.slice(0, 8)).el : h('p', {class: 'empty'}, 'Nothing recorded yet.'),
        h('p', {class: 'note'}, 'Not you? ', link('#/profile?at=password', 'Change your password'), ' straight away.'))));
  }
}
customElements.define('dw-home', DwHome);
