// Sign-in: the development identity provider asks for a password and then the PIN of the (simulated) security key.
import {api} from '../api.js';
import {h, fill} from '../dom.js';
import {startGlobe} from '../globe.js';

class DwLogin extends HTMLElement {
  connectedCallback() {
    const canvas = h('canvas', {'aria-hidden': 'true'});
    this.card = h('div', {class: 'login-card'});
    fill(this, h('div', {class: 'login-page'}, canvas,
      h('div', {class: 'login-top'}, h('span', {class: 'brand'}, 'Dwarpal')),
      h('div', {class: 'login-main'},
        h('div', {class: 'login-intro'}, h('span', {class: 'eyebrow'}, h('span', {class: 'live-dot'}), 'Zero Trust security operations'),
          h('h1', null, 'Every request ', h('em', null, 'stops at the gate.')),
          h('p', null, 'Nothing is trusted because of where it comes from. Each request is checked, decided and recorded.')),
        this.card),
      h('div', {class: 'login-note'}, 'A drawn view from orbit, not a camera feed. Day and night follow the real time.')));
    this.stopBackground = startGlobe(canvas);
    this.step1(this.ctx.message || '');
  }

  disconnectedCallback() {
    if (this.stopBackground) this.stopBackground();
  }

  step1(message) {
    const user = h('input', {type: 'text', id: 'li-user', autocomplete: 'username', required: true, spellcheck: false});
    const pw = h('input', {type: 'password', id: 'li-pw', autocomplete: 'current-password', required: true});
    const msg = h('p', {class: 'note', role: 'alert'}, message);
    const go = h('button', {type: 'submit', class: 'primary'}, 'Continue');
    const form = h('form', {class: 'stack', method: 'dialog'},
      h('label', {for: 'li-user'}, 'User'), user, h('label', {for: 'li-pw'}, 'Password'), pw, msg, h('div', {class: 'row'}, go,
        h('button', {type: 'button', class: 'link', on: {click: () => this.recover('')}}, 'Use a backup code')));
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      go.disabled = true;
      msg.textContent = '';
      try {
        const r = await api.login(user.value.trim(), pw.value);
        pw.value = '';
        this.step2(r.loginId, r.expiresInSeconds);
      } catch (err) {
        msg.textContent = this.explain(err);
        go.disabled = false;
      }
    });
    fill(this.card, h('div', null, h('h1', null, 'Sign in'),
      h('p', {class: 'note'}, 'Your password first, then the PIN of your security key.'),
      form));
    user.focus();
  }

  step2(loginId, seconds) {
    const pin = h('input', {type: 'password', id: 'li-pin', autocomplete: 'one-time-code', required: true, spellcheck: false});
    const msg = h('p', {class: 'note', role: 'alert'}, 'Enter the PIN within ' + seconds + ' seconds.');
    const go = h('button', {type: 'submit', class: 'primary'}, 'Sign in');
    const back = h('button', {type: 'button', on: {click: () => this.step1('')}}, 'Back');
    const form = h('form', {class: 'stack', method: 'dialog'},
      h('label', {for: 'li-pin'}, 'Security key PIN'), pin, msg, h('div', {class: 'row'}, go, back));
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      go.disabled = true;
      try {
        await api.verify(loginId, pin.value);
        this.ctx.onDone();
      } catch (err) {
        this.step1(this.explain(err));
      }
    });
    fill(this.card, h('div', null, h('h1', null, 'Second factor'),
      h('p', {class: 'note'}, 'Your password goes to the identity provider together with a signature from your (simulated) security key, which unlocks with this PIN.'),
      form));
    pin.focus();
  }

  /** A backup code replaces a stolen or forgotten password and PIN. First the code; only a right code asks for new ones. */
  recover(message) {
    const user = h('input', {type: 'text', id: 'rc-user', autocomplete: 'username', required: true, spellcheck: false});
    const code = h('input', {type: 'text', id: 'rc-code', autocomplete: 'off', required: true, spellcheck: false});
    const msg = h('p', {class: 'note', role: 'alert'}, message || '');
    const go = h('button', {type: 'submit', class: 'primary'}, 'Check code');
    const back = h('button', {type: 'button', on: {click: () => this.step1('')}}, 'Back');
    const form = h('form', {class: 'stack', method: 'dialog'}, h('label', {for: 'rc-user'}, 'User'), user,
      h('label', {for: 'rc-code'}, 'Backup code'), code, msg, h('div', {class: 'row'}, go, back));
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      go.disabled = true;
      msg.textContent = '';
      try {
        const r = await api.recoverCode(user.value.trim(), code.value.trim());
        this.newSecrets(r.ticket, user.value.trim(), r.expiresInSeconds);
      } catch (err) {
        msg.textContent = err.status === 401 ? 'That user and code do not match.' : this.explain(err);
        code.value = '';
        go.disabled = false;
      }
    });
    fill(this.card, h('div', null, h('h1', null, 'Use a backup code'),
      h('p', {class: 'note'}, 'Enter your user and one of your codes. The next step sets a new password and PIN.'), form));
    user.focus();
  }

  newSecrets(ticket, who, seconds) {
    const pw = h('input', {type: 'password', id: 'rc-pw', autocomplete: 'new-password', required: true});
    const pin = h('input', {type: 'password', id: 'rc-pin', autocomplete: 'off', required: true});
    const msg = h('p', {class: 'note', role: 'alert'});
    const go = h('button', {type: 'submit', class: 'primary'}, 'Set new password and PIN');
    const form = h('form', {class: 'stack', method: 'dialog'}, h('label', {for: 'rc-pw'}, 'New password (12 characters or more)'), pw,
      h('label', {for: 'rc-pin'}, 'New PIN (6 characters or more)'), pin, msg, h('div', {class: 'row'}, go));
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      go.disabled = true;
      msg.textContent = '';
      try {
        await api.recover(ticket, pw.value, pin.value);
        this.step1('Done. Sign in with your new password and PIN.');
      } catch (err) {
        if (err.status === 401) {
          this.recover('That step ran out of time. Enter your code again.');
          return;
        }
        msg.textContent = err.status === 400 ? err.message : this.explain(err);
        pw.value = '';
        pin.value = '';
        go.disabled = false;
      }
    });
    fill(this.card, h('div', null, h('h1', null, 'Choose a new password and PIN'),
      h('p', {class: 'note'}, 'Code accepted for ' + who + '. Finish within ' + Math.round(seconds / 60) + ' minutes. Everyone using the old password and PIN is signed out, and this code stops working.'), form));
    pw.focus();
  }

  explain(err) {
    if (err.status === 429) return 'Too many attempts. Try again in ' + (err.retryAfter || 5) + ' seconds.';
    if (err.status === 401) return 'Sign-in failed. Check the user, the password and the PIN.';
    return 'Sign-in is unavailable (' + err.message + ').';
  }
}
customElements.define('dw-login', DwLogin);
