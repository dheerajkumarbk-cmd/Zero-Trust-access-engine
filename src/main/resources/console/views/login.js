// Sign-in: the development identity provider asks for a password and then the PIN of the (simulated) security key.
import {api} from '../api.js';
import {h, fill} from '../dom.js';

class DwLogin extends HTMLElement {
  connectedCallback() {
    this.step1(this.ctx.message || '');
  }

  step1(message) {
    const user = h('input', {type: 'text', id: 'li-user', autocomplete: 'username', required: true, spellcheck: false});
    const pw = h('input', {type: 'password', id: 'li-pw', autocomplete: 'current-password', required: true});
    const msg = h('p', {class: 'note', role: 'alert'}, message);
    const go = h('button', {type: 'submit', class: 'primary'}, 'Continue');
    const form = h('form', {class: 'stack', method: 'dialog'},
      h('label', {for: 'li-user'}, 'User'), user, h('label', {for: 'li-pw'}, 'Password'), pw, msg, h('div', {class: 'row'}, go));
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
    fill(this, h('div', {class: 'login panel'}, h('h1', null, 'Dwarpal lab console'),
      h('p', {class: 'note'}, 'Sign in with your lab account. This is the lab\'s own identity provider: a password, then the PIN of your security key (both were printed when the lab started).'),
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
    fill(this, h('div', {class: 'login panel'}, h('h1', null, 'Second factor'),
      h('p', {class: 'note'}, 'Your password goes to the identity provider together with a signature from your (simulated) security key, which unlocks with this PIN.'),
      form));
    pin.focus();
  }

  explain(err) {
    if (err.status === 429) return 'Too many attempts. Try again in ' + (err.retryAfter || 5) + ' seconds.';
    if (err.status === 401) return 'Sign-in failed. Check the user, the password and the PIN.';
    return 'Sign-in is unavailable (' + err.message + ').';
  }
}
customElements.define('dw-login', DwLogin);
