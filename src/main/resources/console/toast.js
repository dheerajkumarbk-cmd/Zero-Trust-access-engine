// What is going on: a pill at the top while something runs, notices at the bottom right when something happened.
import {h, append} from './dom.js';

const SHOW_MS = 6000;
const PILL_DELAY_MS = 300;

let box = null;
let pill = null;
let pillTimer = null;
let running = 0;

function holder() {
  if (!box || !box.isConnected) {
    box = h('div', {class: 'toasts', role: 'status', 'aria-live': 'polite'});
    document.body.append(box);
  }
  return box;
}

/** kind: '', 'ok' or 'bad'. action: {href, text}, a link inside the console. */
export function toast(text, kind = '', action = null) {
  const el = h('div', {class: 'toast ' + kind}, text, action ? h('a', {href: action.href}, action.text) : null);
  append(holder(), [el]);
  setTimeout(() => el.remove(), SHOW_MS);
}

/** Work started; returns the function that ends it. Short work shows nothing: the pill waits a moment. */
export function working(label) {
  running++;
  clearTimeout(pillTimer);
  pillTimer = setTimeout(() => {
    if (!pill) {
      pill = h('div', {class: 'busy', role: 'status'});
      document.body.append(pill);
    }
    pill.textContent = label + '...';
  }, PILL_DELAY_MS);
  return () => {
    running--;
    if (running > 0) return;
    clearTimeout(pillTimer);
    if (pill) pill.remove();
    pill = null;
  };
}
