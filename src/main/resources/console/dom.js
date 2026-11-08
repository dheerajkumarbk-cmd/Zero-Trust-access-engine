// Building DOM without ever parsing markup: text goes in with textContent, attributes come from an allow-list.
// There is no innerHTML, outerHTML, insertAdjacentHTML, document.write, eval or inline handler anywhere in the console;
// ConsoleSourceTest fails the build if one appears.

const ATTRS = new Set([
  'class', 'id', 'type', 'title', 'role', 'value', 'placeholder', 'disabled', 'for', 'colspan', 'rowspan', 'name', 'min',
  'max', 'rows', 'cols', 'tabindex', 'autocomplete', 'open', 'checked', 'selected', 'readonly', 'required', 'maxlength',
  'minlength', 'low', 'high', 'optimum', 'scope', 'lang', 'hidden', 'spellcheck', 'inputmode', 'accept-charset', 'method',
]);

function internalHref(v) {
  // links stay inside the console: a hash route, nothing else (no javascript:, no other origin)
  return typeof v === 'string' && /^#\/[A-Za-z0-9_.:@\/?=&%~+!*()'-]*$/.test(v);
}

/** h('div', {class: 'x', on: {click: fn}}, 'text', child, ...) */
export function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'on') {
        for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn);
      } else if (k === 'href') {
        if (internalHref(v)) el.setAttribute('href', v);
      } else if (k.startsWith('data-') || k.startsWith('aria-')) {
        if (/^[a-z0-9-]+$/.test(k)) el.setAttribute(k, String(v));
      } else if (ATTRS.has(k)) {
        el.setAttribute(k, v === true ? '' : String(v));
      }
    }
  }
  append(el, kids);
  return el;
}

export function append(el, kids) {
  for (const k of kids.flat(Infinity)) {
    if (k === null || k === undefined || k === false) continue;
    el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return el;
}

/** Replaces the children of el. */
export function fill(el, ...kids) {
  el.replaceChildren();
  return append(el, kids);
}

export const link = (href, text, cls) => h('a', {href, class: cls}, text);

/** A panel with a heading. */
export function panel(title, ...kids) {
  return h('section', {class: 'panel'}, title ? h('h2', null, title) : null, ...kids);
}

/** Names a box, so that a link ending in ?at=name can scroll to it and make it flash. */
export function spot(name, el) {
  el.setAttribute('data-spot', name);
  return el;
}

/** A panel on warm paper instead of the green ground. */
export function cream(title, ...kids) {
  const el = panel(title, ...kids);
  el.classList.add('cream');
  return el;
}

/** What a failed load looks like: it says "unavailable", never an empty list that could pass for "nothing wrong". */
export function unavailable(err) {
  if (err && err.status === 423) {
    return h('div', {class: 'locked'}, h('strong', null, 'Locked. '), 'This is confidential. Enter your passkey to open it.',
      h('div', null, h('button', {type: 'button', on: {click: () => window.dispatchEvent(new CustomEvent('dw:unlock', {detail: {scope: err.scope}}))}}, 'Enter passkey')));
  }
  const msg = err && err.message ? err.message : 'unknown error';
  return h('div', {class: 'unavailable', role: 'alert'}, h('strong', null, 'Unavailable. '),
    'This data could not be loaded (', msg, '). Do not read an empty page as "nothing is wrong".');
}

export function note(text, cls = 'note') {
  return h('p', {class: cls}, text);
}
