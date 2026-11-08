// Small DOM helpers for the lab pages. Text only ever goes in through textContent; attributes come from an
// allow-list. Markup is never built from strings: only elements, text nodes and listeners.

const ATTRS = new Set(['class', 'type', 'for', 'id', 'rows', 'cols', 'value', 'placeholder', 'disabled', 'href',
  'download', 'role', 'aria-label', 'aria-live', 'aria-selected', 'min', 'max', 'step', 'readonly', 'spellcheck',
  'title', 'name', 'rel', 'maxlength', 'required', 'list', 'checked', 'selected']);

export function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (!ATTRS.has(k)) throw new Error('attribute not allowed: ' + k);
    if (k === 'href' && !/^(\/console\/|blob:)/.test(String(v))) throw new Error('link target not allowed');
    node.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children.flat()) {
    if (c === undefined || c === null || c === false) continue;
    node.append(typeof c === 'string' || typeof c === 'number' ? document.createTextNode(String(c)) : c);
  }
  return node;
}

export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

export function button(label, onClick, attrs) {
  const b = el('button', Object.assign({ type: 'button' }, attrs || {}), label);
  b.addEventListener('click', onClick);
  return b;
}

export function stylesheet(href) {
  if (document.querySelector('link[rel="stylesheet"][href="' + href + '"]')) return;
  document.head.append(el('link', { rel: 'stylesheet', href }));
}

export function table(headers, rows) {
  return el('table', { class: 'lab-table' },
    el('thead', {}, el('tr', {}, headers.map((h) => el('th', {}, h)))),
    el('tbody', {}, rows.map((r) => el('tr', {}, r.map((c) => el('td', {}, c))))));
}
