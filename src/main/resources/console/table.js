// Dense tables with a keyboard cursor. The shell sends j / k / Enter to the list registered last (the one on screen).
import {h} from './dom.js';

let active = null;

/** Called by the shell's key handler. */
export const lists = {
  move(delta) {
    if (active) active.move(delta);
    return Boolean(active);
  },
  open() {
    if (active) active.open();
    return Boolean(active);
  },
  clear() {
    active = null;
  },
};

/**
 * columns: [{head, cell(row) -> node|string, cls}]. onOpen(row) is called for a click on a row's main link or Enter.
 * Returns {el, select(i), rows}. The table registers itself as the keyboard list until removed from the page.
 */
export function table(columns, rows, opts = {}) {
  const body = h('tbody');
  const el = h('div', {class: 'tablewrap'}, h('table', {class: 'dense'},
    h('thead', null, h('tr', null, columns.map((c) => h('th', {class: c.cls || '', scope: 'col'}, c.head)))), body));
  const trs = [];
  let index = -1;
  rows.forEach((row, i) => {
    const tr = h('tr', {tabindex: -1, 'aria-selected': 'false'}, columns.map((c) => h('td', {class: c.cls || ''}, c.cell(row, i))));
    tr.addEventListener('click', () => select(i, false));
    tr.addEventListener('dblclick', () => opts.onOpen && opts.onOpen(row));
    body.append(tr);
    trs.push(tr);
  });
  function select(i, scroll = true) {
    if (!trs.length) return;
    const n = Math.max(0, Math.min(trs.length - 1, i));
    if (index >= 0 && trs[index]) trs[index].setAttribute('aria-selected', 'false');
    index = n;
    trs[n].setAttribute('aria-selected', 'true');
    if (scroll) trs[n].scrollIntoView({block: 'nearest'});
    if (opts.onSelect) opts.onSelect(rows[n], n);
  }
  const api = {
    el, rows, trs,
    select,
    move: (d) => select(index < 0 ? (d > 0 ? 0 : trs.length - 1) : index + d),
    open: () => {
      if (index >= 0 && opts.onOpen) opts.onOpen(rows[index]);
    },
  };
  // the newest table on the page is the keyboard list; the shell clears it when the route changes
  active = api;
  return api;
}

export function emptyRow(text) {
  return h('p', {class: 'empty'}, text);
}
