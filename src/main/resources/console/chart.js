// Simple charts from elements and classes. The page's rules allow no inline style, so a bar's length is one of the
// classes .v0 to .v100 in style.css, in steps of five. Every figure is also shown as text; the bar only adds the shape.
import {h} from './dom.js';

/** The class for value as a share of max: never empty for a value above zero, so a small value still shows. */
function step(value, max) {
  if (!(value > 0) || !(max > 0)) return 'v0';
  return 'v' + Math.max(5, Math.round((value / max) * 20) * 5);
}

/** Horizontal bars. rows: [{label: node|string, value, text, tone}]; zero-based, longest bar = the largest value. */
export function hbars(rows, name) {
  const max = Math.max(...rows.map((r) => r.value));
  return h('ul', {class: 'hbars', role: 'list', 'aria-label': name}, rows.map((r) => {
    const text = r.text === undefined ? String(r.value) : r.text;
    return h('li', null, h('span', {class: 'lbl'}, r.label),
      h('span', {class: 'track', title: text}, h('i', {class: step(r.value, max) + (r.tone ? ' tone-' + r.tone : '')})),
      h('span', {class: 'val'}, text));
  }));
}

/** Columns over time. rows: [{value, title}]; first and last label the two ends of the axis. */
export function columns(rows, first, last, name) {
  const max = Math.max(...rows.map((r) => r.value));
  return h('div', null,
    h('ul', {class: 'cols', role: 'list', 'aria-label': name}, rows.map((r) => h('li', {title: r.title},
      r.value > 0 ? h('span', null, String(r.value)) : null, h('i', {class: step(r.value, max)})))),
    h('div', {class: 'axis'}, h('span', null, first), h('span', null, last)));
}
