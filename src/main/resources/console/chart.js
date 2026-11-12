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

/** A segment's share of its column, as one of the flex classes in style.css. */
function share(value, total) {
  const parts = [1, 2, 3, 4, 5, 6, 8, 10];
  const want = (value / total) * 10;
  return 'f' + parts.reduce((best, p) => (Math.abs(p - want) < Math.abs(best - want) ? p : best), 1);
}

/** Columns over time, each split by kind. rows: [{parts: [{tone, value}], title}]; ticks label the axis, evenly spaced. */
export function stacked(rows, legend, ticks, name) {
  const totals = rows.map((r) => r.parts.reduce((a, p) => a + p.value, 0));
  const max = Math.max(...totals);
  return h('div', null,
    h('ul', {class: 'legend'}, legend.map((l) => h('li', null, h('i', {class: 'tone-' + l.tone}), l.label))),
    h('ul', {class: 'cols', role: 'list', 'aria-label': name}, rows.map((r, n) => h('li', {title: r.title},
      totals[n] > 0 ? h('span', null, String(totals[n])) : null,
      h('span', {class: 'pile ' + step(totals[n], max)}, r.parts.filter((p) => p.value > 0).map((p) => h('i', {class: 'tone-' + p.tone + ' ' + share(p.value, totals[n])})))))),
    h('div', {class: 'axis'}, ticks.map((t) => h('span', null, t))));
}

/** Stages narrowing left to right. rows: [{label, value}]; bars are relative to the first stage. */
export function funnel(rows, name) {
  const max = Math.max(...rows.map((r) => r.value));
  return h('ul', {class: 'funnel', role: 'list', 'aria-label': name}, rows.map((r) => h('li', null,
    h('b', null, String(r.value)), h('span', null, r.label), h('i', {class: step(r.value, max)}))));
}
