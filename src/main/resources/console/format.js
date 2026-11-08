// Time is scenario time in UTC everywhere in the console. Text only; nothing here builds markup.

export function when(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toISOString().slice(0, 16).replace('T', ' ') + 'Z';
}

export function whenSec(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? String(iso) : d.toISOString().slice(0, 19).replace('T', ' ') + 'Z';
}

/** A whole count with thousands separated: 3,861. */
export const count = (n) => Number(n).toLocaleString('en-US', {maximumFractionDigits: 0});

export function span(ms) {
  const neg = ms < 0;
  let s = Math.floor(Math.abs(ms) / 1000);
  const d = Math.floor(s / 86400); s -= d * 86400;
  const hh = Math.floor(s / 3600); s -= hh * 3600;
  const mm = Math.floor(s / 60);
  const parts = d ? [d + 'd', hh + 'h'] : hh ? [hh + 'h', mm + 'm'] : [mm + 'm'];
  return (neg ? '-' : '') + parts.join(' ');
}

/** How long until a deadline, as words: "2h 10m left" or "breached 15m ago". */
export function untilDeadline(deadlineIso, nowIso) {
  const left = new Date(deadlineIso).getTime() - new Date(nowIso).getTime();
  return left >= 0 ? span(left) + ' left' : 'breached ' + span(-left) + ' ago';
}

export function ago(iso, nowIso) {
  return span(new Date(nowIso).getTime() - new Date(iso).getTime()) + ' ago';
}

export const PRIORITY = {
  P1: {label: 'P1 critical', glyph: '▲'},
  P2: {label: 'P2 high', glyph: '◆'},
  P3: {label: 'P3 medium', glyph: '●'},
  P4: {label: 'P4 low', glyph: '○'},
};

export function num(x, digits = 1) {
  const n = Number(x);
  return Number.isFinite(n) ? n.toFixed(digits) : String(x);
}
