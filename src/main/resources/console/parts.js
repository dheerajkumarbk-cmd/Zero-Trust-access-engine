// Small shared pieces: priority badge, entity links, evidence links, and a cache of case details (every case detail read
// is an audited read of a sensitive object, so the console asks once per change, not once per screen).
import {h, link} from './dom.js';
import {api} from './api.js';
import {PRIORITY} from './format.js';

export function priority(p) {
  const info = PRIORITY[p] || {label: String(p), glyph: '?'};
  return h('span', {class: 'pri pri-' + String(p).toLowerCase(), title: info.label}, info.glyph + ' ' + info.label);
}

export function flag(text, kind) {
  return h('span', {class: 'flag ' + (kind || '')}, text);
}

/** {kind, id} as a link to its entity page. */
export function entityLink(e) {
  return link('#/entity/' + encodeURIComponent(e.kind) + '/' + encodeURIComponent(e.id), e.kind + ':' + e.id);
}

export function entities(list) {
  return h('span', null, (list || []).flatMap((e, i) => [i ? ' ' : null, entityLink(e)]));
}

/** Audit sequence numbers as links into the audit explorer: the lineage of every figure. */
export function evidence(seqs) {
  if (!seqs || !seqs.length) return h('span', {class: 'muted'}, 'none');
  const shown = seqs.slice(0, 12);
  return h('span', null, shown.flatMap((s, i) => [i ? ', ' : null, link('#/audit/' + Number(s), '#' + Number(s))]),
    seqs.length > shown.length ? h('span', {class: 'muted'}, ' +' + (seqs.length - shown.length) + ' more') : null);
}

export function techniques(list) {
  return h('span', null, (list || []).map((t) => h('span', {class: 'tag', title: t.tactic + ': ' + t.name}, t.id + ' ' + t.name)));
}

export function provenance(p) {
  const label = {VERIFIED: 'verified', SIGNED_SENSOR: 'sensor-signed', COLLECTED: 'collected'}[p] || String(p).toLowerCase();
  return h('span', {class: 'flag', title: 'Evidence class: how far this record can be trusted'}, label);
}

const details = new Map();

/** The detail of a case, from the cache unless the case changed (signature from the queue row). */
export async function caseDetail(row, opts) {
  const sig = [row.state, row.priority, row.score, row.alerts, row.assignee].join('|');
  const hit = details.get(row.id);
  if (hit && hit.sig === sig && Date.now() - hit.at < 120000) return hit.value;
  const value = await api.caseDetail(row.id, opts);
  details.set(row.id, {sig, at: Date.now(), value});
  if (details.size > 300) details.delete(details.keys().next().value);
  return value;
}

export function forgetCase(id) {
  details.delete(id);
}

/** Why an alert has its rank: the ranker's reasons, as a short list. */
export function reasons(rankedAlerts) {
  const out = [];
  for (const a of rankedAlerts || []) {
    for (const r of a.reasons || []) if (!out.includes(r)) out.push(r);
  }
  return out;
}

/** Runs fn over items with at most n at a time; one failure does not stop the others. */
export async function pool(items, n, fn) {
  const queue = items.slice();
  const workers = Array.from({length: Math.min(n, queue.length)}, async () => {
    while (queue.length) {
      const item = queue.shift();
      try {
        await fn(item);
      } catch (e) {
        // the caller shows what is missing
      }
    }
  });
  await Promise.all(workers);
}
