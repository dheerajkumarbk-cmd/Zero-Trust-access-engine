// The only file that talks to the server. Everything else asks this module; nothing else calls fetch or opens a stream.
// The session is a cookie the browser keeps by itself (HttpOnly, never visible here). The anti-forgery token is kept in
// memory only: it is fetched from /me after a reload and replaced at login and at step-up.

const BASE = '/console/api/';
let csrf = null;

export class ApiError extends Error {
  constructor(status, message, extra) {
    super(message);
    this.status = status;
    this.retryAfter = extra && extra.retryAfterSeconds ? extra.retryAfterSeconds : 0;
  }
}

async function call(method, path, body, opts) {
  const headers = {Accept: 'application/json'};
  if (method === 'POST') {
    headers['Content-Type'] = 'application/json';
    if (csrf) headers['X-Dwarpal-CSRF'] = csrf;
  }
  if (opts && opts.background) headers['X-Dwarpal-Background'] = '1';
  let res;
  try {
    res = await fetch(BASE + path, {
      method, headers, credentials: 'same-origin', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
      body: method === 'POST' ? JSON.stringify(body === undefined ? {} : body) : undefined,
    });
  } catch (e) {
    throw new ApiError(0, 'the console server cannot be reached');
  }
  let data = null;
  try {
    data = await res.json();
  } catch (e) {
    data = null;
  }
  if (res.status === 401 && !path.startsWith('session/')) {
    window.dispatchEvent(new CustomEvent('dw:session-ended'));
  }
  if (!res.ok) {
    throw new ApiError(res.status, data && typeof data.error === 'string' ? data.error : 'request failed (' + res.status + ')', data);
  }
  return data;
}

const get = (path, opts) => call('GET', path, undefined, opts);
const post = (path, body) => call('POST', path, body);
const enc = (s) => encodeURIComponent(s);

export function setCsrf(token) {
  csrf = token;
}

export const api = {
  // ---- session
  async login(user, password) {
    return post('session/login', {user, password});
  },
  async verify(loginId, pin) {
    const r = await post('session/verify', {loginId, pin});
    csrf = r.csrf;
    return r;
  },
  async stepUp(password, pin) {
    const r = await post('session/stepup', {password, pin});
    csrf = r.csrf;
    return r;
  },
  async logout() {
    try {
      return await post('session/logout', {});
    } finally {
      csrf = null;
    }
  },
  async me(opts) {
    const r = await get('me', opts);
    csrf = r.csrf;
    return r;
  },
  sessions: () => get('session/list'),
  revokeSession: (id) => post('session/revoke', {id}),
  modules: () => get('modules'),
  lab: (opts) => get('lab', opts),

  // ---- the SOC, as the signed-in analyst
  queue: (opts) => get('soc/queue', opts),
  cases: (opts) => get('soc/cases', opts),
  caseDetail: (id, opts) => get('soc/cases/' + enc(id), opts),
  timeline: (id, opts) => get('soc/cases/' + enc(id) + '/timeline', opts),
  addNote: (id, text) => post('soc/cases/' + enc(id) + '/notes', {text}),
  assign: (id, assignee) => post('soc/cases/' + enc(id) + '/assignment', {assignee}),
  verdict: (alertId, outcome) => post('soc/verdicts', {alertId, outcome}),
  riskTop: (opts) => get('soc/risk/top', opts),
  risk: (kind, id) => get('soc/risk/' + enc(kind) + '/' + enc(id)),
  search: (query, from, to, limit) => post('soc/search', {query, from, to, limit}),
  counts: (query, from, to) => post('soc/counts', {query, from, to}),
  isolations: (opts) => get('soc/isolations', opts),
  metrics: (opts) => get('soc/metrics', opts),
  report: (name) => get('soc/reports/' + enc(name)),

  // ---- the audit explorer
  auditHead: () => get('audit/head'),
  auditPage: (after, limit, type) => get('audit/records?after=' + Number(after) + '&limit=' + Number(limit) +
    (type ? '&type=' + enc(type) : '')),
  auditRecord: (seq) => get('audit/records/' + enc(String(seq))),
  auditVerify: () => get('audit/verify'),

  /** The calls a module (parts I, J) may make: only below /console/api/<id>/. */
  module(id) {
    if (!/^[a-z][a-z0-9-]{1,31}$/.test(id)) throw new Error('bad module id');
    const root = id + '/';
    return {
      get: (path, opts) => get(root + String(path).replace(/^\/+/, ''), opts),
      post: (path, body) => post(root + String(path).replace(/^\/+/, ''), body),
    };
  },

  /** Server-sent events. Returns a function that closes the stream. */
  openStream(onEvent, onState) {
    const es = new EventSource(BASE + 'stream');
    for (const name of ['lab.tick', 'alert.new', 'case.changed', 'isolation.changed']) {
      es.addEventListener(name, (e) => {
        let data = null;
        try {
          data = JSON.parse(e.data);
        } catch (err) {
          data = null;
        }
        onEvent(name, data);
      });
    }
    es.addEventListener('open', () => onState('live'));
    es.addEventListener('error', () => onState(es.readyState === EventSource.CLOSED ? 'closed' : 'reconnecting'));
    return () => es.close();
  },
};
