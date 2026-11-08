// The only file that talks to the server. Everything else asks this module; nothing else calls fetch or opens a stream.
// The session is a cookie the browser keeps by itself (HttpOnly, never visible here). The anti-forgery token is kept in
// memory only: it is fetched from /me after a reload and replaced at login and at step-up.
import {toast, working} from './toast.js';

const BASE = '/console/api/';
let csrf = null;
let unlocker = null;

export class ApiError extends Error {
  constructor(status, message, extra) {
    super(message);
    this.status = status;
    this.retryAfter = extra && extra.retryAfterSeconds ? extra.retryAfterSeconds : 0;
    /** For a 423: what is being asked for: 'window' (cases, entities, hunt), 'audit', 'once' (one action), or 'elevation' (a privileged change). */
    this.scope = extra && typeof extra.scope === 'string' ? extra.scope : message === 'elevation required' ? 'elevation' : 'window';
  }
}

/** What a person would call this request; null for the ones that need no notice. */
function activity(method, path) {
  if (path.startsWith('session/')) return null;
  const known = [['fastforward', 'Moving scenario time forward'], ['control/reset', 'Resetting the lab'], ['lab/reset', 'Resetting the lab'],
    ['launch/', 'Starting the scenario'], ['soc/verdicts', 'Signing the verdict'], ['/notes', 'Saving the note'],
    ['/assignment', 'Assigning the case'], ['soc/search', 'Searching'], ['soc/counts', 'Counting events'], ['audit/verify', 'Verifying the audit chain'],
    
    ['profile/password', 'Changing your password'], ['profile/pin', 'Changing your PIN'], ['profile/passkey', 'Saving your passkey'], ['profile/backup-codes', 'Making backup codes']];
  const hit = known.find(([k]) => path.includes(k));
  return hit ? hit[1] : method === 'POST' ? 'Saving' : 'Loading';
}

function sourceQuery(source, lead) {
  return source === 'console' ? lead + 'source=console' : '';
}

async function call(method, path, body, opts) {
  const label = opts && opts.background ? null : activity(method, path);
  const end = label ? working(label) : () => {};
  try {
    let data;
    try {
      data = await send(method, path, body, opts);
    } catch (e) {
      // confidential data: ask for the passkey once, then repeat what the person asked for
      if (e.status !== 423 || !unlocker || (opts && opts.background)) throw e;
      await unlocker(e.scope);
      data = await send(method, path, body, opts);
    }
    if (label && method === 'POST' && !path.startsWith('soc/search') && !path.startsWith('soc/counts')) toast(label + ': done.', 'ok');
    return data;
  } catch (e) {
    if (label && method === 'POST' && e.status !== 423) toast(label + ' failed: ' + e.message, 'bad');
    throw e;
  } finally {
    end();
  }
}

async function send(method, path, body, opts) {
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
  if (res.status === 428) window.dispatchEvent(new CustomEvent('dw:change-due'));
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

/** The shell's way of asking for the passkey: resolves once confidential views are open, rejects if the person gives up. */
export function setUnlocker(fn) {
  unlocker = fn;
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
  /** A fresh challenge for the person's device to sign (when the console uses device passkeys). */
  passkeyChallenge: () => post('session/passkey/challenge', {}),
  /** The first half of registering a device passkey: password and PIN prove who asks, the server answers with a challenge. */
  passkeyBegin: (password, pin) => post('profile/passkey/begin', {password, pin}),
  unlock: (passkey, scope) => post('session/unlock', {passkey, scope: scope || 'window'}),
  lock: () => post('session/lock', {}),
  /** Starts an elevation: the PIN, the passkey and a reason; it lasts ten real minutes. */
  elevate: (pin, passkey, reason) => post('session/elevate', {pin, passkey, reason}),
  endElevation: () => post('session/elevate/end', {}),
  recoverCode: (user, code) => post('session/recover/code', {user, code}),
  recover: (ticket, newPassword, newPin) => post('session/recover', {ticket, newPassword, newPin}),
  activity: () => get('me/activity'),
  profile: () => get('profile'),
  changePassword: (password, pin, newPassword) => post('profile/password', {password, pin, newPassword}),
  changePin: (password, pin, newPin) => post('profile/pin', {password, pin, newPin}),
  setPasskey: (password, pin, passkey) => post('profile/passkey', {password, pin, passkey}),
  backupCodes: (password, pin) => post('profile/backup-codes', {password, pin}),
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
  report: (name, opts) => get('soc/reports/' + enc(name), opts),

  // ---- the audit explorer
  // source: 'lab' (the simulated organisation, the default) or 'console' (what people did on the console, kept on disk)
  auditHead: (source) => get('audit/head' + sourceQuery(source, '?')),
  auditPage: (after, limit, type, source) => get('audit/records?after=' + Number(after) + '&limit=' + Number(limit) +
    (type ? '&type=' + enc(type) : '') + sourceQuery(source, '&')),
  auditRecord: (seq, source) => get('audit/records/' + enc(String(seq)) + sourceQuery(source, '?')),
  auditVerify: (source) => get('audit/verify' + sourceQuery(source, '?')),

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
