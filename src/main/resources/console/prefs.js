// The only browser state besides the session cookie: harmless interface preferences (theme, saved hunt queries).
// Every access is wrapped, because storage can be blocked, full or absent.

export function getPref(key, fallback) {
  try {
    const v = window.localStorage.getItem('dwarpal.' + key);
    return v === null ? fallback : JSON.parse(v);
  } catch (e) {
    return fallback;
  }
}

export function setPref(key, value) {
  try {
    window.localStorage.setItem('dwarpal.' + key, JSON.stringify(value));
    return true;
  } catch (e) {
    return false;
  }
}
