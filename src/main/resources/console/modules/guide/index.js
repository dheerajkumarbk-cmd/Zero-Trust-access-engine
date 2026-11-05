// Guided walkthroughs: for each scenario a short path through the analyst console.
import { el, clear, button, stylesheet } from './dom.js';

function view(root, shell) {
  stylesheet('/console/modules/guide/guide.css');
  const api = shell.api;
  const list = el('ul', { class: 'guide-list' });
  const body = el('div', { class: 'guide-body', 'aria-live': 'polite' });
  const buttons = new Map();

  function fail(e) {
    clear(body);
    body.append(el('p', {}, e && e.message ? e.message : 'The guide is unavailable.'));
  }

  function section(title, items, ordered) {
    if (!items.length) return null;
    return [el('h3', {}, title), el(ordered ? 'ol' : 'ul', {}, items.map((t) => el('li', {}, t)))];
  }

  async function open(id) {
    for (const [k, b] of buttons) b.setAttribute('aria-selected', k === id ? 'true' : 'false');
    try {
      const r = await api.get('walkthroughs/' + id);
      const w = r.walkthrough;
      const s = r.scenario;
      clear(body);
      body.append(el('h2', {}, w.title), el('p', {}, w.summary),
        el('h3', {}, 'What the attacker does'), el('p', {}, s.attacker),
        el('h3', {}, 'What the defender should see'), el('p', {}, s.defender),
        section('Your path through the console', w.steps, true),
        section('MITRE ATT&CK', w.mitre, false),
        section('In a commercial product', w.commercial, false),
        section('What to notice', w.notice, false));
    } catch (e) {
      fail(e);
    }
  }

  root.append(el('h2', {}, 'Guide'),
    el('p', {}, 'Pick a scenario, launch it in the Scenario lab, then follow the path here through the analyst console.'),
    el('div', { class: 'guide' }, el('nav', { 'aria-label': 'scenarios' }, list), body));

  (async () => {
    try {
      const r = await api.get('walkthroughs');
      for (const w of r.walkthroughs) {
        const b = button(w.scenario + '  ' + w.title.replace(/^\S+\s+/, ''), () => open(w.scenario), { 'aria-selected': 'false' });
        buttons.set(w.scenario, b);
        list.append(el('li', {}, b));
      }
      if (r.walkthroughs.length) open(r.walkthroughs[0].scenario);
    } catch (e) {
      fail(e);
    }
  })();
}

export default { id: 'guide', title: 'Guide', requires: 'ANALYST', view };
